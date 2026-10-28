defmodule SecretHub.Agent.UDSServerTest do
  use ExUnit.Case, async: false
  import Bitwise
  alias SecretHub.Agent.AccessAudit.Journal
  alias SecretHub.Agent.{Cache, CertVerifier, UDSAuth, UDSServer}
  alias X509.Certificate.Extension
  @moduletag :tmp_dir

  setup %{tmp_dir: dir} do
    {:ok, _} = Application.ensure_all_started(:telemetry)
    start_supervised!({Journal, state_dir: dir})
    start_supervised!(CertVerifier)
    start_supervised!(Cache)
    path = Path.join(System.tmp_dir!(), "sh-v2-#{System.unique_integer([:positive])}.sock")
    on_exit(fn -> File.rm(path) end)
    start_supervised!({UDSServer, socket_path: path})
    :ok = UDSServer.configure_runtime("agent-1", 2)

    {:ok, socket} =
      :gen_tcp.connect(
        {:local, to_charlist(path)},
        0,
        [:binary, packet: :line, active: false],
        1000
      )

    on_exit(fn -> :gen_tcp.close(socket) end)
    %{socket: socket, path: path, state_dir: dir}
  end

  test "socket is owner-only and legacy auth cannot bypass Core floor", %{
    socket: socket,
    path: path
  } do
    assert (File.stat!(path).mode &&& 0o777) == 0o600
    assert error(request(socket, "authenticate", %{})) == "INCOMPATIBLE_VERSION"
    assert {:error, :closed} = :gen_tcp.recv(socket, 0, 1000)
  end

  @tag :local_socket_read
  test "UDS-only restart restores capability from the existing live runtime", %{path: path} do
    start_supervised!(
      {SecretHub.Agent.UDSCoreFixture,
       responses: [{:ok, %{"value" => "restarted-local-value", "version" => 1, "revision" => 1}}],
       owner: self(),
       runtime: %{
         connection_status: :connected,
         agent_id: "agent-1",
         minimum_uds_auth_version: 2,
         local_socket_read_capable: true
       }}
    )

    assert :ok = stop_supervised(UDSServer)
    start_supervised!({UDSServer, socket_path: path})
    assert_receive :uds_runtime_synchronized, 1_000

    assert %{agent_id: "agent-1", minimum_uds_auth_version: 2, local_socket_read_capable: true} =
             :sys.get_state(UDSServer)

    {:ok, socket} =
      :gen_tcp.connect(
        {:local, to_charlist(path)},
        0,
        [:binary, packet: :line, active: false],
        1000
      )

    on_exit(fn -> :gen_tcp.close(socket) end)

    assert request(socket, "get_secret", %{path: "prod.db.password"})["data"]["value"] ==
             "restarted-local-value"
  end

  @tag :local_socket_read
  test "local reads need no application credentials and audit only the Agent", %{socket: socket} do
    :ok = UDSServer.configure_runtime("agent-1", 2, ["local_socket_read_v1"])

    start_supervised!(
      {SecretHub.Agent.UDSCoreFixture,
       responses: [{:ok, %{"value" => "local-private-canary", "version" => 3, "revision" => 5}}],
       owner: self()}
    )

    assert request(socket, "get_secret", %{path: "prod.db.password"})["data"] == %{
             "value" => "local-private-canary",
             "version" => 3,
             "revision" => 5
           }

    assert_receive {:local_core_request, "prod.db.password", nil, correlation}
    assert {:ok, _} = Ecto.UUID.cast(correlation.audit_request_id)
    assert {:ok, _} = Ecto.UUID.cast(correlation.audit_attempt_id)
    assert {:ok, [admitted, attempt, intent, terminal] = events} = Journal.batch()
    assert Enum.map(events, & &1["phase"]) == ~w(admitted attempt release_intent response_sent)

    for event <- [admitted, attempt, intent, terminal] do
      assert event["agent_id"] == "agent-1"
      assert event["application_id"] == nil
      assert event["identity_status"] == "unverified"
      assert event["attribution"] == "none"
    end

    refute Jason.encode!(events) =~ "local-private-canary"
  end

  @tag :local_socket_read
  test "local cache requires exact current Core approval and denial invalidates it", %{
    socket: socket
  } do
    :ok = UDSServer.configure_runtime("agent-1", 2, ["local_socket_read_v1"])

    start_supervised!(
      {SecretHub.Agent.UDSCoreFixture,
       responses: [
         {:ok, %{"value" => "local-cache-canary", "version" => 7, "revision" => 9}},
         {:ok, %{"not_modified" => true, "version" => 7, "revision" => 9}},
         {:error, %{"reason" => "FORBIDDEN"}}
       ],
       owner: self()}
    )

    key = {:local, "agent-1", "prod.db.password"}
    assert request(socket, "get_secret", %{path: "prod.db.password"})["data"]["version"] == 7
    assert_receive {:local_core_request, "prod.db.password", nil, _}
    assert {:ok, %{revision: 9}} = Cache.get_entry(key)

    assert request(socket, "get_secret", %{path: "prod.db.password"})["data"]["value"] ==
             "local-cache-canary"

    assert_receive {:local_core_request, "prod.db.password", 9, _}
    assert error(request(socket, "get_secret", %{path: "prod.db.password"})) == "FORBIDDEN"
    assert {:error, :not_found} = Cache.get_entry(key)
  end

  @tag :local_socket_read
  test "Core outage never releases previously cached local plaintext", %{socket: socket} do
    :ok = UDSServer.configure_runtime("agent-1", 2, ["local_socket_read_v1"])

    start_supervised!(
      {SecretHub.Agent.UDSCoreFixture,
       responses: [
         {:ok, %{"value" => "local-outage-canary", "version" => 1, "revision" => 1}},
         {:error, :not_connected}
       ],
       owner: self()}
    )

    assert request(socket, "get_secret", %{path: "prod.db.password"})["status"] == "ok"
    response = request(socket, "get_secret", %{path: "prod.db.password"})
    assert error(response) == "UNAVAILABLE"
    refute Jason.encode!(response) =~ "local-outage-canary"
  end

  @tag :local_socket_read
  test "application cache entries cannot grant local Agent access", %{socket: socket} do
    :ok = UDSServer.configure_runtime("agent-1", 2, ["local_socket_read_v1"])

    start_supervised!(
      {SecretHub.Agent.UDSCoreFixture,
       responses: [{:error, %{"reason" => "FORBIDDEN"}}], owner: self()}
    )

    Cache.put({Ecto.UUID.generate(), "app-fingerprint", "prod.db.password"}, "app-canary",
      version: 8,
      revision: 15
    )

    response = request(socket, "get_secret", %{path: "prod.db.password"})
    assert error(response) == "FORBIDDEN"
    assert_receive {:local_core_request, "prod.db.password", nil, _}
    refute Jason.encode!(response) =~ "app-canary"
  end

  @tag :local_socket_read
  test "local requests reject caller-selected identities", %{socket: socket} do
    :ok = UDSServer.configure_runtime("agent-1", 2, ["local_socket_read_v1"])

    for field <- ~w(agent_id app_id certificate_fingerprint local_auth_version auth_version) do
      response = request(socket, "get_secret", %{"path" => "prod.db.password", field => "forged"})
      assert error(response) == "FORBIDDEN"
    end
  end

  @tag :local_socket_read
  test "local reads require negotiated capability and never lower the application floor", %{
    socket: socket
  } do
    :ok = UDSServer.configure_runtime("agent-1", 2, [])

    assert error(request(socket, "get_secret", %{path: "prod.db.password"})) ==
             "INCOMPATIBLE_VERSION"

    :ok = UDSServer.configure_runtime("agent-1", 1, ["local_socket_read_v1"])
    assert error(request(socket, "authenticate", %{auth_version: 1})) == "INCOMPATIBLE_VERSION"
  end

  @tag :local_socket_read
  test "started or failed application authentication cannot fall back to local reads", %{
    socket: socket,
    path: path
  } do
    :ok = UDSServer.configure_runtime("agent-1", 2, ["local_socket_read_v1"])
    {_key, pem, _app_id} = certificate_fixture()

    assert request(socket, "authenticate", %{auth_version: 2, certificate: Base.encode64(pem)})[
             "status"
           ] == "ok"

    assert error(request(socket, "get_secret", %{path: "prod.db.password"})) == "PROOF_REQUIRED"

    {:ok, second} =
      :gen_tcp.connect(
        {:local, to_charlist(path)},
        0,
        [:binary, packet: :line, active: false],
        1000
      )

    on_exit(fn -> :gen_tcp.close(second) end)

    assert error(
             request(second, "authenticate", %{
               auth_version: 2,
               certificate: Base.encode64("invalid")
             })
           ) == "INVALID_CERTIFICATE"

    assert error(request(second, "get_secret", %{path: "prod.db.password"})) == "PROOF_REQUIRED"
  end

  test "unconfigured CA refuses authentication without preventing enrollment", %{socket: socket} do
    assert error(
             request(socket, "authenticate", %{
               auth_version: 2,
               certificate: Base.encode64("invalid")
             })
           ) == "CA_UNAVAILABLE"

    assert error(request(socket, "get_secret", %{path: "prod.db.password"})) == "PROOF_REQUIRED"
  end

  test "private-key proof is required and consumed exactly once", %{socket: socket} do
    {key, pem, app_id} = certificate_fixture()

    data =
      request(socket, "authenticate", %{auth_version: 2, certificate: Base.encode64(pem)})["data"]

    assert data["auth_version"] == 2
    assert byte_size(Base.decode64!(data["challenge"])) == 32
    assert error(request(socket, "get_secret", %{path: "prod.db.password"})) == "PROOF_REQUIRED"
    proof = proof_params(data, key)
    assert request(socket, "authenticate_proof", proof)["data"]["app_id"] == app_id
    assert error(request(socket, "authenticate_proof", proof)) == "PROOF_FAILED"
    assert {:error, :closed} = :gen_tcp.recv(socket, 0, 1000)
  end

  test "cross-connection and changed proof fields close the connection", %{socket: socket} do
    {key, pem, _app_id} = certificate_fixture()

    data =
      request(socket, "authenticate", %{auth_version: 2, certificate: Base.encode64(pem)})["data"]

    assert error(
             request(
               socket,
               "authenticate_proof",
               Map.put(proof_params(data, key), "connection_id", Ecto.UUID.generate())
             )
           ) == "PROOF_FAILED"

    assert {:error, :closed} = :gen_tcp.recv(socket, 0, 1000)
  end

  test "a signature from another connection or Agent cannot prove this challenge", %{
    socket: socket,
    path: path
  } do
    {key, pem, _} = certificate_fixture()

    first =
      request(socket, "authenticate", %{auth_version: 2, certificate: Base.encode64(pem)})["data"]

    signature = proof_params(first, key)["signature"]

    for agent_id <- ["agent-1", "agent-2"] do
      :ok = UDSServer.configure_runtime(agent_id, 2)

      {:ok, other} =
        :gen_tcp.connect(
          {:local, to_charlist(path)},
          0,
          [:binary, packet: :line, active: false],
          1000
        )

      challenge =
        request(other, "authenticate", %{auth_version: 2, certificate: Base.encode64(pem)})[
          "data"
        ]

      assert challenge["agent_id"] == agent_id
      proof = proof_params(challenge, key) |> Map.put("signature", signature)
      assert error(request(other, "authenticate_proof", proof)) == "PROOF_FAILED"
      assert {:error, :closed} = :gen_tcp.recv(other, 0, 1000)
      :gen_tcp.close(other)
    end
  end

  test "three certificate failures close the connection", %{socket: socket} do
    for _ <- 1..3 do
      assert error(
               request(socket, "authenticate", %{
                 auth_version: 2,
                 certificate: Base.encode64("invalid")
               })
             ) == "CA_UNAVAILABLE"
    end

    assert {:error, :closed} = :gen_tcp.recv(socket, 0, 1000)
  end

  test "cached plaintext cannot be served during a Core outage", %{socket: socket} do
    {key, pem, app_id} = certificate_fixture()

    data =
      request(socket, "authenticate", %{auth_version: 2, certificate: Base.encode64(pem)})["data"]

    assert request(socket, "authenticate_proof", proof_params(data, key))["status"] == "ok"

    Cache.put(
      {app_id, data["certificate_fingerprint"], "prod.db.password"},
      %{"value" => "cached-private-marker"},
      revision: 1,
      version: 7
    )

    response = request(socket, "get_secret", %{path: "prod.db.password"})
    assert error(response) == "UNAVAILABLE"
    refute Jason.encode!(response) =~ "cached-private-marker"
  end

  @tag :tmp_dir
  test "external consumer proves its key and preserves private config on denial or outage", %{
    path: socket_path,
    tmp_dir: dir
  } do
    {key, pem, _} = certificate_fixture()
    certificate_path = Path.join(dir, "app.pem")
    key_path = Path.join(dir, "app-key.pem")
    output_path = Path.join(dir, "consumer.json")
    File.write!(certificate_path, pem)
    File.write!(key_path, X509.PrivateKey.to_pem(key))
    File.chmod!(key_path, 0o600)

    start_supervised!(
      {SecretHub.Agent.UDSCoreFixture,
       responses: [
         {:ok, %{"value" => %{"value" => "initial-private"}, "version" => 1, "revision" => 1}},
         {:ok, %{"value" => %{"value" => "updated-private"}, "version" => 2, "revision" => 2}},
         {:error, %{"reason" => "FORBIDDEN"}},
         {:error, :not_connected}
       ],
       owner: self()}
    )

    script = Path.expand("../../../../scripts/prelaunch/static-consumer.py", __DIR__)

    args = [
      script,
      "--socket",
      socket_path,
      "--cert",
      certificate_path,
      "--key",
      key_path,
      "--path",
      "prod.db.password",
      "--output",
      output_path
    ]

    for {value, version} <- [{"initial-private", 1}, {"updated-private", 2}] do
      assert {metadata, 0} = System.cmd("python3", args, stderr_to_stdout: true)

      assert %{"applied" => true, "readback" => true, "version" => ^version} =
               Jason.decode!(metadata)

      refute metadata =~ value
      assert Jason.decode!(File.read!(output_path)) == value
      assert (File.stat!(output_path).mode &&& 0o777) == 0o600
    end

    for _ <- 1..2 do
      assert {metadata, 1} = System.cmd("python3", args, stderr_to_stdout: true)
      assert %{"applied" => false} = Jason.decode!(metadata)
      refute metadata =~ "updated-private"
      assert Jason.decode!(File.read!(output_path)) == "updated-private"
    end
  end

  test "authorized not-modified reads preserve cached version; later denial invalidates it", %{
    socket: socket
  } do
    start_supervised!(
      {SecretHub.Agent.UDSCoreFixture,
       [
         responses: [
           {:ok, %{"value" => %{"value" => "private-value"}, "version" => 7, "revision" => 9}},
           {:ok, %{"not_modified" => true, "version" => 7, "revision" => 9}},
           {:error, %{"reason" => "FORBIDDEN"}}
         ],
         owner: self()
       ]}
    )

    {key, pem, app_id} = certificate_fixture()

    data =
      request(socket, "authenticate", %{auth_version: 2, certificate: Base.encode64(pem)})["data"]

    assert request(socket, "authenticate_proof", proof_params(data, key))["status"] == "ok"
    cache_key = {app_id, data["certificate_fingerprint"], "prod.db.password"}

    assert request(socket, "get_secret", %{path: "prod.db.password"})["data"] == %{
             "value" => "private-value",
             "version" => 7,
             "revision" => 9
           }

    assert_receive {:core_request, %{app_id: ^app_id, local_auth_version: 2}, nil}
    assert request(socket, "get_secret", %{path: "prod.db.password"})["data"]["version"] == 7
    assert_receive {:core_request, _, 9}
    assert error(request(socket, "get_secret", %{path: "prod.db.password"})) == "FORBIDDEN"
    assert {:error, :not_found} = Cache.get_entry(cache_key)
  end

  test "structured fields survive fresh and revision-validated cached delivery", %{socket: socket} do
    value = %{
      "value" => "application-value",
      "region" => "application-region",
      "data" => %{"value" => [1, true]},
      "format" => "application-format",
      "value_format" => "application-value-format"
    }

    start_supervised!(
      {SecretHub.Agent.UDSCoreFixture,
       responses: [
         {:ok,
          %{"value" => value, "value_format" => "structured", "version" => 3, "revision" => 5}},
         {:ok, %{"not_modified" => true, "version" => 3, "revision" => 5}}
       ],
       owner: self()}
    )

    {key, pem, app_id} = certificate_fixture()

    challenge =
      request(socket, "authenticate", %{auth_version: 2, certificate: Base.encode64(pem)})["data"]

    assert request(socket, "authenticate_proof", proof_params(challenge, key))["status"] == "ok"
    cache_key = {app_id, challenge["certificate_fingerprint"], "prod.db.password"}

    assert request(socket, "get_secret", %{path: "prod.db.password"})["data"] == %{
             "value" => value,
             "version" => 3,
             "revision" => 5
           }

    assert_receive {:core_request, _, nil}

    assert {:ok, %{data: ^value, value_format: "structured", revision: 5}} =
             Cache.get_entry(cache_key)

    assert {:ok, ^value} = Cache.get(cache_key)
    assert request(socket, "get_secret", %{path: "prod.db.password"})["data"]["value"] == value
    assert_receive {:core_request, _, 5}
  end

  test "explicit Text preserves empty strings, whitespace and JSON-looking text", %{
    socket: socket
  } do
    values = ["", "  token\n", ~s({"access_key_id":"still-text"})]

    start_supervised!(
      {SecretHub.Agent.UDSCoreFixture,
       responses:
         Enum.map(values, fn value ->
           {:ok,
            %{
              "value" => %{"value" => value},
              "value_format" => "text",
              "version" => 1,
              "revision" => 1
            }}
         end),
       owner: self()}
    )

    {key, pem, _} = certificate_fixture()

    challenge =
      request(socket, "authenticate", %{auth_version: 2, certificate: Base.encode64(pem)})["data"]

    assert request(socket, "authenticate_proof", proof_params(challenge, key))["status"] == "ok"

    for value <- values do
      assert request(socket, "get_secret", %{path: "prod.db.password"})["data"]["value"] == value
    end
  end

  test "unknown formats and malformed Text do not reinterpret application data", %{socket: socket} do
    start_supervised!(
      {SecretHub.Agent.UDSCoreFixture,
       responses: [
         {:ok,
          %{
            "value" => %{"value" => "private"},
            "value_format" => "unknown",
            "version" => 1,
            "revision" => 1
          }},
         {:ok,
          %{
            "value" => %{"value" => "private", "sibling" => "preserve"},
            "value_format" => "text",
            "version" => 1,
            "revision" => 1
          }}
       ],
       owner: self()}
    )

    {key, pem, _} = certificate_fixture()

    challenge =
      request(socket, "authenticate", %{auth_version: 2, certificate: Base.encode64(pem)})["data"]

    assert request(socket, "authenticate_proof", proof_params(challenge, key))["status"] == "ok"

    for _ <- 1..2 do
      response = request(socket, "get_secret", %{path: "prod.db.password"})
      assert error(response) == "UNAVAILABLE"
      refute Jason.encode!(response) =~ "private"
    end
  end

  test "other application cache entries cannot influence Core request or delivery", %{
    socket: socket
  } do
    start_supervised!(
      {SecretHub.Agent.UDSCoreFixture,
       [responses: [{:error, %{"reason" => "FORBIDDEN"}}], owner: self()]}
    )

    {key, pem, app_id} = certificate_fixture()

    data =
      request(socket, "authenticate", %{auth_version: 2, certificate: Base.encode64(pem)})["data"]

    assert request(socket, "authenticate_proof", proof_params(data, key))["status"] == "ok"

    Cache.put(
      {Ecto.UUID.generate(), data["certificate_fingerprint"], "prod.db.password"},
      %{"value" => "other-app-marker"},
      revision: 88,
      version: 7
    )

    response = request(socket, "get_secret", %{path: "prod.db.password"})
    assert error(response) == "FORBIDDEN"
    assert_receive {:core_request, %{app_id: ^app_id}, nil}
    refute Jason.encode!(response) =~ "other-app-marker"
  end

  test "challenge expiry and repeated authentication close connection", %{socket: socket} do
    {key, pem, _} = certificate_fixture()

    data =
      request(socket, "authenticate", %{auth_version: 2, certificate: Base.encode64(pem)})["data"]

    :sys.replace_state(UDSServer, fn state ->
      connections =
        Map.new(state.connections, fn {sock, connection} ->
          {sock,
           %{
             connection
             | challenge: %{
                 connection.challenge
                 | expires_at: DateTime.add(DateTime.utc_now(), -1, :second)
               }
           }}
        end)

      %{state | connections: connections}
    end)

    assert error(request(socket, "authenticate_proof", proof_params(data, key))) == "PROOF_FAILED"
    assert {:error, :closed} = :gen_tcp.recv(socket, 0, 1000)
  end

  test "Core-issued floor cannot be lowered locally", %{socket: socket} do
    :ok = UDSServer.configure_runtime("agent-1", 1)
    assert error(request(socket, "authenticate", %{auth_version: 1})) == "INCOMPATIBLE_VERSION"
  end

  test "oversized newline frames are rejected before decoding", %{socket: socket} do
    :ok = :gen_tcp.send(socket, String.duplicate("x", 65_537) <> "\n")
    assert {:error, :closed} = :gen_tcp.recv(socket, 0, 1000)
  end

  test "audit joins use generated identities and persist release before successful send without values",
       %{
         socket: socket,
         state_dir: dir
       } do
    canary = "disposable-plaintext-canary-6827"

    start_supervised!(
      {SecretHub.Agent.UDSCoreFixture,
       responses: [{:ok, %{"value" => canary, "version" => 1, "revision" => 1}}], owner: self()}
    )

    {key, pem, app_id} = certificate_fixture()

    challenge =
      request(socket, "authenticate", %{auth_version: 2, certificate: Base.encode64(pem)})["data"]

    assert request(socket, "authenticate_proof", proof_params(challenge, key))["status"] == "ok"
    untrusted = Ecto.UUID.generate()
    correlation = Ecto.UUID.generate()

    assert request(socket, "get_secret", %{
             path: "prod.db.password",
             audit_request_id: untrusted,
             audit_attempt_id: untrusted,
             client_correlation_id: correlation
           })["data"]["value"] == canary

    assert_receive {:core_request, %{audit_request_id: request_id, audit_attempt_id: attempt_id},
                    nil}

    refute request_id == untrusted
    refute attempt_id == untrusted
    assert {:ok, [admitted, attempt, intent, terminal]} = Journal.batch()

    assert Enum.map([admitted, attempt, intent, terminal], & &1["phase"]) ==
             ~w(admitted attempt release_intent response_sent)

    assert Enum.all?([admitted, attempt, intent, terminal], &(&1["request_id"] == request_id))
    assert terminal["application_id"] == app_id
    assert terminal["attribution"] == "agent_certificate"
    assert terminal["outcome"] == "success"
    assert terminal["client_correlation_id"] == correlation
    refute File.read!(Path.join(dir, "access-audit/observations.wal")) =~ canary
  end

  test "bounded Core audit classification preserves public errors and legacy fallback", %{
    socket: socket
  } do
    responses = [
      %{"reason" => "FORBIDDEN", "audit_outcome" => "error", "audit_reason_code" => "not_found"},
      %{
        "reason" => "UNAUTHORIZED",
        "audit_outcome" => "denied",
        "audit_reason_code" => "revoked"
      },
      %{"reason" => "FORBIDDEN"},
      %{
        "reason" => "FORBIDDEN",
        "audit_outcome" => "arbitrary",
        "audit_reason_code" => "not_found"
      },
      %{
        "reason" => "FORBIDDEN",
        "audit_outcome" => "error",
        "audit_reason_code" => "TOKEN-CANARY"
      }
    ]

    start_supervised!(
      {SecretHub.Agent.UDSCoreFixture,
       responses: Enum.map(responses, &{:error, &1}), owner: self()}
    )

    {key, pem, _} = certificate_fixture()

    challenge =
      request(socket, "authenticate", %{auth_version: 2, certificate: Base.encode64(pem)})["data"]

    assert request(socket, "authenticate_proof", proof_params(challenge, key))["status"] == "ok"

    for {reply, expected} <-
          Enum.zip(responses, [
            {"error", "not_found"},
            {"denied", "revoked"},
            {"denied", "permission_denied"},
            {"denied", "permission_denied"},
            {"denied", "permission_denied"}
          ]) do
      response = request(socket, "get_secret", %{path: "prod.db.password"})
      assert error(response) == reply["reason"]
      refute Map.has_key?(response["error"], "audit_reason_code")
      # Wait until the actual server callback has persisted its post-send result.
      _ = :sys.get_state(UDSServer)
      assert {:ok, events} = Journal.batch()
      terminal = List.last(events)
      assert {terminal["outcome"], terminal["reason_code"]} == expected
      refute Jason.encode!(events) =~ "TOKEN-CANARY"
    end
  end

  test "missing journal refuses plaintext and Core authorization even when a cache entry exists",
       %{socket: socket} do
    start_supervised!({SecretHub.Agent.UDSCoreFixture, responses: [], owner: self()})
    {key, pem, app_id} = certificate_fixture()

    challenge =
      request(socket, "authenticate", %{auth_version: 2, certificate: Base.encode64(pem)})["data"]

    assert request(socket, "authenticate_proof", proof_params(challenge, key))["status"] == "ok"

    Cache.put(
      {app_id, challenge["certificate_fingerprint"], "prod.db.password"},
      "cached-private-canary",
      version: 1,
      revision: 1
    )

    assert :ok = stop_supervised(Journal)
    response = request(socket, "get_secret", %{path: "prod.db.password"})
    assert error(response) == "AUDIT_UNAVAILABLE"
    refute Jason.encode!(response) =~ "cached-private-canary"
    refute_receive {:core_request, _, _}
  end

  test "invalid local operations omit claimed identity and unsafe path", %{socket: socket} do
    assert error(
             request(socket, "get_secret", %{
               path: "secret-token-body\ncanary",
               app_id: Ecto.UUID.generate()
             })
           ) == "INCOMPATIBLE_VERSION"

    assert {:ok, [admitted, rejected]} = Journal.batch()
    assert admitted["application_id"] == nil
    assert rejected["identity_status"] == "unverified"
    assert rejected["secret_path"] == nil
    assert rejected["phase"] == "rejected"
    assert rejected["reason_code"] == "incompatible_version"
  end

  test "failed certificate and proof authentication are durable unverified rejections", %{
    socket: socket
  } do
    {key, pem, _} = certificate_fixture()

    assert error(
             request(socket, "authenticate", %{
               auth_version: 2,
               certificate: Base.encode64("invalid-cert-canary")
             })
           ) == "INVALID_CERTIFICATE"

    assert {:ok, [cert_admission, cert_rejection]} = Journal.batch()
    assert cert_admission["operation"] == "authenticate"
    assert cert_rejection["reason_code"] == "invalid_identity"
    assert cert_rejection["application_id"] == nil
    assert cert_rejection["identity_status"] == "unverified"
    assert cert_rejection["secret_path"] == nil
    ids = Enum.map([cert_admission, cert_rejection], & &1["event_id"])
    assert :ok = Journal.acknowledge(ids)

    challenge =
      request(socket, "authenticate", %{auth_version: 2, certificate: Base.encode64(pem)})["data"]

    proof =
      Map.put(proof_params(challenge, key), "signature", Base.encode64("invalid-proof-canary"))

    assert error(request(socket, "authenticate_proof", proof)) == "PROOF_FAILED"
    assert {:ok, [_, proof_rejection]} = Journal.batch()
    assert proof_rejection["reason_code"] == "proof_failed"
    assert proof_rejection["application_id"] == nil
    assert proof_rejection["attribution"] == "none"
  end

  test "authentication timeout records unverified rejection before closing real socket", %{
    socket: socket
  } do
    assert request(socket, "ping", %{})["status"] == "ok"
    [server_socket] = :sys.get_state(UDSServer).connections |> Map.keys()
    send(UDSServer, {:authentication_timeout, server_socket})
    assert {:error, :closed} = :gen_tcp.recv(socket, 0, 2_000)

    assert {:ok,
            [
              _,
              %{
                "operation" => "authenticate",
                "reason_code" => "timeout",
                "application_id" => nil
              }
            ]} = Journal.batch()
  end

  test "invalid authenticated paths are classified locally without contacting Core", %{
    socket: socket
  } do
    start_supervised!({SecretHub.Agent.UDSCoreFixture, responses: [], owner: self()})
    authenticate_client(socket)
    assert error(request(socket, "get_secret", %{path: "unsafe\npath-canary"})) == "FORBIDDEN"

    assert {:ok,
            [
              _,
              _,
              %{"phase" => "response_sent", "reason_code" => "invalid_path", "secret_path" => nil}
            ]} = Journal.batch()

    refute_receive {:core_request, _, _}
  end

  test "actual UDS crash before Core reply retains incomplete evidence and never releases plaintext",
       %{socket: socket} do
    gate = make_ref()

    core =
      start_supervised!(
        {SecretHub.Agent.UDSCoreFixture,
         responses: [
           {:wait, gate,
            {:ok, %{"value" => "never-released-canary", "version" => 1, "revision" => 1}}}
         ],
         owner: self()}
      )

    authenticate_client(socket)
    uds = Process.whereis(UDSServer)
    monitor = Process.monitor(uds)
    send_request(socket, "get_secret", %{path: "prod.db.password"})
    assert_receive {:core_waiting, ^gate}, 2_000
    Process.exit(uds, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^uds, :killed}
    send(core, {:release, gate})
    assert {:error, :closed} = :gen_tcp.recv(socket, 0, 2_000)
    assert eventually(fn -> Process.whereis(UDSServer) not in [nil, uds] end)
    assert {:ok, [%{"phase" => "admitted"}, %{"phase" => "attempt"}]} = Journal.batch()
  end

  test "actual send failure after release intent records failure rather than successful delivery",
       %{socket: socket} do
    gate = make_ref()

    core =
      start_supervised!(
        {SecretHub.Agent.UDSCoreFixture,
         responses: [
           {:wait, gate, {:ok, %{"value" => "unsent-canary", "version" => 1, "revision" => 1}}}
         ],
         owner: self()}
      )

    authenticate_client(socket)
    [server_socket] = :sys.get_state(UDSServer).connections |> Map.keys()
    send_request(socket, "get_secret", %{path: "prod.db.password"})
    assert_receive {:core_waiting, ^gate}, 2_000
    # Close the actual transport port while the request owner is waiting for
    # Core. This deterministically exercises :gen_tcp.send's closed result;
    # remote FIN delivery depends on the socket driver's active-once state.
    :ok = :gen_tcp.close(server_socket)
    :ok = :gen_tcp.close(socket)
    send(core, {:release, gate})

    assert eventually(fn ->
             case Journal.batch() do
               {:ok,
                [
                  _,
                  _,
                  %{"phase" => "release_intent"},
                  %{"phase" => "response_failed", "reason_code" => "transport_error"}
                ]} ->
                 true

               _ ->
                 false
             end
           end)
  end

  test "crash after actual plaintext send leaves durable intent ambiguous and never resends", %{
    socket: socket,
    path: path
  } do
    start_supervised!(
      {SecretHub.Agent.UDSCoreFixture,
       responses: [{:ok, %{"value" => "sent-once-canary", "version" => 1, "revision" => 1}}],
       owner: self()}
    )

    authenticate_client(socket)
    uds = Process.whereis(UDSServer)
    owner = self()
    handler = "uds-send-crash-#{System.unique_integer([:positive])}"

    :ok =
      :telemetry.attach(
        handler,
        [:secrethub, :access_audit, :response, :observation],
        fn _, _, _, _ ->
          if self() == uds do
            send(owner, :transport_completed_before_crash)
            Process.exit(self(), :kill)
          end
        end,
        nil
      )

    on_exit(fn -> :telemetry.detach(handler) end)

    assert request(socket, "get_secret", %{path: "prod.db.password"})["data"]["value"] ==
             "sent-once-canary"

    assert_receive :transport_completed_before_crash
    assert_receive {:core_request, _, _}
    assert eventually(fn -> Process.whereis(UDSServer) not in [nil, uds] end)

    assert {:ok,
            [%{"phase" => "admitted"}, %{"phase" => "attempt"}, %{"phase" => "release_intent"}]} =
             Journal.batch()

    assert {:ok, _} = UDSServer.get_stats()

    {:ok, fresh} =
      :gen_tcp.connect(
        {:local, to_charlist(path)},
        0,
        [:binary, packet: :line, active: false],
        1_000
      )

    assert {:error, :timeout} = :gen_tcp.recv(fresh, 0, 100)
    :gen_tcp.close(fresh)
    refute_receive {:core_request, _, _}, 100
  end

  defp authenticate_client(socket) do
    {key, pem, _} = certificate_fixture()

    challenge =
      request(socket, "authenticate", %{auth_version: 2, certificate: Base.encode64(pem)})["data"]

    assert request(socket, "authenticate_proof", proof_params(challenge, key))["status"] == "ok"
  end

  defp send_request(socket, action, params) do
    :gen_tcp.send(
      socket,
      Jason.encode!(%{request_id: Ecto.UUID.generate(), action: action, params: params}) <> "\n"
    )
  end

  defp eventually(fun, remaining \\ 100)
  defp eventually(_fun, 0), do: false

  defp eventually(fun, remaining) do
    if fun.(),
      do: true,
      else:
        (
          Process.sleep(10)
          eventually(fun, remaining - 1)
        )
  end

  defp request(socket, action, params) do
    id = Ecto.UUID.generate()

    :ok =
      :gen_tcp.send(
        socket,
        Jason.encode!(%{request_id: id, action: action, params: params}) <> "\n"
      )

    {:ok, line} = :gen_tcp.recv(socket, 0, 2000)
    response = Jason.decode!(line)
    assert response["request_id"] == id
    response
  end

  defp error(response), do: get_in(response, ["error", "code"])

  defp certificate_fixture do
    key = X509.PrivateKey.new_rsa(2048)
    ca_key = X509.PrivateKey.new_rsa(2048)
    ca = X509.Certificate.self_signed(ca_key, "/CN=Core CA", template: :root_ca)
    :ok = CertVerifier.configure_trust(X509.Certificate.to_pem(ca))
    app_id = Ecto.UUID.generate()

    pem =
      X509.Certificate.new(
        X509.PublicKey.derive(key),
        "/O=SecretHub Applications/CN=#{app_id}",
        ca,
        ca_key,
        template: :server,
        extensions: [
          ext_key_usage: Extension.ext_key_usage([:clientAuth]),
          subject_alt_name:
            Extension.subject_alt_name([
              {:uniformResourceIdentifier, to_charlist("urn:secrethub:app:#{app_id}")}
            ])
        ]
      )
      |> X509.Certificate.to_pem()

    {key, pem, app_id}
  end

  defp proof_params(data, key) do
    challenge = %{
      agent_id: data["agent_id"],
      connection_id: data["connection_id"],
      challenge_id: data["challenge_id"],
      nonce: Base.decode64!(data["challenge"]),
      certificate_fingerprint: data["certificate_fingerprint"],
      signature_algorithm: data["signature_algorithm"]
    }

    signature =
      :public_key.sign(UDSAuth.transcript(challenge), :sha256, key,
        rsa_padding: :rsa_pkcs1_pss_padding,
        rsa_pss_saltlen: 32,
        rsa_mgf1_md: :sha256
      )

    %{
      "auth_version" => 2,
      "connection_id" => challenge.connection_id,
      "challenge_id" => challenge.challenge_id,
      "signature_algorithm" => challenge.signature_algorithm,
      "signature" => Base.encode64(signature)
    }
  end
end

defmodule SecretHub.Agent.UDSCoreFixture do
  use GenServer

  def start_link(opts),
    do: GenServer.start_link(__MODULE__, opts, name: SecretHub.Agent.Connection)

  def init(opts),
    do:
      {:ok,
       %{
         responses: Keyword.fetch!(opts, :responses),
         owner: Keyword.fetch!(opts, :owner),
         runtime: Keyword.get(opts, :runtime, %{connection_status: :disconnected})
       }}

  def handle_cast({:sync_uds_runtime, server}, state) do
    {:noreply, _} =
      SecretHub.Agent.Connection.handle_cast({:sync_uds_runtime, server}, state.runtime)

    # Wait for the actual UDS callback before notifying the test process.
    :sys.get_state(server)
    send(state.owner, :uds_runtime_synchronized)
    {:noreply, state}
  end

  def handle_call({:get_static_secret_local, path, revision, correlation}, _from, state) do
    send(state.owner, {:local_core_request, path, revision, correlation})
    [response | responses] = state.responses
    {:reply, response, %{state | responses: responses}}
  end

  def handle_call({:get_static_secret_for_app, _path, claims, revision}, _from, state) do
    send(state.owner, {:core_request, claims, revision})
    [response | responses] = state.responses

    response =
      case response do
        {:wait, gate, result} ->
          send(state.owner, {:core_waiting, gate})

          receive do
            {:release, ^gate} -> result
          after
            5_000 -> {:error, :not_connected}
          end

        result ->
          result
      end

    {:reply, response, %{state | responses: responses}}
  end
end
