defmodule SecretHub.Web.UnifiedAgentTLSTest do
  use SecretHub.Web.ConnCase, async: false

  alias SecretHub.Core.Agents.Enrollment
  alias SecretHub.Core.PKI.CA
  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.{Agent, Certificate}
  alias SecretHub.Web.{AgentEndpoint, AgentEndpointManager, UnifiedAgentTLSFixture}

  setup_all do
    dir =
      Path.join(
        System.tmp_dir!(),
        "secrethub-unified-agent-tls-#{System.unique_integer([:positive])}"
      )

    on_exit(fn -> File.rm_rf!(dir) end)
    {:ok, fixture: UnifiedAgentTLSFixture.generate!(dir)}
  end

  setup %{fixture: fixture} do
    previous = Application.get_env(:secrethub_web, AgentEndpoint)
    previous_dev = Application.get_env(:secrethub_web, :dev_mode)
    Application.put_env(:secrethub_web, AgentEndpoint, UnifiedAgentTLSFixture.config(fixture))
    Application.put_env(:secrethub_web, :dev_mode, false)

    on_exit(fn ->
      Supervisor.terminate_child(SecretHub.Web.Supervisor, AgentEndpoint)
      Supervisor.delete_child(SecretHub.Web.Supervisor, AgentEndpoint)
      Application.put_env(:secrethub_web, AgentEndpoint, previous)
      Application.put_env(:secrethub_web, :dev_mode, previous_dev)
    end)

    :ok
  end

  test "explicit TLS starts in development without an initialized internal CA" do
    Application.put_env(:secrethub_web, :dev_mode, true)
    assert :ok = AgentEndpointManager.ensure_started()
    assert {:ok, {{127, 0, 0, 1}, _port}} = AgentEndpoint.server_info(:https)
    assert {:error, :no_server_found} = AgentEndpoint.server_info(:http)
  end

  test "incomplete enabled explicit TLS fails clearly instead of generating development material" do
    Application.put_env(:secrethub_web, :dev_mode, true)

    for config <- [[server: true], [server: true, https: false], [server: true, https: [port: 0]]] do
      Application.put_env(:secrethub_web, AgentEndpoint, config)

      assert {:error, {:invalid_agent_endpoint_tls, :incomplete_tls_material}} =
               AgentEndpointManager.ensure_started()
    end
  end

  test "replacing generated development material with explicit TLS takes precedence", %{
    fixture: fixture
  } do
    config = UnifiedAgentTLSFixture.config(fixture)
    Application.put_env(:secrethub_web, :dev_mode, true)

    Application.put_env(
      :secrethub_web,
      AgentEndpoint,
      Keyword.put(config, :dev_generated_tls_paths, %{
        certfile: "previous-dev-cert.pem",
        keyfile: "previous-dev-key.pem",
        cacertfile: "previous-ca.pem"
      })
    )

    assert :ok = AgentEndpointManager.ensure_started()
    assert {:ok, {{127, 0, 0, 1}, _port}} = AgentEndpoint.server_info(:https)
  end

  test "generated development material still consults the active CA on subsequent starts", %{
    fixture: fixture
  } do
    config = UnifiedAgentTLSFixture.config(fixture)
    Application.put_env(:secrethub_web, :dev_mode, true)

    Application.put_env(
      :secrethub_web,
      AgentEndpoint,
      Keyword.put(config, :dev_generated_tls_paths, %{
        certfile: fixture.cert,
        keyfile: fixture.key,
        cacertfile: fixture.ca
      })
    )

    assert {:error, :no_active_ca} = AgentEndpointManager.ensure_started()
  end

  test "explicit TLS refuses plaintext and permissive peer verification", %{fixture: fixture} do
    config = UnifiedAgentTLSFixture.config(fixture)
    Application.put_env(:secrethub_web, AgentEndpoint, Keyword.put(config, :http, port: 0))

    assert {:error, {:invalid_agent_endpoint_tls, :plaintext_listener_enabled}} =
             AgentEndpointManager.ensure_started()

    for opts <- [
          [verify: :verify_none],
          [fail_if_no_peer_cert: true],
          [verify_fun: {fn _, _, state -> {:valid, state} end, nil}]
        ] do
      insecure =
        put_in(
          config,
          [:https, :thousand_island_options, :transport_options],
          Keyword.merge(config[:https][:thousand_island_options][:transport_options], opts)
        )

      Application.put_env(:secrethub_web, AgentEndpoint, insecure)

      assert {:error, {:invalid_agent_endpoint_tls, :invalid_client_verification}} =
               AgentEndpointManager.ensure_started()
    end
  end

  test "real TLS without a client certificate reaches enrollment JSON", %{fixture: fixture} do
    port = start_endpoint!()
    assert {:ok, socket} = UnifiedAgentTLSFixture.connect(fixture, port)
    response = UnifiedAgentTLSFixture.request(socket, "POST", "/v1/agent/enrollments", "{}")
    assert response =~ "HTTP/1.1 400"
    assert response =~ "invalid_enrollment"
    assert response =~ "cache-control: no-store"
  end

  test "real certificate-free enrollment preserves pending-token, approval and SSH-proof gates",
       %{fixture: fixture} do
    port = start_endpoint!()
    assert {:ok, socket} = UnifiedAgentTLSFixture.connect(fixture, port)

    response =
      UnifiedAgentTLSFixture.request(
        socket,
        "POST",
        "/v1/agent/enrollments",
        Jason.encode!(UnifiedAgentTLSFixture.enrollment_attrs(fixture))
      )

    assert response =~ "HTTP/1.1 201"
    [_, body] = String.split(response, "\r\n\r\n", parts: 2)
    %{"enrollment_id" => id, "pending_token" => token} = Jason.decode!(body)

    assert {:ok, socket} = UnifiedAgentTLSFixture.connect(fixture, port)

    denied =
      UnifiedAgentTLSFixture.request(socket, "GET", "/v1/agent/enrollments/#{id}/status", "", [
        {"Authorization", "Bearer incorrect"}
      ])

    assert denied =~ "HTTP/1.1 401"
    assert denied =~ "invalid_pending_token"

    assert {:ok, socket} = UnifiedAgentTLSFixture.connect(fixture, port)

    unapproved =
      UnifiedAgentTLSFixture.request(
        socket,
        "POST",
        "/v1/agent/enrollments/#{id}/csr",
        Jason.encode!(%{"csr_pem" => "invalid", "ssh_proof" => %{}}),
        [{"Authorization", "Bearer #{token}"}]
      )

    assert unapproved =~ "HTTP/1.1 400"
    assert unapproved =~ "invalid_status"

    assert {:ok, _} =
             CA.generate_root_ca(
               "Unified TLS proof test",
               "SecretHub Test",
               key_size: 2048
             )

    assert {:ok, _} = Enrollment.approve(id, "test-operator")
    assert {:ok, socket} = UnifiedAgentTLSFixture.connect(fixture, port)

    proof_denied =
      UnifiedAgentTLSFixture.request(
        socket,
        "POST",
        "/v1/agent/enrollments/#{id}/csr",
        Jason.encode!(%{"csr_pem" => "invalid", "ssh_proof" => %{"signature" => "invalid"}}),
        [{"Authorization", "Bearer #{token}"}]
      )

    assert proof_denied =~ "HTTP/1.1 400"
    refute proof_denied =~ "certificate_pem"
    assert proof_denied =~ "csr_invalid"
    enrollment = Repo.get!(SecretHub.Shared.Schemas.AgentEnrollment, id)
    assert enrollment.last_error["reason"] =~ "invalid_signature"
  end

  test "runtime upgrade rejects a missing certificate despite forged identity claims", %{
    fixture: fixture
  } do
    port = start_endpoint!()
    assert {:ok, socket} = UnifiedAgentTLSFixture.connect(fixture, port)

    response =
      UnifiedAgentTLSFixture.upgrade(socket, "&agent_id=forged&certificate=forged", [
        {"X-SSL-Client-Cert", "forged"},
        {"X-Agent-Id", "forged"}
      ])

    assert response =~ "HTTP/1.1 403"
    :ssl.close(socket)
  end

  test "actual TLS peer identity admits a trusted runtime join and ignores claimed agent IDs", %{
    fixture: fixture
  } do
    certificate = store_runtime_identity!(fixture)
    start_supervised!(SecretHub.Core.Agents.ConnectionManager)
    port = start_endpoint!()
    assert {:ok, socket} = connect_client(fixture, port)
    assert UnifiedAgentTLSFixture.upgrade(socket, "&agent_id=forged") =~ "HTTP/1.1 101"

    assert [
             "1",
             "1",
             "agent:runtime",
             "phx_reply",
             %{
               "status" => "ok",
               "response" => %{
                 "status" => "accepted",
                 "agent_id" => "tls-test",
                 "certificate_id" => certificate_id
               }
             }
           ] = UnifiedAgentTLSFixture.join_runtime(socket)

    assert certificate_id == certificate.id
    :ssl.close(socket)
  end

  test "revoked and wrong-type identities pass chain verification but cannot upgrade runtime", %{
    fixture: fixture
  } do
    certificate = store_runtime_identity!(fixture)
    port = start_endpoint!()

    for attrs <- [[revoked: true], [revoked: false, cert_type: :app_client]] do
      certificate |> Ecto.Changeset.change(attrs) |> Repo.update!()
      assert {:ok, socket} = connect_client(fixture, port)
      assert UnifiedAgentTLSFixture.upgrade(socket) =~ "HTTP/1.1 403"
      :ssl.close(socket)
    end
  end

  test "an unknown presented client certificate fails the TLS handshake", %{fixture: fixture} do
    port = start_endpoint!()

    assert {:error, {:tls_alert, _}} =
             UnifiedAgentTLSFixture.connect(fixture, port,
               certfile: to_charlist(Path.join(fixture.dir, "unknown-client.crt")),
               keyfile: to_charlist(Path.join(fixture.dir, "unknown-client.key"))
             )
  end

  test "TLS 1.3 allows certificate-free enrollment and rejects an unknown presented identity", %{
    fixture: fixture
  } do
    config = UnifiedAgentTLSFixture.config(fixture)
    transport = config[:https][:thousand_island_options][:transport_options]

    config =
      put_in(
        config,
        [:https, :thousand_island_options, :transport_options],
        Keyword.put(transport, :versions, [:"tlsv1.3"])
      )

    Application.put_env(:secrethub_web, AgentEndpoint, config)
    port = start_endpoint!()
    assert {:ok, socket} = UnifiedAgentTLSFixture.connect(fixture, port, versions: [:"tlsv1.3"])

    assert UnifiedAgentTLSFixture.request(socket, "POST", "/v1/agent/enrollments", "{}") =~
             "invalid_enrollment"

    result =
      UnifiedAgentTLSFixture.connect(fixture, port,
        versions: [:"tlsv1.3"],
        certfile: to_charlist(Path.join(fixture.dir, "unknown-client.crt")),
        keyfile: to_charlist(Path.join(fixture.dir, "unknown-client.key"))
      )

    # TLS 1.3 can report the server's rejection after the client's Finished.
    case result do
      {:error, {:tls_alert, _}} ->
        :ok

      {:ok, socket} ->
        assert {:error, {:tls_alert, _}} = :ssl.recv(socket, 0, 5_000)
        :ssl.close(socket)
    end
  end

  test "server verification rejects an untrusted CA", %{fixture: fixture} do
    port = start_endpoint!()

    assert {:error, {:tls_alert, _}} =
             UnifiedAgentTLSFixture.connect(fixture, port,
               cacertfile: to_charlist(Path.join(fixture.dir, "unknown-ca.crt"))
             )
  end

  test "server verification rejects an incorrect server name", %{fixture: fixture} do
    port = start_endpoint!()

    assert {:error, {:tls_alert, _}} =
             UnifiedAgentTLSFixture.connect(fixture, port,
               server_name_indication: ~c"wrong.example"
             )
  end

  defp start_endpoint! do
    assert :ok = AgentEndpointManager.ensure_started()
    assert {:ok, {{127, 0, 0, 1}, port}} = AgentEndpoint.server_info(:https)
    port
  end

  defp connect_client(fixture, port) do
    UnifiedAgentTLSFixture.connect(fixture, port,
      certfile: to_charlist(Path.join(fixture.dir, "client.crt")),
      keyfile: to_charlist(Path.join(fixture.dir, "client.key"))
    )
  end

  defp store_runtime_identity!(fixture) do
    pem = File.read!(Path.join(fixture.dir, "client.crt"))
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    certificate =
      Repo.insert!(%Certificate{
        serial_number: "tls-#{System.unique_integer([:positive])}",
        fingerprint: Certificate.fingerprint_from_pem(pem),
        certificate_pem: pem,
        subject: "CN=client",
        issuer: "CN=ca",
        common_name: "client",
        cert_type: :agent_client,
        valid_from: DateTime.add(now, -60),
        valid_until: DateTime.add(now, 3600),
        entity_id: "tls-test",
        entity_type: "agent",
        metadata: %{
          "extended_key_usage" => ["clientAuth"],
          "san_uri" => [
            "urn:secrethub:agent:tls-test",
            "urn:secrethub:hostkey-sha256:tls-test-host"
          ]
        }
      })

    Repo.insert!(%Agent{
      agent_id: "tls-test",
      name: "TLS fixture",
      status: :certificate_issued,
      certificate_id: certificate.id,
      ssh_host_key_fingerprint: "SHA256:tls-test-host"
    })

    certificate
  end
end
