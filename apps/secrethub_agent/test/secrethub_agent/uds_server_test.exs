defmodule SecretHub.Agent.UDSServerTest do
  use ExUnit.Case, async: false
  import Bitwise
  alias SecretHub.Agent.{Cache, CertVerifier, UDSAuth, UDSServer}
  alias X509.Certificate.Extension

  setup do
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
    %{socket: socket, path: path}
  end

  test "socket is owner-only and legacy auth cannot bypass Core floor", %{
    socket: socket,
    path: path
  } do
    assert (File.stat!(path).mode &&& 0o777) == 0o600
    assert error(request(socket, "authenticate", %{})) == "INCOMPATIBLE_VERSION"
    assert {:error, :closed} = :gen_tcp.recv(socket, 0, 1000)
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
    do: {:ok, %{responses: Keyword.fetch!(opts, :responses), owner: Keyword.fetch!(opts, :owner)}}

  def handle_call({:get_static_secret_for_app, _path, claims, revision}, _from, state) do
    send(state.owner, {:core_request, claims, revision})
    [response | responses] = state.responses
    {:reply, response, %{state | responses: responses}}
  end
end
