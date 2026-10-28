defmodule SecretHub.CLI.AgentClientTest do
  use ExUnit.Case, async: false
  alias SecretHub.CLI.{AgentClient, AgentSocketFixture}

  test "reads directly over a Unix socket without application credentials" do
    path = socket_path()
    server = AgentSocketFixture.start_local(path, self())
    assert_receive :agent_socket_ready

    assert {:ok, %{"value" => "from-agent"}} =
             AgentClient.get_secret("prod.db.password", socket_path: path)

    assert_receive {:local_request,
                    %{"action" => "get_secret", "params" => %{"path" => "prod.db.password"}}}

    Task.await(server, 5000)
  end

  test "credential-free reads preserve structured values with application envelope keys" do
    path = socket_path()
    value = %{"value" => "application-value", "data" => %{"format" => "custom"}}
    server = AgentSocketFixture.start_local(path, self(), {:ok, value})
    assert_receive :agent_socket_ready

    assert {:ok, ^value} = AgentClient.get_secret("prod.app.config", socket_path: path)
    Task.await(server, 5000)
  end

  test "a private key alone cannot fall back to a local read" do
    assert {:error, "Missing required agent certificate"} =
             AgentClient.get_secret("prod.db.password",
               socket_path: "/tmp/no-agent",
               private_key_path: "/tmp/no-key"
             )
  end

  @tag :tmp_dir
  test "invalid explicit application credentials cannot fall back to a local read", %{
    tmp_dir: dir
  } do
    certificate = Path.join(dir, "invalid.crt")
    key = Path.join(dir, "invalid.key")
    File.write!(certificate, "not a certificate")
    File.write!(key, "not a private key")

    assert {:error, "Invalid agent private key"} =
             AgentClient.get_secret("prod.db.password",
               socket_path: "/tmp/no-agent",
               certificate_path: certificate,
               private_key_path: key
             )
  end

  @tag :tmp_dir
  test "failed explicit application authentication does not retry as a local read", %{
    tmp_dir: dir
  } do
    path = socket_path()
    material = AgentSocketFixture.material(dir)
    server = AgentSocketFixture.start_local(path, self(), {:error, "PROOF_FAILED"})
    assert_receive :agent_socket_ready

    assert {:error, "PROOF_FAILED"} =
             AgentClient.get_secret("prod.db.password",
               socket_path: path,
               certificate_path: material.certificate_path,
               private_key_path: material.private_key_path
             )

    assert_receive {:local_request, %{"action" => "authenticate"}}
    refute_receive {:local_request, %{"action" => "get_secret"}}
    Task.await(server, 5000)
  end

  @tag :tmp_dir
  test "authenticates with RSA-PSS and ECDSA possession before retrieving a secret", %{
    tmp_dir: dir
  } do
    for key <- [X509.PrivateKey.new_rsa(2048), X509.PrivateKey.new_ec(:secp256r1)] do
      path = Path.join(System.tmp_dir!(), "sh-cli-#{System.unique_integer([:positive])}.sock")
      on_exit(fn -> File.rm(path) end)
      material = AgentSocketFixture.material(dir, key)
      server = AgentSocketFixture.start(path, self(), material)
      assert_receive :agent_socket_ready

      assert {:ok, %{"value" => "from-agent"}} =
               AgentClient.get_secret("prod.db.password",
                 socket_path: path,
                 certificate_path: material.certificate_path,
                 private_key_path: material.private_key_path
               )

      pem = Base.encode64(material.pem)
      assert_receive {:auth_request, %{"params" => %{"auth_version" => 2, "certificate" => ^pem}}}
      assert_receive {:proof_verified, true}
      assert_receive {:secret_request, %{"params" => %{"path" => "prod.db.password"}}}
      Task.await(server, 5000)
    end
  end

  @tag :tmp_dir
  test "structured application keys survive the single UDS envelope unwrap", %{tmp_dir: dir} do
    path = Path.join(System.tmp_dir!(), "sh-cli-#{System.unique_integer([:positive])}.sock")
    on_exit(fn -> File.rm(path) end)
    material = AgentSocketFixture.material(dir)

    value = %{
      "value" => "application-value",
      "data" => %{"format" => "custom"},
      "region" => "test"
    }

    server = AgentSocketFixture.start(path, self(), material, value)
    assert_receive :agent_socket_ready

    assert {:ok, ^value} =
             AgentClient.get_secret("prod.app.config",
               socket_path: path,
               certificate_path: material.certificate_path,
               private_key_path: material.private_key_path
             )

    Task.await(server, 5000)
  end

  test "certificate alone cannot connect without an application private key" do
    assert {:error, "Missing required agent private key"} =
             AgentClient.get_secret("prod.db.password",
               socket_path: "/tmp/no-agent",
               certificate_path: "/tmp/no-cert"
             )
  end

  defp socket_path do
    path = Path.join(System.tmp_dir!(), "sh-cli-#{System.unique_integer([:positive])}.sock")
    on_exit(fn -> File.rm(path) end)
    path
  end
end
