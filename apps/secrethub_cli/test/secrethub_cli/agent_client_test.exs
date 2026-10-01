defmodule SecretHub.CLI.AgentClientTest do
  use ExUnit.Case, async: false
  alias SecretHub.CLI.{AgentClient, AgentSocketFixture}

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

  test "certificate alone cannot connect without an application private key" do
    assert {:error, "Missing required agent private key"} =
             AgentClient.get_secret("prod.db.password",
               socket_path: "/tmp/no-agent",
               certificate_path: "/tmp/no-cert"
             )
  end
end
