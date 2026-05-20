defmodule SecretHub.Agent.EnrollmentTest do
  use ExUnit.Case, async: true

  alias SecretHub.Agent.{Enrollment, HostKey}

  @tag :tmp_dir
  test "store_material writes a TLS PEM key separate from the OpenSSH host key", %{
    tmp_dir: tmp_dir
  } do
    host_key_path = generate_key!(tmp_dir, "ssh_host_rsa_key", "rsa")
    {:ok, host_key} = HostKey.discover(paths: [rsa: host_key_path])

    storage_dir = Path.join(tmp_dir, "certs")

    assert :ok =
             Enrollment.store_material(
               storage_dir,
               %{"enrollment_id" => "enrollment-1", "pending_token" => "token"},
               %{
                 "certificate_pem" =>
                   "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
                 "ca_chain_pem" =>
                   "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n"
               },
               %{"trusted_websocket_endpoint" => "wss://localhost:4665/agent/socket/websocket"},
               host_key
             )

    assert File.read!(Path.join(storage_dir, "agent-key.pem")) =~ "BEGIN PRIVATE KEY"
    assert File.read!(host_key_path) =~ "BEGIN OPENSSH PRIVATE KEY"
  end

  defp generate_key!(tmp_dir, name, type) do
    path = Path.join(tmp_dir, name)

    {_, 0} =
      System.cmd("ssh-keygen", [
        "-q",
        "-t",
        type,
        "-N",
        "",
        "-f",
        path
      ])

    path
  end
end
