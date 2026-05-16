defmodule SecretHub.Agent.HostKeyTest do
  use ExUnit.Case, async: true

  alias SecretHub.Agent.HostKey

  @tag :tmp_dir
  test "discovers ECDSA before RSA and returns OpenSSH fingerprint", %{tmp_dir: tmp_dir} do
    ecdsa = generate_key!(tmp_dir, "ssh_host_ecdsa_key", "ecdsa")
    rsa = generate_key!(tmp_dir, "ssh_host_rsa_key", "rsa")

    assert {:ok, host_key} =
             HostKey.discover(paths: [ecdsa: ecdsa, rsa: rsa])

    assert host_key.algorithm == "ecdsa"
    assert host_key.path == ecdsa
    assert String.starts_with?(host_key.fingerprint, "SHA256:")
    assert host_key.fingerprint == ssh_keygen_fingerprint!(ecdsa)
  end

  @tag :tmp_dir
  test "falls back to RSA when no ECDSA host key is available", %{tmp_dir: tmp_dir} do
    rsa = generate_key!(tmp_dir, "ssh_host_rsa_key", "rsa")

    assert {:ok, host_key} =
             HostKey.discover(paths: [ecdsa: Path.join(tmp_dir, "missing"), rsa: rsa])

    assert host_key.algorithm == "rsa"
    assert host_key.path == rsa
  end

  @tag :tmp_dir
  test "rejects Ed25519 host keys in v1", %{tmp_dir: tmp_dir} do
    ed25519 = generate_key!(tmp_dir, "ssh_host_ed25519_key", "ed25519")

    assert {:error, {:unsupported_host_key_algorithm, "ed25519"}} =
             HostKey.discover(paths: [ed25519: ed25519])
  end

  test "does not generate fallback keys when no supported host key exists" do
    assert {:error, :no_supported_ssh_host_key} =
             HostKey.discover(paths: [ecdsa: "/no/such/ecdsa", rsa: "/no/such/rsa"])
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

  defp ssh_keygen_fingerprint!(path) do
    {output, 0} = System.cmd("ssh-keygen", ["-l", "-f", "#{path}.pub"])

    output
    |> String.split()
    |> Enum.at(1)
  end
end
