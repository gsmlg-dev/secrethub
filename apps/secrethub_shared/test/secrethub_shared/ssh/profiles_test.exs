defmodule SecretHub.Shared.SSH.ProfilesTest do
  use ExUnit.Case, async: true
  alias SecretHub.Shared.SSH.Profiles
  @moduletag :tmp_dir

  test "OpenSSH resolves the generated strict client profile", ctx do
    assert {:ok, config} =
             Profiles.client(
               base: "/opt/secrethub",
               hosts: ["example.test", "192.0.2.10", "::1"],
               lookup_socket: "/run/ssh-lookup/agent.sock",
               signing_socket: "/run/ssh-sign/agent.sock"
             )

    path = Path.join(ctx.tmp_dir, "ssh_config")
    File.write!(path, config)
    {effective, 0} = System.cmd("ssh", ["-G", "-F", path, "example.test"], stderr_to_stdout: true)

    for expected <- [
          "stricthostkeychecking true",
          "verifyhostkeydns false",
          "forwardagent no",
          "userknownhostsfile /dev/null",
          "globalknownhostsfile /dev/null",
          "identityagent /run/ssh-sign/agent.sock"
        ] do
      assert effective =~ expected
    end

    assert effective =~ "fetch-ssh-host-keys --socket /run/ssh-lookup/agent.sock %I %H %p"

    {unrelated, 0} =
      System.cmd("ssh", ["-G", "-F", path, "unmanaged.test"], stderr_to_stdout: true)

    refute unrelated =~ "fetch-ssh-host-keys"
    refute unrelated =~ "knownhostsfile /dev/null"
    refute unrelated =~ "identityagent /run/ssh-sign/agent.sock"
  end

  test "sshd resolves account-scoped key and CA restrictions and detects earlier Match overrides",
       ctx do
    key = Path.join(ctx.tmp_dir, "host")
    {_, 0} = System.cmd("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", key])

    assert {:ok, profile} =
             Profiles.server(
               base: "/opt/secrethub",
               lookup_socket: "/run/ssh-lookup/agent.sock",
               users: ["deploy", "builder"]
             )

    path = Path.join(ctx.tmp_dir, "sshd_config")
    File.write!(path, "HostKey #{key}\nUsePAM no\n" <> profile)
    assert :ok = Profiles.verify_server(path, "deploy")
    assert :ok = Profiles.verify_server(path, "builder")
    assert {:error, :unsafe_effective_config} = Profiles.verify_server(path, "other")

    File.write!(
      path,
      "HostKey #{key}\nUsePAM no\nMatch User deploy\n  AuthorizedKeysFile /tmp/unmanaged\n" <>
        profile
    )

    assert {:error, :unsafe_effective_config} = Profiles.verify_server(path, "deploy")
  end

  test "profile interpolation refuses directives and unsafe paths" do
    for base <- ["relative", "/opt/ssh\nPermitRootLogin yes", "/opt/ssh %u", "/opt/ssh;id"] do
      assert {:error, :invalid_options} = Profiles.client(base: base, hosts: ["example.test"])
    end

    assert {:error, :invalid_options} =
             Profiles.server(base: "/opt/secrethub", users: ["deploy,*"])

    assert {:error, :invalid_options} = Profiles.server(base: "/opt/secrethub", users: [])
    assert {:error, :invalid_options} = Profiles.client(base: "/opt/secrethub")

    for host <- ["*", "!example.test", "host\nHost *", "example.test other.test"] do
      assert {:error, :invalid_options} = Profiles.client(base: "/opt/secrethub", hosts: [host])
    end
  end
end
