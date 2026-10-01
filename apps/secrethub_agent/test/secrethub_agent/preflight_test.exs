defmodule SecretHub.Agent.PreflightTest do
  use ExUnit.Case, async: false
  alias SecretHub.Agent.{HostKey, IdentityStore, Preflight}

  @moduletag :tmp_dir
  setup %{tmp_dir: dir} do
    original = Application.get_all_env(:secrethub_agent)

    on_exit(fn ->
      for {key, _} <- Application.get_all_env(:secrethub_agent),
          do: Application.delete_env(:secrethub_agent, key)

      for {key, value} <- original, do: Application.put_env(:secrethub_agent, key, value)
    end)

    key_path = Path.join(dir, "host-key")

    {_output, 0} =
      System.cmd("ssh-keygen", ["-q", "-t", "rsa", "-b", "2048", "-N", "", "-f", key_path])

    File.chmod!(dir, 0o700)

    for {key, value} <- [
          launch_profile: :single_operator,
          state_dir: dir,
          socket_path: Path.join(dir, "agent.sock"),
          client_auth_bundle_dir: dir,
          enrollment_opts: [paths: [rsa: key_path]]
        ] do
      Application.put_env(:secrethub_agent, key, value)
    end

    %{key_path: key_path}
  end

  test "fresh private persistent directories can enroll without Core database inputs" do
    assert :ok = Preflight.startup_validate()
    assert Enum.all?(Preflight.checks(), fn {_name, value} -> value == true end)
  end

  test "damaged identity never becomes an automatic fresh enrollment", %{tmp_dir: dir} do
    File.write!(Path.join(dir, "agent-key.pem"), "private-marker")
    refute Preflight.checks().identity
    assert {:error, :agent_preflight_failed} = Preflight.startup_validate()
    assert File.read!(Path.join(dir, "agent-key.pem")) == "private-marker"
  end

  test "world-readable host identity is rejected without changing permissions", %{key_path: path} do
    File.chmod!(path, 0o644)
    refute Preflight.checks().host_key
    assert {:error, :agent_preflight_failed} = Preflight.startup_validate()
  end

  test "inspect redacts private host and runtime key material" do
    refute inspect(%HostKey{
             private_key_pem: "private-marker",
             private_key: {:private, "private-marker"}
           }) =~ "private-marker"

    refute inspect(%IdentityStore{private_key_pem: "private-marker"}) =~ "private-marker"
  end
end
