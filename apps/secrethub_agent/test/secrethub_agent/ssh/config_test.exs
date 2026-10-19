defmodule SecretHub.Agent.SSH.ConfigTest do
  use ExUnit.Case, async: true
  alias SecretHub.Agent.Config
  @moduletag :tmp_dir
  test "SSH defaults off, explicit separate paths/groups are required", %{tmp_dir: _dir} do
    directory =
      Path.join(
        System.tmp_dir!(),
        "shc-" <> Integer.to_string(System.unique_integer([:positive]))
      )

    File.mkdir_p!(directory)
    on_exit(fn -> File.rm_rf(directory) end)
    path = Path.join(directory, "agent.toml")

    base =
      "core_url = \"https://example.com\"\nhost_key_path = \"host\"\nstate_dir = \"state\"\nsocket_path = \"private\"\nclient_auth_bundle_dir = \"bundle\"\n"

    File.write!(path, base)

    env = fn
      "SECRET_HUB_AGENT_CONFIG_FILE" -> path
      _ -> nil
    end

    assert Config.load!(get_env: env)[:ssh_lookup_enabled] == false
    File.write!(path, base <> "ssh_lookup_enabled = true\n")
    assert_raise ArgumentError, fn -> Config.load!(get_env: env) end

    File.write!(
      path,
      base <>
        "ssh_lookup_enabled = true\nssh_lookup_socket_path = \"lookup.sock\"\nssh_lookup_socket_group = \"lookup\"\n"
    )

    settings = Config.load!(get_env: env)
    assert settings[:ssh_lookup_enabled]
    assert settings[:ssh_lookup_socket_path] == Path.join(directory, "lookup.sock")
    assert settings[:ssh_lookup_socket_group] == "lookup"

    File.write!(
      path,
      base <>
        "ssh_lookup_enabled = true\nssh_lookup_socket_path = \"private\"\nssh_lookup_socket_group = \"lookup\"\n"
    )

    assert_raise ArgumentError, fn -> Config.load!(get_env: env) end

    File.write!(
      path,
      base <>
        "ssh_lookup_enabled = true\nssh_lookup_socket_path = \"state/lookup.sock\"\nssh_lookup_socket_group = \"lookup\"\n"
    )

    assert_raise ArgumentError, fn -> Config.load!(get_env: env) end
  end
end
