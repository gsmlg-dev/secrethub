defmodule SecretHub.Agent.ConfigTest do
  use ExUnit.Case, async: true

  alias SecretHub.Agent.Config

  @moduletag :tmp_dir
  @config_env "SECRET_HUB_AGENT_CONFIG_FILE"
  @fields [
    {"core_url", :core_url, "SECRET_HUB_AGENT_CORE_URL", "https://core.example.test:4668"},
    {"host_key_path", :host_key_path, "SECRET_HUB_AGENT_HOST_KEY_PATH", "/etc/ssh/host-key"},
    {"state_dir", :state_dir, "SECRET_HUB_AGENT_STATE_DIR", "/var/lib/secrethub-agent"},
    {"socket_path", :socket_path, "SECRET_HUB_AGENT_SOCKET_PATH",
     "/run/secrethub-agent/agent.sock"},
    {"client_auth_bundle_dir", :client_auth_bundle_dir, "SECRET_HUB_CLIENT_AUTH_BUNDLE_DIR",
     "/var/lib/secrethub-agent/client-auth"}
  ]

  test "loads all required settings from one TOML file", %{tmp_dir: dir} do
    path = write_config!(dir)
    config = load(dir, %{@config_env => path})

    for {_file_key, key, _env, value} <- @fields, do: assert(config[key] == value)
    assert config[:enrollment_ca_path] == nil
  end

  test "discovers the default file without a configuration environment variable", %{tmp_dir: dir} do
    path = write_config!(dir)
    assert load(dir, %{}, default_path: path)[:core_url] == "https://core.example.test:4668"
  end

  test "retains environment-only configuration when no default file exists", %{tmp_dir: dir} do
    config = load(dir, environment())
    for {_file_key, key, _env, value} <- @fields, do: assert(config[key] == value)
  end

  test "allows environment settings to complete a partial or empty TOML file", %{tmp_dir: dir} do
    for settings <- [%{}, %{"state_dir" => "/file-state"}] do
      path = write_config!(dir, settings)
      env = Map.put(environment(), @config_env, path)
      config = load(dir, env)
      assert config[:core_url] == "https://core.example.test:4668"
      assert config[:state_dir] == "/var/lib/secrethub-agent"
    end
  end

  test "does not fall back when an explicitly selected configuration file is absent", %{
    tmp_dir: dir
  } do
    env = Map.put(environment(), @config_env, Path.join(dir, "private-missing.toml"))
    assert_error("#{@config_env}: invalid_file", fn -> load(dir, env) end)
  end

  test "rejects an empty explicit configuration file selection", %{tmp_dir: dir} do
    assert_error("#{@config_env}: empty", fn ->
      load(dir, Map.put(environment(), @config_env, ""))
    end)
  end

  test "environment values override their TOML counterparts", %{tmp_dir: dir} do
    path = write_config!(dir)

    overrides = %{
      @config_env => path,
      "SECRET_HUB_AGENT_CORE_URL" => "https://override.example.test:4668",
      "SECRET_HUB_AGENT_HOST_KEY_PATH" => "relative-env-host-key",
      "SECRET_HUB_AGENT_STATE_DIR" => "relative-env-state",
      "SECRET_HUB_AGENT_SOCKET_PATH" => "relative-env-socket",
      "SECRET_HUB_CLIENT_AUTH_BUNDLE_DIR" => "relative-env-bundle",
      "SECRET_HUB_AGENT_ENROLLMENT_CA_PATH" => "relative-env-ca.pem"
    }

    config = load(dir, overrides)
    assert config[:core_url] == overrides["SECRET_HUB_AGENT_CORE_URL"]
    assert config[:host_key_path] == "relative-env-host-key"
    assert config[:state_dir] == "relative-env-state"
    assert config[:socket_path] == "relative-env-socket"
    assert config[:client_auth_bundle_dir] == "relative-env-bundle"
    assert config[:enrollment_ca_path] == "relative-env-ca.pem"
  end

  test "environment value files override TOML and retain newline handling", %{tmp_dir: dir} do
    path = write_config!(dir)
    value_path = Path.join(dir, "core-url.value")
    File.write!(value_path, "https://from-file.example.test:4668\r\n")

    config =
      load(dir, %{
        @config_env => path,
        "SECRET_HUB_AGENT_CORE_URL_FILE" => value_path
      })

    assert config[:core_url] == "https://from-file.example.test:4668"
  end

  test "rejects conflicting direct and value-file environment sources despite TOML fallback", %{
    tmp_dir: dir
  } do
    path = write_config!(dir)
    value_path = Path.join(dir, "state.value")
    File.write!(value_path, "/private-state")

    assert_error("SECRET_HUB_AGENT_STATE_DIR: conflicting_sources", fn ->
      load(dir, %{
        @config_env => path,
        "SECRET_HUB_AGENT_STATE_DIR" => "/override-state",
        "SECRET_HUB_AGENT_STATE_DIR_FILE" => value_path
      })
    end)
  end

  test "rejects a blank environment override instead of using the TOML value", %{tmp_dir: dir} do
    path = write_config!(dir)

    assert_error("SECRET_HUB_AGENT_STATE_DIR: empty", fn ->
      load(dir, %{@config_env => path, "SECRET_HUB_AGENT_STATE_DIR" => ""})
    end)
  end

  test "reports every missing required option with its established environment name", %{
    tmp_dir: dir
  } do
    for {file_key, _key, env_name, _value} <- @fields do
      path = write_config!(dir, Map.delete(settings(), file_key))
      assert_error("#{env_name}: missing", fn -> load(dir, %{@config_env => path}) end)
    end
  end

  test "reports missing configuration in environment-only mode", %{tmp_dir: dir} do
    assert_error("SECRET_HUB_AGENT_CORE_URL: missing", fn -> load(dir) end)
  end

  test "rejects blank or oversized TOML scalar values with established option names", %{
    tmp_dir: dir
  } do
    for {value, reason} <- [{"", "empty"}, {String.duplicate("x", 4097), "too_large"}] do
      path = write_config!(dir, Map.put(settings(), "state_dir", value))

      assert_error("SECRET_HUB_AGENT_STATE_DIR: #{reason}", fn ->
        load(dir, %{@config_env => path})
      end)
    end
  end

  test "rejects unknown options without disclosing names or values", %{tmp_dir: dir} do
    path = write_config!(dir, Map.put(settings(), "private_unknown_option", "private-value"))
    assert_error("#{@config_env}: unknown_option", fn -> load(dir, %{@config_env => path}) end)
  end

  test "rejects non-string values without coercion or disclosure", %{tmp_dir: dir} do
    for value <- [42, false, ["private-value"], %{"private_nested" => "private-value"}] do
      path = write_config!(dir, Map.put(settings(), "state_dir", value))
      assert_error("#{@config_env}: invalid_value", fn -> load(dir, %{@config_env => path}) end)
    end
  end

  test "rejects malformed TOML without disclosing file paths or content", %{tmp_dir: dir} do
    path = Path.join(dir, "private-config-file.toml")
    File.write!(path, "private-secret = \"do-not-disclose\n")
    assert_error("#{@config_env}: invalid_toml", fn -> load(dir, %{@config_env => path}) end)
  end

  test "rejects directories selected as configuration files", %{tmp_dir: dir} do
    assert_error("#{@config_env}: invalid_file", fn -> load(dir, %{@config_env => dir}) end)
  end

  test "rejects configuration files larger than 64 KiB", %{tmp_dir: dir} do
    path = Path.join(dir, "oversized.toml")
    File.write!(path, String.duplicate("#", 65_537))
    assert_error("#{@config_env}: too_large", fn -> load(dir, %{@config_env => path}) end)
  end

  test "resolves file paths relative to the TOML directory", %{tmp_dir: dir} do
    config_dir = Path.join(dir, "config")
    File.mkdir_p!(config_dir)

    path =
      write_config!(config_dir, %{
        "core_url" => "https://core.example.test:4668",
        "host_key_path" => "host-key",
        "state_dir" => "../state",
        "socket_path" => "../run/agent.sock",
        "client_auth_bundle_dir" => "../state/client-auth",
        "enrollment_ca_path" => "ca.pem"
      })

    config = load(dir, %{@config_env => path})
    assert config[:host_key_path] == Path.join(config_dir, "host-key")
    assert config[:state_dir] == Path.join(dir, "state")
    assert config[:socket_path] == Path.join(dir, "run/agent.sock")
    assert config[:client_auth_bundle_dir] == Path.join(dir, "state/client-auth")
    assert config[:enrollment_ca_path] == Path.join(config_dir, "ca.pem")
  end

  test "treats shell and home markers as literal path data", %{tmp_dir: dir} do
    literal = "~/$HOME/$(touch should-not-exist)"
    path = write_config!(dir, Map.put(settings(), "state_dir", literal))

    assert load(dir, %{@config_env => path})[:state_dir] == Path.join(dir, literal)
    refute File.exists?(Path.join(dir, "should-not-exist"))
  end

  test "accepts an optional private enrollment CA path", %{tmp_dir: dir} do
    path = write_config!(dir, Map.put(settings(), "enrollment_ca_path", "/etc/secrethub/ca.pem"))
    assert load(dir, %{@config_env => path})[:enrollment_ca_path] == "/etc/secrethub/ca.pem"
  end

  test "rejects insecure enrollment URLs from either configuration source", %{tmp_dir: dir} do
    path = write_config!(dir, Map.put(settings(), "core_url", "http://private.example.test"))

    assert_error("SECRET_HUB_AGENT_CORE_URL: invalid_https_url", fn ->
      load(dir, %{@config_env => path})
    end)

    assert_error("SECRET_HUB_AGENT_CORE_URL: invalid_https_url", fn ->
      load(
        dir,
        Map.put(environment(), "SECRET_HUB_AGENT_CORE_URL", "http://private.example.test")
      )
    end)
  end

  test "validates TOML values even when an environment override would mask them", %{tmp_dir: dir} do
    path = write_config!(dir, Map.put(settings(), "core_url", "http://private.example.test"))

    assert_error("SECRET_HUB_AGENT_CORE_URL: invalid_https_url", fn ->
      load(dir, %{
        @config_env => path,
        "SECRET_HUB_AGENT_CORE_URL" => "https://override.example.test"
      })
    end)
  end

  test "validates a complete standalone file without requiring identity or state files", %{
    tmp_dir: dir
  } do
    path = write_config!(dir)
    assert Config.validate!(path) == :ok
  end

  test "validation selects an explicit file before environment and default paths", %{tmp_dir: dir} do
    path = write_config!(dir)

    assert Config.validate!(path,
             get_env: fn _ -> "invalid-environment-input" end,
             default_path: Path.join(dir, "absent.toml")
           ) == :ok
  end

  test "validation selects the configured file or default file when no argument is supplied", %{
    tmp_dir: dir
  } do
    path = write_config!(dir)

    assert Config.validate!(nil, get_env: fn _ -> nil end, default_path: path) == :ok

    assert Config.validate!(nil,
             get_env: &Map.get(%{@config_env => path}, &1),
             default_path: Path.join(dir, "absent.toml")
           ) == :ok
  end

  test "validation requires the selected file even when default selection is implicit", %{
    tmp_dir: dir
  } do
    assert_error("#{@config_env}: invalid_file", fn ->
      Config.validate!(nil,
        get_env: fn _ -> nil end,
        default_path: Path.join(dir, "absent.toml")
      )
    end)

    assert_error("#{@config_env}: empty", fn ->
      Config.validate!(nil, get_env: fn _ -> "" end)
    end)
  end

  test "validation requires file options without applying environment overrides", %{tmp_dir: dir} do
    for {file_key, _key, env_name, _value} <- @fields do
      path = write_config!(dir, Map.delete(settings(), file_key))

      assert_error("#{env_name}: missing", fn ->
        Config.validate!(path, get_env: &Map.get(environment(), &1))
      end)
    end
  end

  defp settings do
    Map.new(@fields, fn {file_key, _key, _env, value} -> {file_key, value} end)
  end

  defp environment do
    Map.new(@fields, fn {_file_key, _key, env, value} -> {env, value} end)
  end

  defp write_config!(dir, settings \\ settings()) do
    path = Path.join(dir, "agent.toml")

    contents =
      Enum.map_join(settings, "\n", fn {key, value} ->
        "#{key} = #{toml_value(value)}"
      end)

    File.write!(path, contents <> "\n")
    path
  end

  defp toml_value(value) when is_map(value) do
    values = Enum.map_join(value, ", ", fn {key, item} -> "#{key} = #{toml_value(item)}" end)
    "{ #{values} }"
  end

  defp toml_value(value), do: inspect(value, printable_limit: :infinity, limit: :infinity)

  defp load(dir, env \\ %{}, opts \\ []) do
    Config.load!(
      Keyword.merge(
        [get_env: &Map.get(env, &1), default_path: Path.join(dir, "missing-default.toml")],
        opts
      )
    )
  end

  defp assert_error(message, fun), do: assert_raise(ArgumentError, message, fun)
end
