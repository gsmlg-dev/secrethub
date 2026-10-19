defmodule SecretHub.Agent.Config do
  @moduledoc "Loads standalone Agent TOML settings and existing environment overrides."

  alias SecretHub.Shared.{RuntimeConfig, RuntimeSecrets}

  @config_env "SECRET_HUB_AGENT_CONFIG_FILE"
  @default_path "/etc/secrethub/agent.toml"
  @max_file_bytes 65_536
  @fields [
    {:core_url, "SECRET_HUB_AGENT_CORE_URL", true},
    {:host_key_path, "SECRET_HUB_AGENT_HOST_KEY_PATH", true},
    {:state_dir, "SECRET_HUB_AGENT_STATE_DIR", true},
    {:socket_path, "SECRET_HUB_AGENT_SOCKET_PATH", true},
    {:client_auth_bundle_dir, "SECRET_HUB_CLIENT_AUTH_BUNDLE_DIR", true},
    {:enrollment_ca_path, "SECRET_HUB_AGENT_ENROLLMENT_CA_PATH", false}
  ]

  @doc "Loads validated settings; environment inputs take precedence over the file."
  def load!(opts \\ []) do
    get_env = Keyword.get(opts, :get_env, &System.get_env/1)
    default_path = Keyword.get(opts, :default_path, @default_path)

    file_config =
      case get_env.(@config_env) do
        nil -> read_file!(default_path, true)
        "" -> config_error!(:empty)
        path -> read_file!(path, false)
      end

    Enum.map(@fields, fn {key, env_name, required} ->
      value =
        RuntimeSecrets.read!(env_name, required: false, get_env: get_env) || file_config[key]

      if required and is_nil(value), do: raise(ArgumentError, "#{env_name}: missing")
      if key == :core_url, do: RuntimeConfig.https_url!(env_name, value)
      {key, value}
    end)
  end

  @doc "Validates a complete TOML file without applying option environment overrides."
  def validate!(path \\ nil, opts \\ []) do
    get_env = Keyword.get(opts, :get_env, &System.get_env/1)
    path = path || get_env.(@config_env) || Keyword.get(opts, :default_path, @default_path)
    if path == "", do: config_error!(:empty)
    settings = read_file!(path, false)

    Enum.each(@fields, fn {key, env_name, required} ->
      if required and not Map.has_key?(settings, key),
        do: raise(ArgumentError, "#{env_name}: missing")
    end)

    :ok
  end

  defp read_file!(path, optional) do
    case File.stat(path) do
      {:error, :enoent} when optional ->
        %{}

      {:ok, %{type: :regular, size: size}} when size > @max_file_bytes ->
        config_error!(:too_large)

      {:ok, %{type: :regular}} ->
        case File.read(path) do
          {:ok, contents} when byte_size(contents) <= @max_file_bytes ->
            contents |> decode!() |> validate_file!(Path.dirname(Path.expand(path)))

          {:ok, _contents} ->
            config_error!(:too_large)

          {:error, _reason} ->
            config_error!(:invalid_file)
        end

      _ ->
        config_error!(:invalid_file)
    end
  end

  defp decode!(contents) do
    case Toml.decode(contents) do
      {:ok, config} -> config
      {:error, _reason} -> config_error!(:invalid_toml)
    end
  rescue
    _ -> config_error!(:invalid_toml)
  end

  defp validate_file!(config, directory) do
    names = Enum.map(@fields, fn {key, _, _} -> Atom.to_string(key) end)

    unless Enum.all?(Map.keys(config), &(&1 in names)), do: config_error!(:unknown_option)

    Enum.reduce(@fields, %{}, fn {key, env_name, _required}, values ->
      case Map.fetch(config, Atom.to_string(key)) do
        {:ok, value} ->
          validate_value!(env_name, value)
          resolved = resolve_value!(key, env_name, value, directory)
          Map.put(values, key, resolved)

        :error ->
          values
      end
    end)
  end

  defp resolve_value!(:core_url, env_name, value, _directory) do
    RuntimeConfig.https_url!(env_name, value)
    value
  end

  defp resolve_value!(_key, _env_name, value, directory) do
    # Joining first keeps a leading ~ literal instead of expanding HOME.
    if Path.type(value) == :absolute,
      do: Path.expand(value),
      else: Path.expand(Path.join(directory, value))
  end

  defp validate_value!(env_name, value) when is_binary(value) do
    cond do
      String.trim(value) == "" -> raise ArgumentError, "#{env_name}: empty"
      byte_size(value) > 4096 -> raise ArgumentError, "#{env_name}: too_large"
      true -> :ok
    end
  end

  defp validate_value!(_env_name, _value), do: config_error!(:invalid_value)

  defp config_error!(reason), do: raise(ArgumentError, "#{@config_env}: #{reason}")
end
