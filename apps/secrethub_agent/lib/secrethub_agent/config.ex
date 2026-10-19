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

  @ssh_fields [
    {:ssh_lookup_enabled, "SECRET_HUB_AGENT_SSH_LOOKUP_ENABLED", :boolean},
    {:ssh_signing_enabled, "SECRET_HUB_AGENT_SSH_SIGNING_ENABLED", :boolean},
    {:ssh_lookup_socket_path, "SECRET_HUB_AGENT_SSH_LOOKUP_SOCKET_PATH", :path},
    {:ssh_signing_socket_path, "SECRET_HUB_AGENT_SSH_SIGNING_SOCKET_PATH", :path},
    {:ssh_lookup_socket_group, "SECRET_HUB_AGENT_SSH_LOOKUP_SOCKET_GROUP", :group},
    {:ssh_signing_socket_group, "SECRET_HUB_AGENT_SSH_SIGNING_SOCKET_GROUP", :group}
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

    settings =
      Enum.map(@fields, fn {key, env_name, required} ->
        value =
          RuntimeSecrets.read!(env_name, required: false, get_env: get_env) || file_config[key]

        if required and is_nil(value), do: raise(ArgumentError, "#{env_name}: missing")
        if key == :core_url, do: RuntimeConfig.https_url!(env_name, value)
        {key, value}
      end)

    ssh =
      Enum.map(@ssh_fields, fn {key, env_name, type} ->
        value =
          RuntimeSecrets.read!(env_name, required: false, get_env: get_env) || file_config[key]

        {key, ssh_value!(type, value)}
      end)

    settings = settings ++ ssh
    validate_ssh!(settings)
    settings
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

    validate_ssh!(Map.to_list(settings))
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
    names = Enum.map(@fields ++ @ssh_fields, fn {key, _, _} -> Atom.to_string(key) end)

    unless Enum.all?(Map.keys(config), &(&1 in names)), do: config_error!(:unknown_option)

    values =
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

    Enum.reduce(@ssh_fields, values, fn {key, _env_name, type}, values ->
      value = ssh_value!(type, config[Atom.to_string(key)])

      resolved =
        if type == :path and value,
          do: resolve_value!(key, "SSH socket path", value, directory),
          else: value

      Map.put(values, key, resolved)
    end)
  end

  defp ssh_value!(:boolean, nil), do: false
  defp ssh_value!(:boolean, value) when is_boolean(value), do: value
  defp ssh_value!(:boolean, "true"), do: true
  defp ssh_value!(:boolean, "false"), do: false
  defp ssh_value!(:boolean, _), do: config_error!(:invalid_ssh_boolean)
  defp ssh_value!(_, nil), do: nil

  defp ssh_value!(:path, value) do
    validate_value!("SSH socket path", value)
    value
  end

  defp ssh_value!(:group, value) when is_binary(value) do
    if Regex.match?(~r/\A[a-zA-Z_][a-zA-Z0-9_-]{0,63}\z/, value),
      do: value,
      else: config_error!(:invalid_ssh_group)
  end

  defp ssh_value!(_, _), do: config_error!(:invalid_ssh_value)

  defp validate_ssh!(settings) do
    paths =
      [
        settings[:socket_path],
        settings[:ssh_lookup_socket_path],
        settings[:ssh_signing_socket_path]
      ]
      |> Enum.reject(&is_nil/1)
      |> Enum.map(&Path.expand/1)

    if length(paths) != length(Enum.uniq(paths)), do: config_error!(:ssh_socket_paths_must_differ)

    for path <- [settings[:ssh_lookup_socket_path], settings[:ssh_signing_socket_path]],
        is_binary(path) do
      if Path.type(path) != :absolute or byte_size(path) > 100,
        do: config_error!(:invalid_ssh_socket_path)

      for directory <- [settings[:state_dir], settings[:client_auth_bundle_dir]],
          is_binary(directory) do
        if path == Path.expand(directory) or
             String.starts_with?(path, Path.expand(directory) <> "/"),
           do: config_error!(:ssh_socket_must_be_outside_private_state)
      end
    end

    for {enabled, path, group} <- [
          {:ssh_lookup_enabled, :ssh_lookup_socket_path, :ssh_lookup_socket_group},
          {:ssh_signing_enabled, :ssh_signing_socket_path, :ssh_signing_socket_group}
        ] do
      if settings[enabled] and (is_nil(settings[path]) or is_nil(settings[group])),
        do: config_error!(:ssh_socket_path_and_group_required)
    end

    :ok
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
