defmodule SecretHub.CLI.Config do
  @moduledoc """
  Configuration management for SecretHub CLI.

  Stores configuration in `~/.secrethub/config.toml`.
  """

  @default_config_dir Path.expand("~/.secrethub")

  @doc """
  Gets the configuration directory path.
  """
  def config_dir do
    Application.get_env(:secrethub_cli, :config_dir, @default_config_dir)
  end

  @doc """
  Gets the configuration file path.
  """
  def config_file do
    Path.join(config_dir(), "config.toml")
  end

  @doc """
  Loads the configuration from disk.

  Returns a map with configuration values.
  """
  def load do
    case File.read(config_file()) do
      {:ok, content} ->
        case Toml.decode(content) do
          {:ok, config} -> {:ok, config}
          {:error, reason} -> {:error, "Failed to parse config: #{inspect(reason)}"}
        end

      {:error, :enoent} ->
        {:ok, default_config()}

      {:error, reason} ->
        {:error, "Failed to read config: #{inspect(reason)}"}
    end
  end

  @doc """
  Saves configuration to disk.
  """
  def save(config) do
    with :ok <- ensure_config_dir(),
         toml = encode_toml(config),
         :ok <- File.write(config_file(), toml) do
      :ok
    else
      {:error, reason} -> {:error, "Failed to save config: #{inspect(reason)}"}
    end
  end

  @doc """
  Gets a configuration value.
  """
  def get(key) when is_binary(key) do
    with {:ok, config} <- load() do
      value = get_in(config, parse_key_for_get(key))
      {:ok, value}
    end
  end

  @doc """
  Sets a configuration value.
  """
  def set(key, value) when is_binary(key) do
    with {:ok, config} <- load() do
      updated_config = put_in(config, parse_key_for_set(key), value)
      save(updated_config)
    end
  end

  @doc """
  Deletes a configuration value.
  """
  def delete(key) when is_binary(key) do
    with {:ok, config} <- load() do
      {_, updated_config} = pop_in(config, parse_key_for_get(key))
      save(updated_config)
    end
  end

  @doc """
  Gets the server URL from config.
  """
  def get_server_url do
    case get("server_url") do
      {:ok, url} when is_binary(url) -> url
      _ -> "http://localhost:4000"
    end
  end

  @doc """
  Gets the output format from config.
  """
  def get_output_format do
    case get("output.format") do
      {:ok, format} when format in ["json", "table", "yaml"] -> format
      _ -> "table"
    end
  end

  @doc """
  Gets authentication token.
  """
  def get_auth_token do
    case get("auth.token") do
      {:ok, token} when is_binary(token) ->
        check_token_expiration(token)

      _ ->
        {:error, :not_found}
    end
  end

  defp check_token_expiration(token) do
    case get("auth.expires_at") do
      {:ok, expires_str} when is_binary(expires_str) ->
        validate_expiration(token, expires_str)

      _ ->
        # No expires_at field, assume token is valid
        {:ok, token}
    end
  end

  defp validate_expiration(token, expires_str) do
    case DateTime.from_iso8601(expires_str) do
      {:ok, expires, _} ->
        if DateTime.compare(expires, DateTime.utc_now()) == :gt do
          {:ok, token}
        else
          {:error, :expired}
        end

      _ ->
        # Invalid date format, assume token is valid
        {:ok, token}
    end
  end

  @doc """
  Saves authentication credentials.
  """
  def save_auth(token, expires_at) do
    with {:ok, config} <- load() do
      auth_config = %{
        "token" => token,
        "expires_at" => DateTime.to_iso8601(expires_at),
        "authenticated_at" => DateTime.to_iso8601(DateTime.utc_now())
      }

      updated_config = Map.put(config, "auth", auth_config)
      save(updated_config)
    end
  end

  @doc """
  Clears authentication credentials.
  """
  def clear_auth do
    delete("auth")
  end

  ## Private Functions

  defp ensure_config_dir do
    dir = config_dir()

    case File.mkdir_p(dir) do
      :ok ->
        # Set directory permissions to 0700 (owner only)
        File.chmod(dir, 0o700)

      error ->
        error
    end
  end

  defp default_config do
    %{
      "server_url" => "http://localhost:4000",
      "output" => %{
        "format" => "table",
        "color" => true
      }
    }
  end

  # Parse key for get operations - returns nil for non-existent keys
  defp parse_key_for_get(key) do
    key
    |> String.split(".")
    |> Enum.map(&Access.key/1)
  end

  # Parse key for set operations - creates intermediate maps
  defp parse_key_for_set(key) do
    key
    |> String.split(".")
    |> Enum.map(&Access.key(&1, %{}))
  end

  defp encode_toml(config) when is_map(config) do
    {sections, values} =
      Enum.split_with(config, fn {_key, value} -> is_map(value) end)

    # Encode top-level values
    top_level =
      Enum.map_join(values, "\n", fn {key, value} ->
        "#{key} = #{encode_toml_value(value)}"
      end)

    # Encode sections
    section_strings =
      sections
      |> Enum.map(fn {section_name, section_map} ->
        section_values =
          Enum.map_join(section_map, "\n", fn {key, value} ->
            "#{key} = #{encode_toml_value(value)}"
          end)

        "[#{section_name}]\n#{section_values}"
      end)

    # Combine with blank line between top-level and sections
    [top_level | section_strings]
    |> Enum.reject(&(&1 == ""))
    |> Enum.join("\n\n")
    |> Kernel.<>("\n")
  end

  defp encode_toml_value(value) when is_binary(value), do: ~s("#{value}")
  defp encode_toml_value(value) when is_boolean(value), do: to_string(value)
  defp encode_toml_value(value) when is_number(value), do: to_string(value)

  defp encode_toml_value(value) when is_list(value) do
    "[" <> Enum.map_join(value, ", ", &encode_toml_value/1) <> "]"
  end

  defp encode_toml_value(value) when is_map(value) do
    # Encode as TOML inline table: {key = "value", key2 = "value2"}
    "{" <>
      Enum.map_join(value, ", ", fn {k, v} ->
        "#{k} = #{encode_toml_value(v)}"
      end) <> "}"
  end

  defp encode_toml_value(value), do: inspect(value)
end
