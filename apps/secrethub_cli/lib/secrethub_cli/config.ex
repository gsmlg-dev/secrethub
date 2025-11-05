defmodule SecretHub.CLI.Config do
  @moduledoc """
  Configuration management for SecretHub CLI.

  Stores configuration in `~/.secrethub/config.toml`.
  """

  @config_dir Path.expand("~/.secrethub")
  @config_file Path.join(@config_dir, "config.toml")

  @doc """
  Gets the configuration directory path.
  """
  def config_dir, do: @config_dir

  @doc """
  Gets the configuration file path.
  """
  def config_file, do: @config_file

  @doc """
  Loads the configuration from disk.

  Returns a map with configuration values.
  """
  def load do
    case File.read(@config_file) do
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
         :ok <- File.write(@config_file, toml) do
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
      value = get_in(config, parse_key(key))
      {:ok, value}
    end
  end

  @doc """
  Sets a configuration value.
  """
  def set(key, value) when is_binary(key) do
    with {:ok, config} <- load() do
      updated_config = put_in(config, parse_key(key), value)
      save(updated_config)
    end
  end

  @doc """
  Deletes a configuration value.
  """
  def delete(key) when is_binary(key) do
    with {:ok, config} <- load() do
      {_, updated_config} = pop_in(config, parse_key(key))
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
        # Check if token is expired
        case get("auth.expires_at") do
          {:ok, expires_str} ->
            case DateTime.from_iso8601(expires_str) do
              {:ok, expires, _} ->
                if DateTime.compare(expires, DateTime.utc_now()) == :gt do
                  {:ok, token}
                else
                  {:error, :expired}
                end

              _ ->
                {:ok, token}
            end

          _ ->
            {:ok, token}
        end

      _ ->
        {:error, :not_found}
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
    case File.mkdir_p(@config_dir) do
      :ok ->
        # Set directory permissions to 0700 (owner only)
        File.chmod(@config_dir, 0o700)

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

  defp parse_key(key) do
    key
    |> String.split(".")
    |> Enum.map(&Access.key(&1, %{}))
  end

  defp encode_toml(config) when is_map(config) do
    {sections, values} =
      Enum.split_with(config, fn {_key, value} -> is_map(value) end)

    # Encode top-level values
    top_level =
      values
      |> Enum.map(fn {key, value} -> "#{key} = #{encode_toml_value(value)}" end)
      |> Enum.join("\n")

    # Encode sections
    section_strings =
      sections
      |> Enum.map(fn {section_name, section_map} ->
        section_values =
          section_map
          |> Enum.map(fn {key, value} -> "#{key} = #{encode_toml_value(value)}" end)
          |> Enum.join("\n")

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
    items = Enum.map(value, &encode_toml_value/1)
    "[" <> Enum.join(items, ", ") <> "]"
  end
  defp encode_toml_value(value), do: inspect(value)
end
