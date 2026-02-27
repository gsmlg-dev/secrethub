defmodule SecretHub.CLI.Commands.ConfigCommands do
  @moduledoc """
  Configuration management command implementations.
  """

  alias SecretHub.CLI.{Config, Output}

  @doc """
  Lists all configuration values.
  """
  def list(opts) do
    with {:ok, config} <- Config.load() do
      # Filter out sensitive auth data unless verbose
      config =
        if Keyword.get(opts, :verbose, false) do
          config
        else
          Map.delete(config, "auth")
        end

      format = Keyword.get(opts, :format, Config.get_output_format())
      Output.format(config, format: format)
    end
  end

  @doc """
  Gets a configuration value.
  """
  def get(key, opts) do
    with {:ok, value} <- Config.get(key) do
      if is_nil(value) do
        Output.warning("Configuration key not found: #{key}")
        {:ok, ""}
      else
        format = Keyword.get(opts, :format, "table")

        if format == "table" do
          IO.puts(format_value(value))
          {:ok, ""}
        else
          Output.format(%{key => value}, format: format)
        end
      end
    end
  end

  @doc """
  Sets a configuration value.
  """
  def set(key, value, _opts) do
    # Validate certain keys
    case validate_config_value(key, value) do
      :ok ->
        case Config.set(key, parse_value(value)) do
          :ok ->
            Output.success("Configuration updated: #{key} = #{value}")
            {:ok, "Configuration updated"}

          {:error, reason} ->
            Output.error("Failed to update configuration: #{inspect(reason)}")
            {:error, reason}
        end

      {:error, reason} ->
        Output.error("Invalid value for #{key}: #{reason}")
        {:error, reason}
    end
  end

  ## Private Functions

  defp format_value(value) when is_binary(value), do: value
  defp format_value(value) when is_number(value), do: to_string(value)
  defp format_value(value) when is_boolean(value), do: to_string(value)
  defp format_value(value) when is_map(value), do: Jason.encode!(value, pretty: true)
  defp format_value(value) when is_list(value), do: Enum.join(value, ", ")
  defp format_value(value), do: inspect(value)

  defp parse_value("true"), do: true
  defp parse_value("false"), do: false

  defp parse_value(value) when is_binary(value) do
    case Integer.parse(value) do
      {int, ""} -> int
      _ -> value
    end
  end

  defp parse_value(value), do: value

  defp validate_config_value("server_url", value) do
    if String.starts_with?(value, "http://") or String.starts_with?(value, "https://") do
      :ok
    else
      {:error, "Server URL must start with http:// or https://"}
    end
  end

  defp validate_config_value("output.format", value) do
    if value in ["json", "table", "yaml"] do
      :ok
    else
      {:error, "Format must be one of: json, table, yaml"}
    end
  end

  defp validate_config_value("output.color", value) do
    if value in ["true", "false", true, false] do
      :ok
    else
      {:error, "Color must be true or false"}
    end
  end

  defp validate_config_value(_key, _value), do: :ok
end
