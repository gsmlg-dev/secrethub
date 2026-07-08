defmodule SecretHub.CLI.Commands.SecretCommands do
  @moduledoc """
  Secret management command implementations.
  """

  alias SecretHub.CLI.{AgentClient, Auth, Config, Output}

  @doc """
  Executes secret commands.
  """
  def execute(:list, _path, opts) do
    with {:ok, _token} <- Auth.ensure_authenticated(),
         {:ok, secrets} <- list_secrets(opts) do
      format = Keyword.get(opts, :format, Config.get_output_format())
      Output.format(secrets, format: format)
    end
  end

  def execute(:get, path, _args, opts) do
    with {:ok, secret} <- get_secret_for_cli(path, opts) do
      format = Keyword.get(opts, :format, Config.get_output_format())
      Output.format(secret, format: format)
    end
  end

  def execute(:create, path, _args, opts) do
    value = Keyword.get(opts, :value)

    if is_nil(value) do
      {:error, "Missing required option: --value"}
    else
      with {:ok, _token} <- Auth.ensure_authenticated(),
           {:ok, _secret} <- create_secret(path, value, opts) do
        Output.success("Secret created: #{path}")
        {:ok, "Secret created"}
      end
    end
  end

  def execute(:update, path, _args, opts) do
    value = Keyword.get(opts, :value)

    if is_nil(value) do
      {:error, "Missing required option: --value"}
    else
      with {:ok, _token} <- Auth.ensure_authenticated(),
           {:ok, _secret} <- update_secret(path, value, opts) do
        Output.success("Secret updated: #{path}")
        {:ok, "Secret updated"}
      end
    end
  end

  def execute(:delete, path, _args, opts) do
    with {:ok, _token} <- Auth.ensure_authenticated(),
         :ok <- delete_secret(path, opts) do
      Output.success("Secret deleted: #{path}")
      {:ok, "Secret deleted"}
    end
  end

  def execute(:versions, path, _args, opts) do
    with {:ok, _token} <- Auth.ensure_authenticated(),
         {:ok, versions} <- list_versions(path, opts) do
      format = Keyword.get(opts, :format, Config.get_output_format())
      Output.format(versions, format: format)
    end
  end

  def execute(:rollback, path, version, _args, opts) do
    with {:ok, _token} <- Auth.ensure_authenticated(),
         {:ok, _secret} <- rollback_secret(path, version, opts) do
      Output.success("Secret rolled back to version #{version}")
      {:ok, "Rollback successful"}
    end
  end

  ## Private API Functions

  defp get_secret_for_cli(path, opts) do
    if agent_socket = Keyword.get(opts, :agent_socket) do
      AgentClient.get_secret(path,
        socket_path: agent_socket,
        certificate_path: Keyword.get(opts, :agent_cert)
      )
    else
      with {:ok, _token} <- Auth.ensure_authenticated() do
        get_secret(path, opts)
      end
    end
  end

  defp list_secrets(_opts) do
    server = Config.get_server_url()
    url = "#{server}/v1/secret/metadata?list=true"
    headers = Auth.vault_headers()

    case Req.get(url, headers: headers) do
      {:ok, %{status: 200, body: body}} ->
        secrets =
          body
          |> Map.get("keys", [])
          |> Enum.map(&%{"path" => &1})

        {:ok, secrets}

      {:ok, %{status: status, body: body}} ->
        {:error, "API error #{status}: #{inspect(body)}"}

      {:error, reason} ->
        {:error, "HTTP request failed: #{inspect(reason)}"}
    end
  end

  defp get_secret(path, _opts) do
    server = Config.get_server_url()
    url = "#{server}/v1/secret/data/#{vault_path(path)}"
    headers = Auth.vault_headers()

    case Req.get(url, headers: headers) do
      {:ok, %{status: 200, body: body}} ->
        {:ok, Map.get(body, "data", %{})}

      {:ok, %{status: 404}} ->
        {:error, "Secret not found: #{path}"}

      {:ok, %{status: status, body: body}} ->
        {:error, "API error #{status}: #{inspect(body)}"}

      {:error, reason} ->
        {:error, "HTTP request failed: #{inspect(reason)}"}
    end
  end

  defp create_secret(path, value, _opts) do
    server = Config.get_server_url()
    url = "#{server}/v1/secret/data/#{vault_path(path)}"
    headers = Auth.vault_headers() ++ [{"content-type", "application/json"}]

    body =
      Jason.encode!(%{
        data: %{value: value}
      })

    case Req.post(url, body: body, headers: headers) do
      {:ok, %{status: 200, body: body}} ->
        {:ok, body}

      {:ok, %{status: status, body: body}} ->
        {:error, "API error #{status}: #{inspect(body)}"}

      {:error, reason} ->
        {:error, "HTTP request failed: #{inspect(reason)}"}
    end
  end

  defp update_secret(path, value, _opts) do
    server = Config.get_server_url()
    url = "#{server}/v1/secret/data/#{vault_path(path)}"
    headers = Auth.vault_headers() ++ [{"content-type", "application/json"}]

    body =
      Jason.encode!(%{
        data: %{value: value}
      })

    case Req.post(url, body: body, headers: headers) do
      {:ok, %{status: 200, body: body}} ->
        {:ok, body}

      {:ok, %{status: status, body: body}} ->
        {:error, "API error #{status}: #{inspect(body)}"}

      {:error, reason} ->
        {:error, "HTTP request failed: #{inspect(reason)}"}
    end
  end

  defp delete_secret(path, _opts) do
    server = Config.get_server_url()
    url = "#{server}/v1/secret/data/#{vault_path(path)}"
    headers = Auth.vault_headers()

    case Req.delete(url, headers: headers) do
      {:ok, %{status: 204}} ->
        :ok

      {:ok, %{status: status, body: body}} ->
        {:error, "API error #{status}: #{inspect(body)}"}

      {:error, reason} ->
        {:error, "HTTP request failed: #{inspect(reason)}"}
    end
  end

  defp list_versions(path, _opts) do
    server = Config.get_server_url()
    url = "#{server}/v1/secret/metadata/#{vault_path(path)}"
    headers = Auth.vault_headers()

    case Req.get(url, headers: headers) do
      {:ok, %{status: 200, body: body}} ->
        versions = Map.get(body, "versions", %{})
        {:ok, versions}

      {:ok, %{status: status, body: body}} ->
        {:error, "API error #{status}: #{inspect(body)}"}

      {:error, reason} ->
        {:error, "HTTP request failed: #{inspect(reason)}"}
    end
  end

  defp rollback_secret(path, version, _opts) do
    server = Config.get_server_url()
    url = "#{server}/v1/secret/data/#{vault_path(path)}"
    headers = Auth.vault_headers() ++ [{"content-type", "application/json"}]

    body =
      Jason.encode!(%{
        version: version
      })

    case Req.post(url, body: body, headers: headers) do
      {:ok, %{status: 200, body: body}} ->
        {:ok, Map.get(body, "data", %{})}

      {:ok, %{status: status, body: body}} ->
        {:error, "API error #{status}: #{inspect(body)}"}

      {:error, reason} ->
        {:error, "HTTP request failed: #{inspect(reason)}"}
    end
  end

  defp vault_path(path) do
    path
    |> to_string()
    |> String.split("/")
    |> Enum.flat_map(&String.split(&1, "."))
    |> Enum.reject(&(&1 == ""))
    |> Enum.map_join("/", &URI.encode/1)
  end
end
