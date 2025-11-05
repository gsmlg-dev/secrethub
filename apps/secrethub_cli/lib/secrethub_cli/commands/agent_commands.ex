defmodule SecretHub.CLI.Commands.AgentCommands do
  @moduledoc """
  Agent management command implementations.
  """

  alias SecretHub.CLI.{Auth, Config, Output}

  @doc """
  Executes agent commands.
  """
  def execute(:list, _args, opts) do
    with {:ok, _token} <- Auth.ensure_authenticated(),
         {:ok, agents} <- list_agents(opts) do
      format = Keyword.get(opts, :format, Config.get_output_format())
      Output.format(agents, format: format)
    end
  end

  def execute(:status, id, _args, opts) do
    with {:ok, _token} <- Auth.ensure_authenticated(),
         {:ok, status} <- get_agent_status(id, opts) do
      format = Keyword.get(opts, :format, Config.get_output_format())
      Output.format(status, format: format)
    end
  end

  def execute(:logs, id, _args, opts) do
    with {:ok, _token} <- Auth.ensure_authenticated() do
      stream_agent_logs(id, opts)
    end
  end

  ## Private API Functions

  defp list_agents(_opts) do
    server = Config.get_server_url()
    url = "#{server}/admin/api/dashboard/agents"
    headers = Auth.auth_headers()

    case Req.get(url, headers: headers) do
      {:ok, %{status: 200, body: body}} ->
        agents = Map.get(body, "agents", [])
        {:ok, agents}

      {:ok, %{status: status, body: body}} ->
        {:error, "API error #{status}: #{inspect(body)}"}

      {:error, reason} ->
        {:error, "HTTP request failed: #{inspect(reason)}"}
    end
  end

  defp get_agent_status(id, _opts) do
    server = Config.get_server_url()
    url = "#{server}/admin/api/agents/#{id}"
    headers = Auth.auth_headers()

    case Req.get(url, headers: headers) do
      {:ok, %{status: 200, body: body}} ->
        {:ok, Map.get(body, "data", %{})}

      {:ok, %{status: 404}} ->
        {:error, "Agent not found: #{id}"}

      {:ok, %{status: status, body: body}} ->
        {:error, "API error #{status}: #{inspect(body)}"}

      {:error, reason} ->
        {:error, "HTTP request failed: #{inspect(reason)}"}
    end
  end

  defp stream_agent_logs(id, opts) do
    server = Config.get_server_url()
    # WebSocket URL for log streaming
    ws_url = server |> String.replace("http://", "ws://") |> String.replace("https://", "wss://")
    url = "#{ws_url}/admin/agents/#{id}/logs"

    Output.info("Streaming logs for agent #{id}... (Ctrl+C to stop)")
    Output.info("Note: Log streaming requires WebSocket support")

    # For now, just poll the logs endpoint
    poll_logs(id, opts)
  end

  defp poll_logs(id, _opts) do
    server = Config.get_server_url()
    url = "#{server}/admin/api/agents/#{id}/logs"
    headers = Auth.auth_headers()

    case Req.get(url, headers: headers) do
      {:ok, %{status: 200, body: body}} ->
        logs = Map.get(body, "logs", [])

        Enum.each(logs, fn log ->
          timestamp = Map.get(log, "timestamp", "")
          level = Map.get(log, "level", "info")
          message = Map.get(log, "message", "")
          IO.puts("[#{timestamp}] [#{level}] #{message}")
        end)

        {:ok, "Logs retrieved"}

      {:ok, %{status: 404}} ->
        {:error, "Agent not found: #{id}"}

      {:ok, %{status: status, body: body}} ->
        {:error, "API error #{status}: #{inspect(body)}"}

      {:error, reason} ->
        {:error, "HTTP request failed: #{inspect(reason)}"}
    end
  end
end
