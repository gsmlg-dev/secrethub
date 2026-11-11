defmodule SecretHub.SDK.Client do
  @moduledoc false
  # One request per connection over the Agent's JSON-lines socket protocol:
  # {"request_id", "action", "params"} -> {"request_id", "status", "data" | "error"}.

  alias SecretHub.SDK.Error

  @default_socket_path "/var/run/secrethub/agent.sock"
  @default_timeout 15_000
  # The Agent's frame limit; a smaller receive buffer would split long lines.
  @frame_limit 65_536

  def request(action, params, opts) do
    timeout = Keyword.get(opts, :timeout, @default_timeout)
    socket_path = Keyword.get_lazy(opts, :socket_path, &default_socket_path/0)

    case connect(socket_path, timeout) do
      {:ok, socket} ->
        try do
          exchange(socket, action, params, timeout)
        after
          :gen_tcp.close(socket)
        end

      {:error, _reason} ->
        {:error, Error.new(:agent_unavailable, "SecretHub Agent socket unavailable")}
    end
  end

  defp default_socket_path,
    do: System.get_env("SECRET_HUB_AGENT_SOCKET_PATH", @default_socket_path)

  defp connect(socket_path, timeout) do
    :gen_tcp.connect(
      {:local, to_charlist(socket_path)},
      0,
      [:binary, packet: :line, packet_size: @frame_limit, buffer: @frame_limit, active: false],
      timeout
    )
  end

  defp exchange(socket, action, params, timeout) do
    id = Base.encode16(:crypto.strong_rand_bytes(16), case: :lower)
    frame = Jason.encode!(%{request_id: id, action: action, params: params}) <> "\n"

    with :ok <- :gen_tcp.send(socket, frame),
         {:ok, line} <- :gen_tcp.recv(socket, 0, timeout),
         {:ok, %{"request_id" => ^id} = response} <- Jason.decode(line) do
      case response do
        %{"status" => "ok", "data" => data} when is_map(data) ->
          {:ok, data}

        %{"status" => "error", "error" => %{"code" => code}} when is_binary(code) ->
          {:error, Error.from_agent(code)}

        _ ->
          {:error, Error.new(:unknown, "Unrecognised SecretHub Agent response")}
      end
    else
      # The request may have reached the Agent; a mutation's outcome is unknown.
      _ when action in ["secret_put", "secret_delete"] ->
        {:error, Error.new(:unconfirmed, "No complete SecretHub Agent response")}

      _ ->
        {:error, Error.new(:agent_unavailable, "No complete SecretHub Agent response")}
    end
  end
end
