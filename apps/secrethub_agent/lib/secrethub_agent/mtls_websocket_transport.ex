defmodule SecretHub.Agent.MTLSWebSocketTransport do
  @moduledoc """
  WebSocket transport that forwards mTLS options to `:websocket_client`.

  `phoenix_socket_client`'s default transport passes only headers to
  `:websocket_client.start_link/4`. The Erlang client expects TLS settings in
  `:socket_opts` and verification mode in `:ssl_verify`.
  """

  @behaviour Phoenix.SocketClient.Transport

  require Logger

  @impl true
  def open(url, transport_opts) do
    headers = Keyword.get(transport_opts, :headers, [])
    extra_headers = Keyword.get(transport_opts, :extra_headers, [])

    websocket_opts =
      transport_opts
      |> Keyword.take([:keepalive, :ssl_verify, :socket_opts])
      |> Keyword.put(:extra_headers, normalize_headers(extra_headers ++ headers))

    :websocket_client.start_link(
      String.to_charlist(url),
      __MODULE__,
      transport_opts,
      websocket_opts
    )
  end

  @impl true
  def close(socket) do
    send(socket, :close)
  end

  def init(opts) do
    {:once,
     %{
       opts: opts,
       sender: opts[:sender]
     }}
  end

  def onconnect(_websocket_req, state) do
    send(state.sender, {:connected, self()})
    {:ok, state}
  end

  def ondisconnect(reason, state) do
    send(state.sender, {:disconnected, reason, self()})
    {:close, :normal, state}
  end

  def websocket_handle({:text, msg}, _conn_state, state) do
    send(state.sender, {:receive, msg})
    {:ok, state}
  end

  def websocket_handle({:pong, _msg}, _conn_state, state), do: {:ok, state}

  def websocket_handle(other_msg, _req, state) do
    Logger.warning(fn -> "Unknown message #{inspect(other_msg)}" end)
    {:ok, state}
  end

  def websocket_info({:send, msg}, _conn_state, state) do
    {:reply, {:text, msg}, state}
  end

  def websocket_info(:close, _conn_state, state) do
    send(state.sender, {:closed, :normal, self()})
    {:close, <<>>, "done"}
  end

  def websocket_info(_message, _req, state), do: {:ok, state}

  def websocket_terminate(_reason, _conn_state, _state), do: :ok

  defp normalize_headers(headers) do
    Enum.map(headers, fn {key, value} -> {to_charlist(key), to_charlist(value)} end)
  end
end
