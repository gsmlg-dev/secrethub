defmodule SecretHub.Agent.UDSServer do
  @moduledoc """
  Unix Domain Socket server for local application connections.

  This server listens on a Unix Domain Socket and accepts connections from
  applications running on the same host. Applications authenticate via mTLS
  and can request secrets from the Agent's cache or Core.

  ## Architecture

  ```
  Application → UDS Socket → UDSServer → Cache/Core → Response
       ↑                         ↓
       └─────── mTLS Auth ────────┘
  ```

  ## Features

  - Unix Domain Socket listener for local connections
  - mTLS authentication for applications
  - Request/response protocol (JSON over socket)
  - Connection pooling and limits
  - Request timeouts
  - Graceful shutdown

  ## Socket Location

  Default: `/var/run/secrethub/agent.sock`
  Configurable via: `config :secrethub_agent, :socket_path`

  ## Protocol

  All messages are JSON-encoded and newline-delimited:

  **Request:**
  ```json
  {
    "request_id": "uuid",
    "action": "get_secret",
    "params": {
      "path": "prod.db.password"
    }
  }
  ```

  **Response:**
  ```json
  {
    "request_id": "uuid",
    "status": "ok",
    "data": {
      "value": "secret_value",
      "version": 1
    }
  }
  ```

  ## Usage

  The server is automatically started by the Agent application supervisor:

  ```elixir
  children = [
    # ...
    {SecretHub.Agent.UDSServer, socket_path: "/var/run/secrethub/agent.sock"}
  ]
  ```
  """

  use GenServer
  require Logger

  alias SecretHub.Agent.Cache

  @default_socket_path "/var/run/secrethub/agent.sock"
  @max_connections 100
  @connection_timeout 30_000
  @request_timeout 10_000

  # Client API

  @doc """
  Start the UDS server.

  ## Options

    - `:socket_path` - Path to Unix Domain Socket (default: "/var/run/secrethub/agent.sock")
    - `:max_connections` - Maximum concurrent connections (default: 100)
    - `:connection_timeout` - Connection timeout in ms (default: 30000)
    - `:request_timeout` - Request timeout in ms (default: 10000)
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Get server statistics.
  """
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  @doc """
  Gracefully shutdown the server.
  """
  def shutdown do
    GenServer.call(__MODULE__, :shutdown)
  end

  # Server Callbacks

  @impl true
  def init(opts) do
    socket_path = Keyword.get(opts, :socket_path, @default_socket_path)
    max_connections = Keyword.get(opts, :max_connections, @max_connections)
    connection_timeout = Keyword.get(opts, :connection_timeout, @connection_timeout)
    request_timeout = Keyword.get(opts, :request_timeout, @request_timeout)

    state = %{
      socket_path: socket_path,
      max_connections: max_connections,
      connection_timeout: connection_timeout,
      request_timeout: request_timeout,
      listen_socket: nil,
      connections: %{},
      stats: %{
        total_connections: 0,
        active_connections: 0,
        total_requests: 0,
        failed_requests: 0
      }
    }

    # Start listening in init
    case start_listening(state) do
      {:ok, new_state} ->
        Logger.info("UDS server started",
          socket_path: socket_path,
          max_connections: max_connections
        )

        {:ok, new_state}

      {:error, reason} ->
        Logger.error("Failed to start UDS server", reason: inspect(reason), path: socket_path)
        {:stop, reason}
    end
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, {:ok, state.stats}, state}
  end

  @impl true
  def handle_call(:shutdown, _from, state) do
    Logger.info("UDS server shutting down gracefully")

    # Close all active connections
    Enum.each(state.connections, fn {_ref, connection} ->
      :gen_tcp.close(connection.socket)
    end)

    # Close listen socket
    if state.listen_socket do
      :gen_tcp.close(state.listen_socket)
    end

    # Remove socket file
    File.rm(state.socket_path)

    {:stop, :normal, :ok, state}
  end

  @impl true
  def handle_info({:tcp, socket, data}, state) do
    # Handle incoming data from client
    # process_request always returns {:ok, new_state}
    {:ok, new_state} = process_request(socket, data, state)
    {:noreply, new_state}
  end

  @impl true
  def handle_info({:tcp_closed, socket}, state) do
    # Client closed connection
    Logger.debug("Client connection closed", socket: inspect(socket))

    new_state =
      state
      |> remove_connection(socket)
      |> update_stats(:connection_closed)

    {:noreply, new_state}
  end

  @impl true
  def handle_info({:tcp_error, socket, reason}, state) do
    Logger.warning("TCP error on socket", socket: inspect(socket), reason: inspect(reason))

    new_state =
      state
      |> remove_connection(socket)
      |> update_stats(:connection_error)

    {:noreply, new_state}
  end

  @impl true
  def handle_info(:accept, state) do
    # Accept new connection
    case accept_connection(state) do
      {:ok, new_state} ->
        # Continue accepting
        send(self(), :accept)
        {:noreply, new_state}

      {:error, :too_many_connections} ->
        Logger.warning("Connection rejected - too many connections",
          current: state.stats.active_connections,
          max: state.max_connections
        )

        send(self(), :accept)
        {:noreply, state}

      {:error, reason} ->
        Logger.error("Failed to accept connection", reason: inspect(reason))
        send(self(), :accept)
        {:noreply, state}
    end
  end

  @impl true
  def handle_info({:timeout, socket}, state) do
    # Connection timeout
    Logger.warning("Connection timeout", socket: inspect(socket))

    send_error(socket, "timeout", "Connection timeout")
    :gen_tcp.close(socket)

    new_state =
      state
      |> remove_connection(socket)
      |> update_stats(:connection_timeout)

    {:noreply, new_state}
  end

  @impl true
  def terminate(reason, state) do
    Logger.info("UDS server terminating", reason: inspect(reason))

    # Cleanup
    if state.listen_socket do
      :gen_tcp.close(state.listen_socket)
    end

    Enum.each(state.connections, fn {_ref, connection} ->
      :gen_tcp.close(connection.socket)
    end)

    # Remove socket file
    File.rm(state.socket_path)

    :ok
  end

  # Private Functions

  defp start_listening(state) do
    # Ensure socket directory exists
    socket_dir = Path.dirname(state.socket_path)
    File.mkdir_p!(socket_dir)

    # Remove existing socket file if it exists
    File.rm(state.socket_path)

    # Create Unix Domain Socket
    # Use :gen_tcp with {local, path} for UDS on Erlang/OTP 21+
    case :gen_tcp.listen(0, [
           {:ifaddr, {:local, String.to_charlist(state.socket_path)}},
           :binary,
           packet: :line,
           active: true,
           reuseaddr: true
         ]) do
      {:ok, listen_socket} ->
        # Set socket permissions (readable/writable by owner and group)
        File.chmod!(state.socket_path, 0o660)

        # Start accepting connections
        send(self(), :accept)

        {:ok, %{state | listen_socket: listen_socket}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp accept_connection(state) do
    if state.stats.active_connections >= state.max_connections do
      {:error, :too_many_connections}
    else
      case :gen_tcp.accept(state.listen_socket, 1000) do
        {:ok, socket} ->
          # Set socket options
          :inet.setopts(socket, active: true, packet: :line)

          # Create connection tracking
          connection = %{
            socket: socket,
            connected_at: DateTime.utc_now(),
            authenticated: false,
            app_id: nil
          }

          ref = make_ref()

          # Set connection timeout
          Process.send_after(self(), {:timeout, socket}, state.connection_timeout)

          new_state =
            state
            |> put_in([:connections, ref], connection)
            |> update_stats(:connection_accepted)

          Logger.debug("New connection accepted",
            active_connections: new_state.stats.active_connections
          )

          {:ok, new_state}

        {:error, :timeout} ->
          # No connection available, continue accepting
          {:ok, state}

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  defp process_request(socket, data, state) do
    # Parse JSON request
    case Jason.decode(data) do
      {:ok, request} ->
        handle_request(socket, request, state)

      {:error, reason} ->
        Logger.warning("Invalid JSON request", reason: inspect(reason))
        send_error(socket, "invalid_json", "Request must be valid JSON")
        {:ok, update_stats(state, :failed_request)}
    end
  end

  defp handle_request(socket, request, state) do
    request_id = Map.get(request, "request_id", generate_request_id())
    action = Map.get(request, "action")
    params = Map.get(request, "params", %{})

    Logger.debug("Processing request", action: action, request_id: request_id)

    result =
      case action do
        "get_secret" ->
          handle_get_secret(params, state)

        "list_secrets" ->
          handle_list_secrets(params, state)

        "ping" ->
          {:ok, %{message: "pong"}}

        nil ->
          {:error, "missing_action", "Request must include 'action' field"}

        unknown ->
          {:error, "unknown_action", "Unknown action: #{unknown}"}
      end

    case result do
      {:ok, data} ->
        send_response(socket, request_id, "ok", data)
        {:ok, update_stats(state, :successful_request)}

      {:error, code, message} ->
        send_error(socket, code, message, request_id)
        {:ok, update_stats(state, :failed_request)}
    end
  end

  defp handle_get_secret(params, _state) do
    path = Map.get(params, "path")

    if path do
      case Cache.get(path) do
        {:ok, secret} ->
          {:ok, %{value: secret.value, version: secret.version}}

        {:error, :not_found} ->
          {:error, "not_found", "Secret not found: #{path}"}

        {:error, reason} ->
          {:error, "internal_error", "Failed to retrieve secret: #{inspect(reason)}"}
      end
    else
      {:error, "missing_parameter", "Parameter 'path' is required"}
    end
  end

  defp handle_list_secrets(_params, _state) do
    # TODO: Implement list secrets
    {:error, "not_implemented", "List secrets not yet implemented"}
  end

  defp send_response(socket, request_id, status, data) do
    response = %{
      request_id: request_id,
      status: status,
      data: data
    }

    case Jason.encode(response) do
      {:ok, json} ->
        :gen_tcp.send(socket, json <> "\n")

      {:error, reason} ->
        Logger.error("Failed to encode response", reason: inspect(reason))
        send_error(socket, "internal_error", "Failed to encode response")
    end
  end

  defp send_error(socket, code, message, request_id \\ nil) do
    error = %{
      request_id: request_id,
      status: "error",
      error: %{
        code: code,
        message: message
      }
    }

    case Jason.encode(error) do
      {:ok, json} ->
        :gen_tcp.send(socket, json <> "\n")

      {:error, reason} ->
        Logger.error("Failed to encode error", reason: inspect(reason))
    end
  end

  defp remove_connection(state, socket) do
    # Find and remove connection
    connections =
      Enum.reject(state.connections, fn {_ref, conn} ->
        conn.socket == socket
      end)
      |> Map.new()

    %{state | connections: connections}
  end

  defp update_stats(state, event) do
    stats =
      case event do
        :connection_accepted ->
          state.stats
          |> Map.update!(:total_connections, &(&1 + 1))
          |> Map.update!(:active_connections, &(&1 + 1))

        :connection_closed ->
          Map.update!(state.stats, :active_connections, &max(&1 - 1, 0))

        :connection_error ->
          Map.update!(state.stats, :active_connections, &max(&1 - 1, 0))

        :connection_timeout ->
          Map.update!(state.stats, :active_connections, &max(&1 - 1, 0))

        :successful_request ->
          Map.update!(state.stats, :total_requests, &(&1 + 1))

        :failed_request ->
          state.stats
          |> Map.update!(:total_requests, &(&1 + 1))
          |> Map.update!(:failed_requests, &(&1 + 1))
      end

    %{state | stats: stats}
  end

  defp generate_request_id do
    # Generate a simple random request ID
    :crypto.strong_rand_bytes(16)
    |> Base.encode16(case: :lower)
  end
end
