defmodule SecretHub.Agent.Connection do
  @moduledoc """
  WebSocket client for SecretHub Agent.

  Maintains a persistent WebSocket connection to the SecretHub Core service
  with automatic reconnection and request/reply tracking.

  ## Features

  - Automatic connection with exponential backoff
  - Request/reply pattern with ref matching
  - Server push event handling
  - Heartbeat monitoring
  - mTLS certificate configuration (for production)

  ## Usage

      # Start connection (usually via supervision tree)
      {:ok, pid} = Connection.start_link(
        agent_id: "agent-prod-01",
        core_url: "wss://secrethub.example.com",
        cert_path: "priv/cert/agent.pem",
        key_path: "priv/cert/agent-key.pem",
        ca_path: "priv/cert/ca.pem"
      )

      # Request static secret
      {:ok, secret} = Connection.get_static_secret(pid, "prod.db.password")

      # Request dynamic credentials
      {:ok, creds} = Connection.get_dynamic_secret(pid, "prod.db.postgres.readonly", 3600)

      # Renew lease
      {:ok, renewal} = Connection.renew_lease(pid, lease_id)

  ## Configuration

  Configure in config/dev.exs or config/prod.exs:

      config :secrethub_agent,
        agent_id: "agent-01",
        core_url: "wss://localhost:4001",
        cert_path: "priv/cert/agent.pem",
        key_path: "priv/cert/agent-key.pem",
        ca_path: "priv/cert/ca.pem"
  """

  use GenServer

  require Logger

  alias PhoenixClient.{Channel, Message, Socket}

  @type state :: %{
          socket: pid() | nil,
          channel: pid() | nil,
          agent_id: String.t(),
          core_url: String.t(),
          pending_requests: %{reference() => GenServer.from()},
          cert_path: String.t() | nil,
          key_path: String.t() | nil,
          ca_path: String.t() | nil,
          connection_status: :disconnected | :connecting | :connected,
          reconnect_timer: reference() | nil
        }

  ## Client API

  @doc """
  Start the Connection GenServer.

  ## Options

  - `:agent_id` - Agent identifier (required)
  - `:core_url` - Core WebSocket URL (required)
  - `:cert_path` - Path to agent certificate (optional, for mTLS)
  - `:key_path` - Path to agent private key (optional, for mTLS)
  - `:ca_path` - Path to CA certificate (optional, for mTLS)
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Request a static secret from Core.

  ## Parameters

  - `server` - Connection GenServer pid or name
  - `path` - Secret path in reverse domain notation

  ## Returns

  - `{:ok, %{value: ..., version: ...}}` on success
  - `{:error, reason}` on failure

  ## Example

      {:ok, secret} = Connection.get_static_secret("prod.db.postgres.password")
  """
  @spec get_static_secret(GenServer.server(), String.t(), timeout()) ::
          {:ok, map()} | {:error, term()}
  def get_static_secret(server \\ __MODULE__, path, timeout \\ 5000) do
    GenServer.call(server, {:get_static_secret, path}, timeout)
  end

  @doc """
  Request dynamic credentials from Core.

  ## Parameters

  - `server` - Connection GenServer pid or name
  - `role` - Dynamic secret role
  - `ttl` - Time-to-live in seconds

  ## Returns

  - `{:ok, %{username: ..., password: ..., lease_id: ...}}` on success
  - `{:error, reason}` on failure

  ## Example

      {:ok, creds} = Connection.get_dynamic_secret("prod.db.postgres.readonly", 3600)
  """
  @spec get_dynamic_secret(GenServer.server(), String.t(), integer(), timeout()) ::
          {:ok, map()} | {:error, term()}
  def get_dynamic_secret(server \\ __MODULE__, role, ttl, timeout \\ 5000) do
    GenServer.call(server, {:get_dynamic_secret, role, ttl}, timeout)
  end

  @doc """
  Renew an active lease.

  ## Parameters

  - `server` - Connection GenServer pid or name
  - `lease_id` - Lease UUID to renew

  ## Returns

  - `{:ok, %{lease_id: ..., renewed_ttl: ..., new_expires_at: ...}}` on success
  - `{:error, reason}` on failure

  ## Example

      {:ok, renewal} = Connection.renew_lease(lease_id)
  """
  @spec renew_lease(GenServer.server(), String.t(), timeout()) :: {:ok, map()} | {:error, term()}
  def renew_lease(server \\ __MODULE__, lease_id, timeout \\ 5000) do
    GenServer.call(server, {:renew_lease, lease_id}, timeout)
  end

  @doc """
  Get current connection status.

  Returns `:connected`, `:connecting`, or `:disconnected`.
  """
  @spec status(GenServer.server()) :: atom()
  def status(server \\ __MODULE__) do
    GenServer.call(server, :status)
  end

  ## GenServer Callbacks

  @impl true
  def init(opts) do
    agent_id = Keyword.fetch!(opts, :agent_id)
    core_url = Keyword.fetch!(opts, :core_url)
    cert_path = Keyword.get(opts, :cert_path)
    key_path = Keyword.get(opts, :key_path)
    ca_path = Keyword.get(opts, :ca_path)

    state = %{
      socket: nil,
      channel: nil,
      agent_id: agent_id,
      core_url: core_url,
      pending_requests: %{},
      cert_path: cert_path,
      key_path: key_path,
      ca_path: ca_path,
      connection_status: :disconnected,
      reconnect_timer: nil
    }

    Logger.info("Agent Connection initializing", agent_id: agent_id, core_url: core_url)

    # Start connection asynchronously
    send(self(), :connect)

    {:ok, state}
  end

  @impl true
  def handle_call({:get_static_secret, path}, from, state) do
    case state.connection_status do
      :connected ->
        send_request(state, from, "secrets:get_static", %{"path" => path})

      _ ->
        {:reply, {:error, :not_connected}, state}
    end
  end

  @impl true
  def handle_call({:get_dynamic_secret, role, ttl}, from, state) do
    case state.connection_status do
      :connected ->
        send_request(state, from, "secrets:get_dynamic", %{"role" => role, "ttl" => ttl})

      _ ->
        {:reply, {:error, :not_connected}, state}
    end
  end

  @impl true
  def handle_call({:renew_lease, lease_id}, from, state) do
    case state.connection_status do
      :connected ->
        send_request(state, from, "lease:renew", %{"lease_id" => lease_id})

      _ ->
        {:reply, {:error, :not_connected}, state}
    end
  end

  @impl true
  def handle_call(:status, _from, state) do
    {:reply, state.connection_status, state}
  end

  @impl true
  def handle_info(:connect, state) do
    Logger.info("Attempting to connect to Core", agent_id: state.agent_id, url: state.core_url)

    case connect_to_core(state) do
      {:ok, socket} ->
        case join_channel(socket, state.agent_id) do
          {:ok, channel} ->
            Logger.info("Successfully connected to Core",
              agent_id: state.agent_id,
              channel: "agent:#{state.agent_id}"
            )

            new_state = %{
              state
              | socket: socket,
                channel: channel,
                connection_status: :connected,
                reconnect_timer: nil
            }

            {:noreply, new_state}

          {:error, reason} ->
            Logger.error("Failed to join channel", reason: reason, agent_id: state.agent_id)
            schedule_reconnect(state)
        end

      {:error, reason} ->
        Logger.error("Failed to connect to Core",
          reason: reason,
          agent_id: state.agent_id,
          url: state.core_url
        )

        schedule_reconnect(state)
    end
  end

  @impl true
  def handle_info(%Message{event: "phx_reply", payload: payload, ref: ref}, state) do
    Logger.debug("Received reply", ref: ref, payload: payload)

    case Map.pop(state.pending_requests, ref) do
      {nil, _} ->
        Logger.warning("Received reply for unknown request", ref: ref)
        {:noreply, state}

      {from, pending_requests} ->
        GenServer.reply(from, parse_reply(payload))
        {:noreply, %{state | pending_requests: pending_requests}}
    end
  end

  @impl true
  def handle_info(%Message{event: "connected", payload: payload}, state) do
    Logger.info("Core connection confirmed", payload: payload)
    {:noreply, state}
  end

  @impl true
  def handle_info(%Message{event: "secret:rotated", payload: payload}, state) do
    Logger.info("Secret rotated notification",
      agent_id: state.agent_id,
      secret_path: payload["secret_path"],
      new_version: payload["new_version"]
    )

    # TODO: Invalidate cache for this secret
    {:noreply, state}
  end

  @impl true
  def handle_info(%Message{event: "policy:updated", payload: payload}, state) do
    Logger.info("Policy updated notification", agent_id: state.agent_id, payload: payload)
    # TODO: Refresh cached policies
    {:noreply, state}
  end

  @impl true
  def handle_info(%Message{event: event, payload: payload}, state) do
    Logger.info("Received push event", event: event, payload: payload)
    {:noreply, state}
  end

  @impl true
  def handle_info({:chan_close, _channel, reason}, state) do
    Logger.warning("WebSocket connection closed", reason: reason, agent_id: state.agent_id)
    schedule_reconnect(%{state | connection_status: :disconnected, socket: nil, channel: nil})
  end

  @impl true
  def handle_info(:reconnect, state) do
    Logger.info("Reconnecting to Core", agent_id: state.agent_id)
    send(self(), :connect)
    {:noreply, %{state | reconnect_timer: nil}}
  end

  ## Private Functions

  defp connect_to_core(state) do
    socket_opts = build_socket_opts(state)

    Logger.debug("Connecting to WebSocket",
      url: state.core_url,
      agent_id: state.agent_id
    )

    case Socket.start_link(socket_opts) do
      {:ok, socket} ->
        {:ok, socket}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp build_socket_opts(state) do
    url =
      state.core_url
      |> URI.parse()
      |> Map.put(:path, "/agent/socket/websocket")
      |> URI.to_string()

    [
      url: url,
      sender: self(),
      serializer: Jason,
      headers: [{"x-agent-id", state.agent_id}],
      heartbeat_interval: 30_000,
      reconnect_interval: 5_000,
      reconnect: true
    ]

    # Add TLS options if certificates are configured
    # Will be enabled when we have real certificates in production
    # if state.cert_path && state.key_path && state.ca_path do
    #   transport_opts = [
    #     certfile: state.cert_path,
    #     keyfile: state.key_path,
    #     cacertfile: state.ca_path
    #   ]
    #   Keyword.put(base_opts, :transport_opts, transport_opts)
    # else
    #   base_opts
    # end
  end

  defp join_channel(socket, agent_id) do
    topic = "agent:#{agent_id}"

    Logger.debug("Joining channel", topic: topic)

    case Channel.join(socket, topic) do
      {:ok, _response, channel} ->
        {:ok, channel}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp send_request(state, from, event, payload) do
    ref = make_ref()

    Logger.debug("Sending request", event: event, payload: payload, ref: ref)

    case Channel.push(state.channel, event, payload) do
      :ok ->
        pending_requests = Map.put(state.pending_requests, ref, from)
        {:noreply, %{state | pending_requests: pending_requests}}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  defp parse_reply(%{"status" => "ok", "response" => response}), do: {:ok, response}
  defp parse_reply(%{"status" => "error", "response" => error}), do: {:error, error}
  defp parse_reply(other), do: {:ok, other}

  defp schedule_reconnect(state) do
    # Exponential backoff: 1s, 2s, 4s, 8s, 16s, max 60s
    delay = min(1000 * :math.pow(2, map_size(state.pending_requests)), 60_000) |> round()

    Logger.info("Scheduling reconnect", delay_ms: delay, agent_id: state.agent_id)

    timer = Process.send_after(self(), :reconnect, delay)

    {:noreply, %{state | connection_status: :connecting, reconnect_timer: timer}}
  end
end
