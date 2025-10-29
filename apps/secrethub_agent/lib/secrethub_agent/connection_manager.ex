defmodule SecretHub.Agent.ConnectionManager do
  @moduledoc """
  Enhanced connection manager with multi-endpoint failover support.

  Wraps the Connection module and integrates with EndpointManager
  to provide automatic failover between multiple Core endpoints.

  ## Features

  - Automatic failover to healthy endpoints
  - Connection health monitoring
  - Exponential backoff on failures
  - Transparent reconnection
  - Load balancing across healthy endpoints

  ## Usage

      # Start with multiple endpoints
      {:ok, pid} = ConnectionManager.start_link(
        agent_id: "agent-01",
        core_endpoints: [
          "wss://secrethub-core-0.secrethub.svc.cluster.local:4000",
          "wss://secrethub-core-1.secrethub.svc.cluster.local:4000",
          "wss://secrethub-core-2.secrethub.svc.cluster.local:4000"
        ]
      )

      # Use same API as Connection module
      {:ok, secret} = ConnectionManager.get_static_secret("prod.db.password")
  """

  use GenServer
  require Logger

  alias SecretHub.Agent.{Connection, EndpointManager}

  defstruct [
    :agent_id,
    :connection_pid,
    :current_endpoint,
    :cert_path,
    :key_path,
    :ca_path,
    :reconnect_attempts,
    :max_reconnect_attempts
  ]

  @max_reconnect_attempts 3

  ## Client API

  @doc """
  Starts the ConnectionManager.

  ## Options

    * `:agent_id` - Agent identifier (required)
    * `:core_endpoints` - List of Core URLs (required)
    * `:cert_path` - Path to agent certificate (optional)
    * `:key_path` - Path to agent private key (optional)
    * `:ca_path` - Path to CA certificate (optional)
  """
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Request a static secret (delegates to Connection).
  """
  def get_static_secret(path, timeout \\ 5000) do
    GenServer.call(
      __MODULE__,
      {:call_connection, :get_static_secret, [path, timeout]},
      timeout + 1000
    )
  end

  @doc """
  Request dynamic credentials (delegates to Connection).
  """
  def get_dynamic_secret(role, ttl, timeout \\ 5000) do
    GenServer.call(
      __MODULE__,
      {:call_connection, :get_dynamic_secret, [role, ttl, timeout]},
      timeout + 1000
    )
  end

  @doc """
  Renew a lease (delegates to Connection).
  """
  def renew_lease(lease_id, timeout \\ 5000) do
    GenServer.call(
      __MODULE__,
      {:call_connection, :renew_lease, [lease_id, timeout]},
      timeout + 1000
    )
  end

  @doc """
  Get connection status.
  """
  def status do
    GenServer.call(__MODULE__, :status)
  end

  ## GenServer Callbacks

  @impl true
  def init(opts) do
    agent_id = Keyword.fetch!(opts, :agent_id)
    cert_path = Keyword.get(opts, :cert_path)
    key_path = Keyword.get(opts, :key_path)
    ca_path = Keyword.get(opts, :ca_path)

    state = %__MODULE__{
      agent_id: agent_id,
      connection_pid: nil,
      current_endpoint: nil,
      cert_path: cert_path,
      key_path: key_path,
      ca_path: ca_path,
      reconnect_attempts: 0,
      max_reconnect_attempts: @max_reconnect_attempts
    }

    # Start initial connection
    send(self(), :connect)

    {:ok, state}
  end

  @impl true
  def handle_call({:call_connection, func, args}, _from, state) do
    if state.connection_pid do
      # Forward call to Connection GenServer
      try do
        result = apply(Connection, func, [state.connection_pid | args])
        {:reply, result, state}
      catch
        :exit, {:noproc, _} ->
          # Connection process died, trigger reconnect
          Logger.warning("Connection process died, reconnecting...")
          send(self(), :connect)
          {:reply, {:error, :connection_lost}, state}
      end
    else
      {:reply, {:error, :not_connected}, state}
    end
  end

  @impl true
  def handle_call(:status, _from, state) do
    status =
      if state.connection_pid && Process.alive?(state.connection_pid) do
        Connection.status(state.connection_pid)
      else
        :disconnected
      end

    {:reply, status, state}
  end

  @impl true
  def handle_info(:connect, state) do
    case EndpointManager.get_next_endpoint() do
      {:ok, endpoint} ->
        Logger.info("Attempting connection to #{endpoint}")

        connection_opts = [
          agent_id: state.agent_id,
          core_url: endpoint,
          cert_path: state.cert_path,
          key_path: state.key_path,
          ca_path: state.ca_path
        ]

        case Connection.start_link(connection_opts) do
          {:ok, pid} ->
            # Monitor the connection process
            Process.monitor(pid)

            # Report success to endpoint manager
            EndpointManager.report_success(endpoint)

            Logger.info("Connected to #{endpoint}")

            {:noreply,
             %{
               state
               | connection_pid: pid,
                 current_endpoint: endpoint,
                 reconnect_attempts: 0
             }}

          {:error, reason} ->
            Logger.error("Failed to connect to #{endpoint}: #{inspect(reason)}")

            # Report failure to endpoint manager
            EndpointManager.report_failure(endpoint)

            # Schedule retry
            schedule_reconnect(state)

            {:noreply, %{state | reconnect_attempts: state.reconnect_attempts + 1}}
        end

      {:error, :no_healthy_endpoints} ->
        Logger.error("No healthy endpoints available, will retry...")

        schedule_reconnect(state)

        {:noreply, %{state | reconnect_attempts: state.reconnect_attempts + 1}}
    end
  end

  @impl true
  def handle_info(:reconnect, state) do
    Logger.info(
      "Reconnecting to Core (attempt #{state.reconnect_attempts + 1}/#{state.max_reconnect_attempts})"
    )

    send(self(), :connect)
    {:noreply, state}
  end

  @impl true
  def handle_info({:DOWN, _ref, :process, pid, reason}, state) when pid == state.connection_pid do
    Logger.warning("Connection process died: #{inspect(reason)}")

    # Report failure for current endpoint
    if state.current_endpoint do
      EndpointManager.report_failure(state.current_endpoint)
    end

    # Trigger reconnection with different endpoint
    send(self(), :connect)

    {:noreply, %{state | connection_pid: nil, current_endpoint: nil}}
  end

  ## Private Functions

  defp schedule_reconnect(state) do
    # Exponential backoff: 1s, 2s, 4s, 8s, max 60s
    delay = min(:math.pow(2, state.reconnect_attempts) * 1000, 60_000) |> round()

    Logger.debug("Scheduling reconnect in #{delay}ms")
    Process.send_after(self(), :reconnect, delay)
  end
end
