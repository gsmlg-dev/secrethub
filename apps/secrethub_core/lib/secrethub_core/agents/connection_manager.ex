defmodule SecretHub.Core.Agents.ConnectionManager do
  @moduledoc """
  Runtime registry for trusted Agent WebSocket connections.
  """

  use GenServer

  defstruct [
    :agent_id,
    :cert_serial,
    :socket_pid,
    :metadata,
    :connected_at,
    :last_seen_at
  ]

  def start_link(opts \\ []) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  def register_connection(agent_id, cert_serial, socket_pid, metadata) do
    register_connection(__MODULE__, agent_id, cert_serial, socket_pid, metadata)
  end

  def register_connection(server, agent_id, cert_serial, socket_pid, metadata) do
    GenServer.call(server, {:register, agent_id, cert_serial, socket_pid, metadata})
  end

  def unregister_connection(agent_id, reason \\ :normal) do
    unregister_connection(__MODULE__, agent_id, reason)
  end

  def unregister_connection(server, agent_id, reason) do
    GenServer.call(server, {:unregister, agent_id, reason})
  end

  def heartbeat(agent_id), do: heartbeat(__MODULE__, agent_id)
  def heartbeat(server, agent_id), do: GenServer.call(server, {:heartbeat, agent_id})

  def get_connection(agent_id), do: get_connection(__MODULE__, agent_id)
  def get_connection(server, agent_id), do: GenServer.call(server, {:get, agent_id})

  def list_connections, do: list_connections(__MODULE__)
  def list_connections(server), do: GenServer.call(server, :list)

  def connected?(agent_id), do: connected?(__MODULE__, agent_id)
  def connected?(server, agent_id), do: GenServer.call(server, {:connected?, agent_id})

  def send_to_agent(agent_id, message), do: send_to_agent(__MODULE__, agent_id, message)

  def send_to_agent(server, agent_id, message) do
    GenServer.call(server, {:send_to_agent, agent_id, message})
  end

  def disconnect_agent(agent_id, reason), do: disconnect_agent(__MODULE__, agent_id, reason)

  def disconnect_agent(server, agent_id, reason) do
    GenServer.call(server, {:disconnect, agent_id, reason})
  end

  @impl true
  def init(_opts) do
    {:ok, %{connections: %{}, monitors: %{}, refs_by_agent: %{}}}
  end

  @impl true
  def handle_call({:register, agent_id, cert_serial, socket_pid, metadata}, _from, state) do
    state = close_existing(state, agent_id, :replaced)
    monitor_ref = Process.monitor(socket_pid)
    now = now()

    connection = %__MODULE__{
      agent_id: agent_id,
      cert_serial: cert_serial,
      socket_pid: socket_pid,
      metadata: normalize_metadata(metadata),
      connected_at: now,
      last_seen_at: now
    }

    state = %{
      connections: Map.put(state.connections, agent_id, connection),
      monitors: Map.put(state.monitors, monitor_ref, {agent_id, socket_pid}),
      refs_by_agent: Map.put(state.refs_by_agent, agent_id, monitor_ref)
    }

    {:reply, :ok, state}
  end

  def handle_call({:unregister, agent_id, _reason}, _from, state) do
    {:reply, :ok, remove_connection(state, agent_id)}
  end

  def handle_call({:heartbeat, agent_id}, _from, state) do
    case Map.fetch(state.connections, agent_id) do
      {:ok, connection} ->
        updated = %{connection | last_seen_at: now()}
        {:reply, :ok, %{state | connections: Map.put(state.connections, agent_id, updated)}}

      :error ->
        {:reply, {:error, :not_connected}, state}
    end
  end

  def handle_call({:get, agent_id}, _from, state) do
    case Map.fetch(state.connections, agent_id) do
      {:ok, connection} -> {:reply, {:ok, connection}, state}
      :error -> {:reply, {:error, :not_connected}, state}
    end
  end

  def handle_call(:list, _from, state) do
    {:reply, Map.values(state.connections), state}
  end

  def handle_call({:connected?, agent_id}, _from, state) do
    {:reply, Map.has_key?(state.connections, agent_id), state}
  end

  def handle_call({:send_to_agent, agent_id, message}, _from, state) do
    case Map.fetch(state.connections, agent_id) do
      {:ok, connection} ->
        send(connection.socket_pid, {:secrethub_agent_message, message})
        {:reply, :ok, state}

      :error ->
        {:reply, {:error, :not_connected}, state}
    end
  end

  def handle_call({:disconnect, agent_id, reason}, _from, state) do
    state =
      case Map.fetch(state.connections, agent_id) do
        {:ok, connection} ->
          send(connection.socket_pid, {:secrethub_agent_disconnect, reason})
          remove_connection(state, agent_id)

        :error ->
          state
      end

    {:reply, :ok, state}
  end

  @impl true
  def handle_info({:DOWN, ref, :process, _pid, _reason}, state) do
    case Map.pop(state.monitors, ref) do
      {nil, monitors} ->
        {:noreply, %{state | monitors: monitors}}

      {{agent_id, pid}, monitors} ->
        connections =
          case Map.fetch(state.connections, agent_id) do
            {:ok, %{socket_pid: ^pid}} -> Map.delete(state.connections, agent_id)
            _ -> state.connections
          end

        refs_by_agent =
          case Map.get(state.refs_by_agent, agent_id) do
            ^ref -> Map.delete(state.refs_by_agent, agent_id)
            _ -> state.refs_by_agent
          end

        {:noreply,
         %{state | monitors: monitors, connections: connections, refs_by_agent: refs_by_agent}}
    end
  end

  defp close_existing(state, agent_id, reason) do
    case Map.fetch(state.connections, agent_id) do
      {:ok, %{socket_pid: pid}} when pid != self() ->
        send(pid, {:secrethub_agent_disconnect, reason})
        Process.exit(pid, :kill)
        remove_connection(state, agent_id)

      {:ok, _connection} ->
        remove_connection(state, agent_id)

      :error ->
        state
    end
  end

  defp remove_connection(state, agent_id) do
    {ref, refs_by_agent} = Map.pop(state.refs_by_agent, agent_id)
    monitors = if ref, do: Map.delete(state.monitors, ref), else: state.monitors
    if ref, do: Process.demonitor(ref, [:flush])

    %{
      state
      | connections: Map.delete(state.connections, agent_id),
        monitors: monitors,
        refs_by_agent: refs_by_agent
    }
  end

  defp normalize_metadata(metadata) when is_map(metadata), do: metadata
  defp normalize_metadata(_), do: %{}

  defp now, do: DateTime.utc_now() |> DateTime.truncate(:second)
end
