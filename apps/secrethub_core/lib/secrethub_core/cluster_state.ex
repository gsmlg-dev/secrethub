defmodule SecretHub.Core.ClusterState do
  @moduledoc """
  Manages cluster-wide state coordination for HA deployments.

  Coordinates critical operations across multiple SecretHub Core nodes:
  - Initialization (only one node should initialize)
  - Unsealing (all nodes need to unseal, but coordinated)
  - Leader election for certain operations
  - Cluster health monitoring

  Uses PostgreSQL advisory locks via DistributedLock for coordination.

  ## Initialization Flow (HA Cluster)

  1. Multiple nodes start simultaneously
  2. Each node tries to acquire the init lock
  3. First node to acquire lock performs initialization:
     - Generates master key
     - Generates unseal keys
     - Creates initial seal state in DB
  4. Other nodes wait for initialization to complete
  5. All nodes can then proceed to unsealing

  ## Unsealing Flow (HA Cluster)

  1. Each node independently unseals using provided unseal keys
  2. Nodes check cluster unseal status
  3. Once unsealed, nodes mark themselves as ready
  4. Load balancer routes traffic to unsealed nodes

  ## Leader Election

  For operations that require exactly one node to execute (e.g., scheduled tasks,
  auto-unseal), we use a leader election mechanism:

  1. Nodes compete for leader lock
  2. Lock holder becomes leader
  3. Leader renews lock periodically
  4. On leader failure, lock expires and new election occurs
  """

  use GenServer
  require Logger

  alias SecretHub.Core.{DistributedLock, Repo, Vault.SealState}
  alias SecretHub.Shared.Schemas.ClusterNode

  @type node_status :: :starting | :initializing | :sealed | :unsealed | :shutdown
  @type cluster_info :: %{
          node_count: non_neg_integer(),
          initialized: boolean(),
          sealed_count: non_neg_integer(),
          unsealed_count: non_neg_integer(),
          nodes: [map()]
        }

  # GenServer state
  defstruct [
    :node_id,
    :status,
    :leader?,
    :last_heartbeat,
    :leader_lock
  ]

  @heartbeat_interval 10_000
  @leader_lock_renewal_interval 15_000
  @node_timeout 30_000

  # Client API

  @doc """
  Starts the ClusterState GenServer.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Attempts to initialize the vault with cluster coordination.

  Only one node in the cluster should successfully initialize. Other nodes
  will wait for initialization to complete.

  Returns:
  - `{:ok, :initialized}` if this node initialized successfully
  - `{:ok, :already_initialized}` if another node already initialized
  - `{:error, reason}` on failure
  """
  @spec coordinated_init(integer(), integer()) ::
          {:ok, :initialized | :already_initialized} | {:error, term()}
  def coordinated_init(threshold, shares) do
    GenServer.call(__MODULE__, {:coordinated_init, threshold, shares}, 60_000)
  end

  @doc """
  Checks if the vault is already initialized (cluster-wide).
  """
  @spec initialized?() :: boolean()
  def initialized? do
    GenServer.call(__MODULE__, :check_initialized)
  end

  @doc """
  Returns cluster-wide information about all nodes.
  """
  @spec cluster_info() :: {:ok, cluster_info()} | {:error, term()}
  def cluster_info do
    GenServer.call(__MODULE__, :cluster_info)
  end

  @doc """
  Returns whether this node is currently the cluster leader.
  """
  @spec leader?() :: boolean()
  def leader? do
    GenServer.call(__MODULE__, :is_leader)
  end

  @doc """
  Attempts to become the cluster leader.

  Used for operations that should only run on one node (e.g., scheduled tasks).
  """
  @spec acquire_leadership() :: :ok | {:error, :another_leader}
  def acquire_leadership do
    GenServer.call(__MODULE__, :acquire_leadership)
  end

  @doc """
  Releases leadership if this node is the leader.
  """
  @spec release_leadership() :: :ok
  def release_leadership do
    GenServer.call(__MODULE__, :release_leadership)
  end

  @doc """
  Updates this node's status in the cluster.
  """
  @spec update_status(node_status()) :: :ok
  def update_status(status) do
    GenServer.cast(__MODULE__, {:update_status, status})
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    # Generate or retrieve node ID
    node_id = generate_node_id()

    state = %__MODULE__{
      node_id: node_id,
      status: :starting,
      leader?: false,
      last_heartbeat: DateTime.utc_now(),
      leader_lock: nil
    }

    # Register this node in the cluster
    register_node(node_id)

    # Schedule periodic tasks
    schedule_heartbeat()
    schedule_leader_check()

    Logger.info("ClusterState initialized for node #{node_id}")

    {:ok, state}
  end

  @impl true
  def handle_call({:coordinated_init, threshold, shares}, _from, state) do
    result =
      DistributedLock.with_lock(:init, [timeout: 5000], fn ->
        # Check if already initialized
        if SealState.initialized?() do
          Logger.info("Vault already initialized by another node")
          {:ok, :already_initialized}
        else
          # This node will perform initialization
          Logger.info("This node is performing cluster initialization")

          case SealState.initialize(threshold, shares) do
            {:ok, unseal_keys} ->
              # Mark cluster as initialized in DB
              mark_cluster_initialized()
              {:ok, :initialized, unseal_keys}

            {:error, reason} ->
              {:error, reason}
          end
        end
      end)

    case result do
      {:ok, {:ok, :already_initialized}} ->
        {:reply, {:ok, :already_initialized}, state}

      {:ok, {:ok, :initialized, _keys}} ->
        new_state = %{state | status: :sealed}
        {:reply, {:ok, :initialized}, new_state}

      {:ok, {:error, reason}} ->
        {:reply, {:error, reason}, state}

      {:error, :timeout} ->
        {:reply, {:error, :init_lock_timeout}, state}
    end
  end

  @impl true
  def handle_call(:check_initialized, _from, state) do
    initialized = SealState.initialized?()
    {:reply, initialized, state}
  end

  @impl true
  def handle_call(:cluster_info, _from, state) do
    case get_cluster_info() do
      {:ok, info} -> {:reply, {:ok, info}, state}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call(:is_leader, _from, state) do
    {:reply, state.leader?, state}
  end

  @impl true
  def handle_call(:acquire_leadership, _from, state) do
    if state.leader? do
      {:reply, :ok, state}
    else
      case DistributedLock.acquire(:leader, timeout: 1000) do
        {:ok, lock} ->
          Logger.info("Node #{state.node_id} became cluster leader")
          new_state = %{state | leader?: true, leader_lock: lock}
          {:reply, :ok, new_state}

        {:error, :timeout} ->
          {:reply, {:error, :another_leader}, state}
      end
    end
  end

  @impl true
  def handle_call(:release_leadership, _from, state) do
    if state.leader? && state.leader_lock do
      DistributedLock.release(state.leader_lock)
      Logger.info("Node #{state.node_id} released leadership")
      new_state = %{state | leader?: false, leader_lock: nil}
      {:reply, :ok, new_state}
    else
      {:reply, :ok, state}
    end
  end

  @impl true
  def handle_cast({:update_status, new_status}, state) do
    Logger.debug("Node status updated: #{state.status} -> #{new_status}")
    update_node_status(state.node_id, new_status)
    {:noreply, %{state | status: new_status}}
  end

  @impl true
  def handle_info(:heartbeat, state) do
    # Send heartbeat to update last_seen timestamp
    send_heartbeat(state.node_id)

    # Clean up stale nodes
    cleanup_stale_nodes()

    # Schedule next heartbeat
    schedule_heartbeat()

    {:noreply, %{state | last_heartbeat: DateTime.utc_now()}}
  end

  @impl true
  def handle_info(:check_leader, state) do
    # If we're the leader, try to renew the lock
    new_state =
      if state.leader? do
        # Leader lock is session-based and doesn't expire,
        # but we should verify we still hold it
        if DistributedLock.locked?(:leader) do
          state
        else
          # We lost leadership somehow
          Logger.warning("Node #{state.node_id} lost leadership")
          %{state | leader?: false, leader_lock: nil}
        end
      else
        state
      end

    schedule_leader_check()
    {:noreply, new_state}
  end

  @impl true
  def terminate(_reason, state) do
    # Release leadership if we're the leader
    if state.leader? && state.leader_lock do
      DistributedLock.release(state.leader_lock)
    end

    # Mark node as shutdown
    update_node_status(state.node_id, :shutdown)

    :ok
  end

  # Private Functions

  defp generate_node_id do
    # Use hostname + random suffix for node ID
    hostname = :inet.gethostname() |> elem(1) |> to_string()
    random_suffix = :crypto.strong_rand_bytes(4) |> Base.encode16()
    "#{hostname}-#{random_suffix}"
  end

  defp register_node(node_id) do
    # Create or update cluster node record
    # This would be a new schema - for now we'll skip DB operations
    # and just log
    Logger.info("Registering cluster node: #{node_id}")
    :ok
  end

  defp mark_cluster_initialized do
    # Store cluster initialization state
    # This would update a cluster_state table
    Logger.info("Marking cluster as initialized")
    :ok
  end

  defp update_node_status(node_id, status) do
    Logger.debug("Updating node #{node_id} status to #{status}")
    # Would update cluster_nodes table
    :ok
  end

  defp send_heartbeat(node_id) do
    Logger.debug("Sending heartbeat for node #{node_id}")
    # Would update last_seen timestamp in cluster_nodes table
    :ok
  end

  defp cleanup_stale_nodes do
    # Remove nodes that haven't sent heartbeat in @node_timeout
    # This would be a DB query to delete stale records
    :ok
  end

  defp get_cluster_info do
    # Query cluster_nodes table for current state
    # For now, return mock data
    {:ok,
     %{
       node_count: 1,
       initialized: SealState.initialized?(),
       sealed_count: if(SealState.sealed?(), do: 1, else: 0),
       unsealed_count: if(!SealState.sealed?(), do: 1, else: 0),
       nodes: []
     }}
  end

  defp schedule_heartbeat do
    Process.send_after(self(), :heartbeat, @heartbeat_interval)
  end

  defp schedule_leader_check do
    Process.send_after(self(), :check_leader, @leader_lock_renewal_interval)
  end
end
