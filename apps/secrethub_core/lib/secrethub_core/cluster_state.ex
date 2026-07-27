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

  alias SecretHub.Core.{DistributedLock, NodeHealthCollector, Repo, Vault.SealState}
  alias SecretHub.Shared.Schemas.{ClusterNode, NodeHealthMetric}
  import Ecto.Query

  @node_statuses [:starting, :initializing, :sealed, :unsealed, :shutdown]
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
    :incarnation_id,
    :status,
    :leader?,
    :last_heartbeat,
    :leader_lock
  ]

  @heartbeat_interval 10_000
  @leader_lock_renewal_interval 15_000
  @code_capabilities %{"upgrade_gates" => 1}
  @minimum_freshness_timeout_seconds 1
  @maximum_freshness_timeout_seconds 300

  # Client API

  @doc """
  Starts the ClusterState GenServer.
  """
  def start_link(opts \\ []) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
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
  Returns the configured heartbeat freshness window used for cluster evidence.

  The bounded window is shared by cluster status reporting and destructive
  upgrade capability checks.
  """
  @spec freshness_timeout_seconds() :: pos_integer()
  def freshness_timeout_seconds do
    timeout =
      Application.get_env(
        :secrethub_core,
        :cluster_node_freshness_timeout_seconds,
        30
      )

    if is_integer(timeout) and
         timeout in @minimum_freshness_timeout_seconds..@maximum_freshness_timeout_seconds do
      timeout
    else
      raise ArgumentError,
            ":cluster_node_freshness_timeout_seconds must be an integer between " <>
              "#{@minimum_freshness_timeout_seconds} and " <>
              "#{@maximum_freshness_timeout_seconds}"
    end
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
  @spec update_status(term()) :: :ok | {:error, :invalid_status}
  def update_status(status) when status in @node_statuses do
    GenServer.cast(__MODULE__, {:update_status, status})
  end

  def update_status(_status), do: {:error, :invalid_status}

  @doc """
  Retrieves health history for a specific node.

  Returns health metrics for the specified duration.
  Duration can be specified in hours (e.g., 1 for last hour, 24 for last day).
  """
  @spec get_node_health_history(String.t(), pos_integer()) ::
          {:ok, [NodeHealthMetric.t()]} | {:error, term()}
  def get_node_health_history(node_id, hours \\ 1) do
    GenServer.call(__MODULE__, {:get_node_health_history, node_id, hours})
  end

  @doc """
  Retrieves the most recent health metrics for a specific node.
  """
  @spec get_node_current_health(String.t()) :: {:ok, NodeHealthMetric.t()} | {:error, term()}
  def get_node_current_health(node_id) do
    GenServer.call(__MODULE__, {:get_node_current_health, node_id})
  end

  # Server Callbacks

  @impl true
  def init(opts) do
    node_id = node_id!(opts)
    incarnation_id = Ecto.UUID.generate()

    state = %__MODULE__{
      node_id: node_id,
      incarnation_id: incarnation_id,
      status: :starting,
      leader?: false,
      last_heartbeat: DateTime.utc_now() |> DateTime.truncate(:second),
      leader_lock: nil
    }

    case register_node(node_id, incarnation_id, Keyword.get(opts, :metadata, %{})) do
      {:ok, _node} ->
        schedule_heartbeat()
        schedule_leader_check()

        Logger.info("ClusterState initialized for node #{node_id} incarnation #{incarnation_id}")

        {:ok, state}

      {:error, reason} ->
        {:stop, {:node_registration_failed, reason}}
    end
  end

  @impl true
  def handle_call({:coordinated_init, threshold, shares}, _from, state) do
    result =
      DistributedLock.with_lock(:init, [timeout: 5000], fn ->
        perform_coordinated_init(threshold, shares)
      end)

    handle_coordinated_init_result(result, state)
  end

  @impl true
  def handle_call(:check_initialized, _from, state) do
    initialized = SealState.initialized?()
    {:reply, initialized, state}
  end

  @impl true
  def handle_call(:cluster_info, _from, state) do
    {:ok, info} = get_cluster_info()
    {:reply, {:ok, info}, state}
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
  def handle_call({:get_node_health_history, node_id, hours}, _from, state) do
    case get_health_history(node_id, hours) do
      {:ok, metrics} -> {:reply, {:ok, metrics}, state}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:get_node_current_health, node_id}, _from, state) do
    case get_current_health(node_id) do
      {:ok, metric} -> {:reply, {:ok, metric}, state}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_cast({:update_status, new_status}, state) when new_status in @node_statuses do
    Logger.debug("Node status updated: #{state.status} -> #{new_status}")
    update_node_status(state.node_id, state.incarnation_id, new_status)
    {:noreply, %{state | status: new_status}}
  end

  def handle_cast({:update_status, invalid_status}, state) do
    Logger.warning("Ignoring invalid cluster node status: #{inspect(invalid_status)}")
    {:noreply, state}
  end

  @impl true
  def handle_info(:heartbeat, state) do
    if send_heartbeat(state.node_id, state.incarnation_id) == :ok do
      collect_and_store_health_metrics(state.node_id)
    end

    # Schedule next heartbeat
    schedule_heartbeat()

    {:noreply, %{state | last_heartbeat: DateTime.utc_now() |> DateTime.truncate(:second)}}
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
    update_node_status(state.node_id, state.incarnation_id, :shutdown)

    :ok
  end

  # Private Functions

  defp perform_coordinated_init(threshold, shares) do
    if SealState.initialized?() do
      Logger.info("Vault already initialized by another node")
      {:ok, :already_initialized}
    else
      Logger.info("This node is performing cluster initialization")

      case SealState.initialize(threshold, shares) do
        {:ok, unseal_keys} ->
          mark_cluster_initialized()
          {:ok, :initialized, unseal_keys}

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  defp handle_coordinated_init_result({:ok, {:ok, :already_initialized}}, state) do
    {:reply, {:ok, :already_initialized}, state}
  end

  defp handle_coordinated_init_result({:ok, {:ok, :initialized, _keys}}, state) do
    new_state = %{state | status: :sealed}
    {:reply, {:ok, :initialized}, new_state}
  end

  defp handle_coordinated_init_result({:ok, {:error, reason}}, state) do
    {:reply, {:error, reason}, state}
  end

  defp handle_coordinated_init_result({:error, :timeout}, state) do
    {:reply, {:error, :init_lock_timeout}, state}
  end

  defp node_id!(opts) do
    node_id =
      Keyword.get(opts, :node_id) ||
        Application.get_env(:secrethub_core, :cluster_node_id)

    case node_id do
      node_id when is_binary(node_id) and byte_size(node_id) > 0 ->
        node_id

      _ ->
        raise ArgumentError,
              "cluster node identity is required; set SECRET_HUB_CLUSTER_NODE_ID or pass :node_id"
    end
  end

  defp register_node(node_id, incarnation_id, supplied_metadata) do
    hostname = :inet.gethostname() |> elem(1) |> to_string()
    version = Application.spec(:secrethub_core, :vsn) |> to_string()
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    metadata = normalize_metadata(supplied_metadata)

    attrs = %{
      node_id: node_id,
      incarnation_id: incarnation_id,
      hostname: hostname,
      status: "starting",
      leader: false,
      last_seen_at: now,
      started_at: now,
      sealed: true,
      initialized: false,
      version: version,
      metadata: metadata
    }

    result =
      %ClusterNode{}
      |> ClusterNode.changeset(attrs)
      |> Repo.insert(
        conflict_target: :node_id,
        on_conflict: registration_conflict_query()
      )

    case result do
      {:ok, node} ->
        Logger.info("Registered cluster node: #{node_id} incarnation #{incarnation_id}")
        {:ok, node}

      {:error, changeset} ->
        Logger.error("Failed to register cluster node #{node_id}")
        {:error, changeset}
    end
  end

  defp normalize_metadata(supplied_metadata) when is_map(supplied_metadata) do
    supplied_metadata
    |> Map.drop(["capabilities", :capabilities])
    |> Map.put("capabilities", @code_capabilities)
  end

  defp normalize_metadata(_supplied_metadata) do
    %{"capabilities" => @code_capabilities}
  end

  defp registration_conflict_query do
    capability_metadata = %{"capabilities" => @code_capabilities}

    from(n in ClusterNode,
      update: [
        set: [
          incarnation_id: fragment("EXCLUDED.incarnation_id"),
          hostname: fragment("EXCLUDED.hostname"),
          status: fragment("EXCLUDED.status"),
          leader: fragment("EXCLUDED.leader"),
          last_seen_at: fragment("EXCLUDED.last_seen_at"),
          started_at: fragment("EXCLUDED.started_at"),
          sealed: fragment("EXCLUDED.sealed"),
          initialized: fragment("EXCLUDED.initialized"),
          version: fragment("EXCLUDED.version"),
          metadata:
            fragment(
              "COALESCE(?, '{}'::jsonb) || (EXCLUDED.metadata - 'capabilities') || ?",
              n.metadata,
              type(^capability_metadata, :map)
            ),
          updated_at: fragment("EXCLUDED.updated_at")
        ]
      ]
    )
  end

  defp mark_cluster_initialized do
    # Store cluster initialization state
    # This would update a cluster_state table
    Logger.info("Marking cluster as initialized")
    :ok
  end

  defp update_node_status(node_id, incarnation_id, status) do
    Logger.debug("Updating node #{node_id} status to #{status}")

    sealed = status in [:sealed, :starting, :initializing]
    initialized = status != :starting
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    from(n in ClusterNode,
      where: n.node_id == ^node_id and n.incarnation_id == ^incarnation_id
    )
    |> Repo.update_all(
      set: [
        status: to_string(status),
        sealed: sealed,
        initialized: initialized,
        last_seen_at: now,
        updated_at: now
      ]
    )
    |> case do
      {1, _} ->
        :ok

      {0, _} ->
        Logger.warning("Cannot update status for stale or unknown node incarnation: #{node_id}")
        :stale_incarnation
    end
  end

  defp send_heartbeat(node_id, incarnation_id) do
    Logger.debug("Sending heartbeat for node #{node_id}")

    now = DateTime.utc_now() |> DateTime.truncate(:second)

    from(n in ClusterNode,
      where: n.node_id == ^node_id and n.incarnation_id == ^incarnation_id
    )
    |> Repo.update_all(set: [last_seen_at: now, updated_at: now])
    |> case do
      {1, _} ->
        :ok

      {0, _} ->
        Logger.warning("Cannot heartbeat stale or unknown node incarnation: #{node_id}")
        :stale_incarnation
    end
  end

  defp get_cluster_info do
    stale_cutoff =
      DateTime.add(
        DateTime.utc_now() |> DateTime.truncate(:second),
        -freshness_timeout_seconds(),
        :second
      )

    nodes =
      Repo.all(
        from(n in ClusterNode,
          where: n.status == "shutdown" or n.last_seen_at >= ^stale_cutoff,
          order_by: [desc: n.last_seen_at]
        )
      )

    node_maps =
      Enum.map(nodes, fn node ->
        %{
          node_id: node.node_id,
          hostname: node.hostname,
          status: node.status,
          leader: node.leader,
          sealed: node.sealed,
          initialized: node.initialized,
          last_seen_at: node.last_seen_at,
          started_at: node.started_at,
          version: node.version,
          metadata: node.metadata,
          stale: DateTime.compare(node.last_seen_at, stale_cutoff) == :lt
        }
      end)

    # Calculate aggregate metrics
    sealed_count = Enum.count(nodes, & &1.sealed)
    unsealed_count = Enum.count(nodes, &(!&1.sealed))

    {:ok,
     %{
       node_count: length(nodes),
       initialized: SealState.initialized?(),
       sealed_count: sealed_count,
       unsealed_count: unsealed_count,
       nodes: node_maps
     }}
  end

  defp schedule_heartbeat do
    Process.send_after(self(), :heartbeat, @heartbeat_interval)
  end

  defp schedule_leader_check do
    Process.send_after(self(), :check_leader, @leader_lock_renewal_interval)
  end

  # Health metrics collection and storage

  defp collect_and_store_health_metrics(node_id) do
    case NodeHealthCollector.collect() do
      {:ok, metrics} ->
        store_health_metrics(node_id, metrics)

      {:error, reason} ->
        Logger.error("Failed to collect health metrics for node #{node_id}: #{inspect(reason)}")
        :ok
    end
  end

  defp store_health_metrics(node_id, metrics) do
    attrs = Map.put(metrics, :node_id, node_id)

    %NodeHealthMetric{}
    |> NodeHealthMetric.changeset(attrs)
    |> Repo.insert()

    # Clean up old metrics (keep only last 7 days)
    cleanup_old_health_metrics()

    :ok
  rescue
    e ->
      Logger.error("Failed to store health metrics: #{Exception.message(e)}")
      :ok
  end

  defp cleanup_old_health_metrics do
    # Delete metrics older than 7 days
    cutoff =
      DateTime.add(DateTime.utc_now() |> DateTime.truncate(:second), -7 * 24 * 3600, :second)

    from(m in NodeHealthMetric, where: m.timestamp < ^cutoff)
    |> Repo.delete_all()

    :ok
  rescue
    _ -> :ok
  end

  defp get_health_history(node_id, hours) do
    cutoff =
      DateTime.add(DateTime.utc_now() |> DateTime.truncate(:second), -hours * 3600, :second)

    metrics =
      from(m in NodeHealthMetric,
        where: m.node_id == ^node_id and m.timestamp >= ^cutoff,
        order_by: [desc: m.timestamp]
      )
      |> Repo.all()

    {:ok, metrics}
  rescue
    e ->
      {:error, Exception.message(e)}
  end

  defp get_current_health(node_id) do
    metric =
      from(m in NodeHealthMetric,
        where: m.node_id == ^node_id,
        order_by: [desc: m.timestamp],
        limit: 1
      )
      |> Repo.one()

    case metric do
      nil -> {:error, :not_found}
      metric -> {:ok, metric}
    end
  rescue
    e ->
      {:error, Exception.message(e)}
  end
end
