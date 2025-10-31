defmodule SecretHub.Core.LeaseManager do
  @moduledoc """
  Manages the lifecycle of dynamic secret leases.

  The LeaseManager is responsible for:
  - Creating new leases when credentials are generated
  - Tracking lease expiry times
  - Scheduling automatic revocation on expiry
  - Handling lease renewal requests
  - Cleaning up expired leases
  - Coordinating with dynamic engines for revocation

  ## Lease Lifecycle

  1. **Creation**: When a dynamic engine generates credentials, a lease is created
  2. **Active**: Lease is tracked and can be renewed before expiry
  3. **Renewal**: Client can request lease renewal (extends TTL)
  4. **Expiry**: When TTL reaches zero, credentials are automatically revoked
  5. **Cleanup**: Lease is marked as revoked and eventually purged from database

  ## State Management

  The LeaseManager maintains an in-memory index of active leases for fast lookups
  and uses a heap-based timer system for efficient expiry scheduling.
  """

  use GenServer

  require Logger

  alias SecretHub.Shared.Schemas.Lease
  alias SecretHub.Core.Repo

  import Ecto.Query

  @cleanup_interval :timer.minutes(5)
  @revocation_check_interval :timer.seconds(10)

  defmodule State do
    @moduledoc false
    defstruct [
      # Map of lease_id => %Lease{}
      :leases,
      # Timer ref for periodic cleanup
      :cleanup_timer,
      # Timer ref for revocation checks
      :revocation_timer
    ]
  end

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Create a new lease for dynamic credentials.

  ## Parameters

  - `attrs`: Lease attributes
    - `:engine_type` - Type of dynamic engine ("postgresql", "redis", etc.)
    - `:role_name` - Name of the role used to generate credentials
    - `:credentials` - Generated credentials (will be encrypted)
    - `:ttl` - Time-to-live in seconds
    - `:agent_id` - ID of the agent that requested the credentials (optional)
    - `:metadata` - Additional metadata (optional)

  ## Returns

  - `{:ok, lease}` - Successfully created lease
  - `{:error, changeset}` - Validation failed
  """
  def create_lease(attrs) do
    GenServer.call(__MODULE__, {:create_lease, attrs})
  end

  @doc """
  Renew an existing lease.

  ## Parameters

  - `lease_id`: ID of the lease to renew
  - `increment`: TTL increment in seconds (optional, uses default if not provided)

  ## Returns

  - `{:ok, lease}` - Successfully renewed lease with updated TTL
  - `{:error, :not_found}` - Lease not found
  - `{:error, :expired}` - Lease has already expired
  - `{:error, reason}` - Engine-specific renewal failure
  """
  def renew_lease(lease_id, increment \\ nil) do
    GenServer.call(__MODULE__, {:renew_lease, lease_id, increment})
  end

  @doc """
  Manually revoke a lease.

  This immediately revokes the credentials and marks the lease as revoked.

  ## Parameters

  - `lease_id`: ID of the lease to revoke

  ## Returns

  - `:ok` - Successfully revoked
  - `{:error, :not_found}` - Lease not found
  - `{:error, reason}` - Failed to revoke credentials
  """
  def revoke_lease(lease_id) do
    GenServer.call(__MODULE__, {:revoke_lease, lease_id})
  end

  @doc """
  Get a lease by ID.

  ## Returns

  - `{:ok, lease}` - Lease found
  - `{:error, :not_found}` - Lease not found
  """
  def get_lease(lease_id) do
    GenServer.call(__MODULE__, {:get_lease, lease_id})
  end

  @doc """
  List all active leases.

  ## Parameters

  - `opts`: Options for filtering
    - `:engine_type` - Filter by engine type
    - `:agent_id` - Filter by agent ID
    - `:limit` - Maximum number of leases to return

  ## Returns

  List of active leases
  """
  def list_active_leases(opts \\ []) do
    GenServer.call(__MODULE__, {:list_active_leases, opts})
  end

  @doc """
  Get lease statistics.

  ## Returns

  Map with statistics:
  - `:total_active` - Number of active leases
  - `:by_engine` - Count by engine type
  - `:expiring_soon` - Leases expiring in next 5 minutes
  """
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    # Load active leases from database
    {:ok, leases} = load_active_leases()

    # Schedule periodic cleanup
    cleanup_timer = Process.send_after(self(), :cleanup_expired, @cleanup_interval)

    # Schedule revocation checks
    revocation_timer = Process.send_after(self(), :check_revocations, @revocation_check_interval)

    state = %State{
      leases: leases,
      cleanup_timer: cleanup_timer,
      revocation_timer: revocation_timer
    }

    Logger.info("LeaseManager started with #{map_size(leases)} active leases")

    {:ok, state}
  end

  @impl true
  def handle_call({:create_lease, attrs}, _from, state) do
    ttl = attrs[:ttl] || 3600
    expires_at = DateTime.add(DateTime.utc_now(), ttl, :second)

    lease_attrs =
      attrs
      |> Map.new()
      |> Map.put(:expires_at, expires_at)
      |> Map.put(:renewable, true)
      |> Map.put(:status, "active")

    case create_lease_in_db(lease_attrs) do
      {:ok, lease} ->
        new_leases = Map.put(state.leases, lease.id, lease)

        Logger.info("Created lease",
          lease_id: lease.id,
          engine_type: lease.engine_type,
          role: lease.role_name,
          ttl: ttl
        )

        {:reply, {:ok, lease}, %{state | leases: new_leases}}

      {:error, changeset} = error ->
        Logger.error("Failed to create lease", error: inspect(changeset.errors))
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:renew_lease, lease_id, increment}, _from, state) do
    case Map.get(state.leases, lease_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      lease ->
        if DateTime.compare(lease.expires_at, DateTime.utc_now()) == :lt do
          {:reply, {:error, :expired}, state}
        else
          case perform_renewal(lease, increment) do
            {:ok, updated_lease} ->
              new_leases = Map.put(state.leases, lease_id, updated_lease)
              {:reply, {:ok, updated_lease}, %{state | leases: new_leases}}

            {:error, reason} = error ->
              Logger.error("Failed to renew lease",
                lease_id: lease_id,
                reason: inspect(reason)
              )

              {:reply, error, state}
          end
        end
    end
  end

  @impl true
  def handle_call({:revoke_lease, lease_id}, _from, state) do
    case Map.get(state.leases, lease_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      lease ->
        case perform_revocation(lease) do
          :ok ->
            new_leases = Map.delete(state.leases, lease_id)
            {:reply, :ok, %{state | leases: new_leases}}

          {:error, reason} = error ->
            Logger.error("Failed to revoke lease",
              lease_id: lease_id,
              reason: inspect(reason)
            )

            {:reply, error, state}
        end
    end
  end

  @impl true
  def handle_call({:get_lease, lease_id}, _from, state) do
    case Map.get(state.leases, lease_id) do
      nil -> {:reply, {:error, :not_found}, state}
      lease -> {:reply, {:ok, lease}, state}
    end
  end

  @impl true
  def handle_call({:list_active_leases, opts}, _from, state) do
    leases =
      state.leases
      |> Map.values()
      |> filter_leases(opts)
      |> Enum.take(Keyword.get(opts, :limit, 100))

    {:reply, leases, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    now = DateTime.utc_now()
    five_minutes_from_now = DateTime.add(now, 300, :second)

    stats = %{
      total_active: map_size(state.leases),
      by_engine:
        state.leases
        |> Map.values()
        |> Enum.group_by(& &1.engine_type)
        |> Map.new(fn {engine, leases} -> {engine, length(leases)} end),
      expiring_soon:
        state.leases
        |> Map.values()
        |> Enum.count(fn lease ->
          DateTime.compare(lease.expires_at, five_minutes_from_now) == :lt
        end)
    }

    {:reply, stats, state}
  end

  @impl true
  def handle_info(:cleanup_expired, state) do
    # Find and revoke expired leases
    {expired, active} =
      Enum.split_with(state.leases, fn {_id, lease} ->
        DateTime.compare(lease.expires_at, DateTime.utc_now()) == :lt
      end)

    if length(expired) > 0 do
      Logger.info("Found #{length(expired)} expired leases, revoking...")

      Enum.each(expired, fn {_id, lease} ->
        case perform_revocation(lease) do
          :ok -> :ok
          {:error, reason} -> Logger.error("Failed to revoke expired lease: #{inspect(reason)}")
        end
      end)
    end

    # Schedule next cleanup
    cleanup_timer = Process.send_after(self(), :cleanup_expired, @cleanup_interval)

    {:noreply, %{state | leases: Map.new(active), cleanup_timer: cleanup_timer}}
  end

  @impl true
  def handle_info(:check_revocations, state) do
    # Check for leases that need immediate revocation
    now = DateTime.utc_now()

    Enum.each(state.leases, fn {_id, lease} ->
      if DateTime.compare(lease.expires_at, now) == :lt do
        # Send async revocation message
        send(self(), {:revoke_now, lease.id})
      end
    end)

    # Schedule next check
    revocation_timer = Process.send_after(self(), :check_revocations, @revocation_check_interval)

    {:noreply, %{state | revocation_timer: revocation_timer}}
  end

  @impl true
  def handle_info({:revoke_now, lease_id}, state) do
    case Map.get(state.leases, lease_id) do
      nil ->
        {:noreply, state}

      lease ->
        case perform_revocation(lease) do
          :ok ->
            new_leases = Map.delete(state.leases, lease_id)
            {:noreply, %{state | leases: new_leases}}

          {:error, reason} ->
            Logger.error("Failed to revoke lease",
              lease_id: lease_id,
              reason: inspect(reason)
            )

            # Keep in state for retry
            {:noreply, state}
        end
    end
  end

  # Private Functions

  defp load_active_leases do
    leases =
      Lease
      |> where([l], l.status == "active")
      |> where([l], l.expires_at > ^DateTime.utc_now())
      |> Repo.all()
      |> Map.new(fn lease -> {lease.id, lease} end)

    {:ok, leases}
  end

  defp create_lease_in_db(attrs) do
    %Lease{}
    |> Lease.changeset(attrs)
    |> Repo.insert()
  end

  defp perform_renewal(lease, increment) do
    # Call the dynamic engine to renew
    engine_module = engine_module_for_type(lease.engine_type)

    opts = [
      increment: increment || 3600,
      current_ttl: DateTime.diff(lease.expires_at, DateTime.utc_now()),
      credentials: lease.credentials,
      config: lease.metadata["config"] || %{}
    ]

    case engine_module.renew_lease(lease.id, opts) do
      {:ok, %{ttl: new_ttl}} ->
        new_expires_at = DateTime.add(DateTime.utc_now(), new_ttl, :second)

        lease
        |> Lease.changeset(%{
          expires_at: new_expires_at,
          last_renewal_time: DateTime.utc_now()
        })
        |> Repo.update()

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp perform_revocation(lease) do
    # Call the dynamic engine to revoke
    engine_module = engine_module_for_type(lease.engine_type)

    case engine_module.revoke_credentials(lease.id, lease.credentials) do
      :ok ->
        # Mark lease as revoked in database
        lease
        |> Lease.changeset(%{
          status: "revoked",
          revoked_at: DateTime.utc_now()
        })
        |> Repo.update()

        Logger.info("Revoked lease", lease_id: lease.id)
        :ok

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp engine_module_for_type("postgresql"), do: SecretHub.Core.Engines.Dynamic.PostgreSQL
  defp engine_module_for_type("redis"), do: SecretHub.Core.Engines.Dynamic.Redis
  defp engine_module_for_type("aws_sts"), do: SecretHub.Core.Engines.Dynamic.AWSSTS
  defp engine_module_for_type("aws"), do: SecretHub.Core.Engines.Dynamic.AWSSTS
  defp engine_module_for_type(type), do: raise("Unknown engine type: #{type}")

  defp filter_leases(leases, opts) do
    leases
    |> filter_by_engine(Keyword.get(opts, :engine_type))
    |> filter_by_agent(Keyword.get(opts, :agent_id))
  end

  defp filter_by_engine(leases, nil), do: leases

  defp filter_by_engine(leases, engine_type) do
    Enum.filter(leases, fn lease -> lease.engine_type == engine_type end)
  end

  defp filter_by_agent(leases, nil), do: leases

  defp filter_by_agent(leases, agent_id) do
    Enum.filter(leases, fn lease -> lease.agent_id == agent_id end)
  end
end
