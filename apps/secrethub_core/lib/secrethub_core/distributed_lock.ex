defmodule SecretHub.Core.DistributedLock do
  @moduledoc """
  Distributed locking using PostgreSQL advisory locks.

  Provides cluster-wide coordination for critical operations during HA deployments.
  Uses PostgreSQL's advisory lock mechanisms to ensure only one node performs
  critical initialization or unsealing operations at a time.

  ## PostgreSQL Advisory Locks

  Advisory locks are application-level locks that use PostgreSQL's locking system
  but don't lock actual database objects. They're perfect for distributed coordination:

  - Fast: In-memory, no disk I/O
  - Cluster-aware: All nodes see the same locks
  - Automatic cleanup: Released on connection close or transaction rollback
  - Two modes: Session-level and transaction-level

  ## Lock Types

  - **Initialization Lock**: Ensures only one node initializes the vault
  - **Unseal Lock**: Coordinates unsealing across nodes (not strictly exclusive)
  - **Master Key Rotation Lock**: Prevents concurrent key rotation
  - **Backup Lock**: Ensures only one backup operation runs at a time

  ## Usage

      # Try to acquire initialization lock
      case DistributedLock.acquire(:init, timeout: 5000) do
        {:ok, lock} ->
          # Perform initialization
          result = initialize_vault()
          DistributedLock.release(lock)
          result

        {:error, :timeout} ->
          {:error, "Another node is already initializing"}
      end

      # Use with_lock for automatic cleanup
      DistributedLock.with_lock(:unseal, timeout: 30_000, fn ->
        perform_unseal()
      end)
  """

  require Logger
  alias SecretHub.Core.Repo

  @type lock_key ::
          :init | :unseal | :master_key_rotation | :backup | :auto_unseal | {:custom, integer()}
  @type lock_handle :: %{key: lock_key, lock_id: integer(), acquired_at: DateTime.t()}
  @type lock_option :: {:timeout, non_neg_integer()} | {:session, boolean()}

  # Lock key mappings (PostgreSQL advisory locks use integers)
  # We use a hash of the lock name to generate unique integers
  @lock_keys %{
    init: 1_000_001,
    unseal: 1_000_002,
    master_key_rotation: 1_000_003,
    backup: 1_000_004,
    auto_unseal: 1_000_005
  }

  @default_timeout 30_000

  @doc """
  Acquires a distributed lock.

  ## Options

    * `:timeout` - Maximum time to wait for lock acquisition in milliseconds (default: 30000)
    * `:session` - Use session-level lock (default: true). If false, uses transaction-level.

  Returns `{:ok, lock_handle}` if acquired, `{:error, :timeout}` if timeout exceeded,
  or `{:error, :already_held}` if the calling process already holds the lock.

  ## Examples

      {:ok, lock} = DistributedLock.acquire(:init)
      # ... do work ...
      DistributedLock.release(lock)

      # With timeout
      case DistributedLock.acquire(:unseal, timeout: 5000) do
        {:ok, lock} -> # ...
        {:error, :timeout} -> # ...
      end
  """
  @spec acquire(lock_key(), [lock_option()]) ::
          {:ok, lock_handle()} | {:error, :timeout | :already_held}
  def acquire(lock_key, opts \\ []) do
    timeout = Keyword.get(opts, :timeout, @default_timeout)
    session = Keyword.get(opts, :session, true)
    lock_id = get_lock_id(lock_key)

    Logger.debug("Attempting to acquire lock: #{inspect(lock_key)} (id: #{lock_id})")

    start_time = System.monotonic_time(:millisecond)

    case try_acquire_lock(lock_id, session, timeout, start_time) do
      {:ok, true} ->
        lock_handle = %{
          key: lock_key,
          lock_id: lock_id,
          acquired_at: DateTime.utc_now() |> DateTime.truncate(:second),
          session: session
        }

        Logger.info("Acquired distributed lock: #{inspect(lock_key)}")
        {:ok, lock_handle}

      {:ok, false} ->
        {:error, :timeout}

      {:error, reason} ->
        Logger.error("Failed to acquire lock #{inspect(lock_key)}: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc """
  Releases a distributed lock.

  Releases the lock identified by the lock handle. If using session-level locks,
  this will release the lock immediately. Transaction-level locks are released
  automatically at the end of the transaction.

  ## Examples

      {:ok, lock} = DistributedLock.acquire(:init)
      # ... do work ...
      :ok = DistributedLock.release(lock)
  """
  @spec release(lock_handle()) :: :ok | {:error, term()}
  def release(%{lock_id: lock_id, key: key, session: session}) do
    Logger.debug("Releasing lock: #{inspect(key)} (id: #{lock_id})")

    if session do
      # Session-level locks need explicit unlock
      case Repo.query("SELECT pg_advisory_unlock($1)", [lock_id]) do
        {:ok, %{rows: [[true]]}} ->
          Logger.info("Released distributed lock: #{inspect(key)}")
          :ok

        {:ok, %{rows: [[false]]}} ->
          Logger.warning("Lock was not held: #{inspect(key)}")
          {:error, :not_held}

        {:error, reason} ->
          Logger.error("Failed to release lock #{inspect(key)}: #{inspect(reason)}")
          {:error, reason}
      end
    else
      # Transaction-level locks are released automatically
      :ok
    end
  end

  @doc """
  Executes a function while holding a distributed lock.

  Automatically acquires the lock before executing the function and releases it
  afterwards, even if the function raises an exception.

  ## Options

  Same as `acquire/2`.

  ## Examples

      DistributedLock.with_lock(:init, fn ->
        initialize_vault()
      end)

      # With timeout
      DistributedLock.with_lock(:unseal, [timeout: 5000], fn ->
        perform_unseal()
      end)
  """
  @spec with_lock(lock_key(), [lock_option()], (-> any())) ::
          {:ok, any()} | {:error, :timeout | term()}
  def with_lock(lock_key, opts \\ [], fun) when is_function(fun, 0) do
    case acquire(lock_key, opts) do
      {:ok, lock} ->
        try do
          result = fun.()
          {:ok, result}
        after
          release(lock)
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Checks if a lock is currently held by any node.

  Note: This is advisory only and doesn't acquire the lock. The lock status
  may change immediately after this check.

  ## Examples

      if DistributedLock.locked?(:init) do
        Logger.info("Initialization in progress on another node")
      end
  """
  @spec locked?(lock_key()) :: boolean()
  def locked?(lock_key) do
    lock_id = get_lock_id(lock_key)

    # Try to acquire with pg_try_advisory_lock (non-blocking)
    # If we get it, release it immediately and return false
    # If we don't get it, it's held by someone else
    case Repo.query("SELECT pg_try_advisory_lock($1)", [lock_id]) do
      {:ok, %{rows: [[true]]}} ->
        # We got it, release it immediately
        Repo.query("SELECT pg_advisory_unlock($1)", [lock_id])
        false

      {:ok, %{rows: [[false]]}} ->
        # Someone else holds it
        true

      {:error, _} ->
        # Error checking, assume not locked
        false
    end
  end

  @doc """
  Returns information about all currently held advisory locks in the database.

  Useful for debugging and monitoring lock contention.

  ## Examples

      DistributedLock.list_locks()
      # => [%{lock_id: 1000001, pid: 12345, granted: true, ...}]
  """
  @spec list_locks() :: {:ok, [map()]} | {:error, term()}
  def list_locks do
    query = """
    SELECT
      locktype,
      classid AS lock_id,
      objid,
      pid,
      mode,
      granted
    FROM pg_locks
    WHERE locktype = 'advisory'
    ORDER BY classid, objid
    """

    case Repo.query(query) do
      {:ok, result} ->
        locks =
          Enum.map(result.rows, fn [locktype, lock_id, objid, pid, mode, granted] ->
            %{
              locktype: locktype,
              lock_id: lock_id,
              objid: objid,
              pid: pid,
              mode: mode,
              granted: granted,
              lock_name: reverse_lookup_lock_name(lock_id)
            }
          end)

        {:ok, locks}

      {:error, reason} ->
        {:error, reason}
    end
  end

  # Private Functions

  defp get_lock_id(lock_key) when is_atom(lock_key) do
    Map.get(@lock_keys, lock_key) ||
      raise ArgumentError, "Unknown lock key: #{inspect(lock_key)}"
  end

  defp get_lock_id({:custom, id}) when is_integer(id) do
    # Custom locks must be in a different range to avoid conflicts
    if id < 2_000_000 do
      raise ArgumentError, "Custom lock IDs must be >= 2_000_000"
    end

    id
  end

  defp try_acquire_lock(lock_id, session, timeout, start_time) do
    elapsed = System.monotonic_time(:millisecond) - start_time

    if elapsed >= timeout do
      Logger.debug("Lock acquisition timed out after #{elapsed}ms")
      {:ok, false}
    else
      # Try to acquire the lock (non-blocking)
      lock_acquired? =
        if session do
          # Session-level advisory lock
          case Repo.query("SELECT pg_try_advisory_lock($1)", [lock_id]) do
            {:ok, %{rows: [[acquired]]}} -> acquired
            {:error, _} -> false
          end
        else
          # Transaction-level advisory lock (must be in a transaction)
          case Repo.query("SELECT pg_try_advisory_xact_lock($1)", [lock_id]) do
            {:ok, %{rows: [[acquired]]}} -> acquired
            {:error, _} -> false
          end
        end

      if lock_acquired? do
        {:ok, true}
      else
        # Wait a bit and retry
        Process.sleep(100)
        try_acquire_lock(lock_id, session, timeout, start_time)
      end
    end
  end

  defp reverse_lookup_lock_name(lock_id) do
    @lock_keys
    |> Enum.find(fn {_name, id} -> id == lock_id end)
    |> case do
      {name, _id} -> name
      nil -> :unknown
    end
  end
end
