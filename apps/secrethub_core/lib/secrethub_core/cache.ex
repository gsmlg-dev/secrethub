defmodule SecretHub.Core.Cache do
  @moduledoc """
  High-performance ETS-based caching layer for SecretHub.

  Provides caching for:
  - Policy evaluation results
  - Secret metadata (not encrypted values)
  - Database query results
  - Agent connection metadata

  Features:
  - TTL-based expiration
  - Automatic cleanup of expired entries
  - Telemetry metrics for hits/misses
  - LRU eviction when cache size limit reached
  """

  use GenServer
  require Logger

  # 5 minutes
  @default_ttl_seconds 300
  # 1 minute
  @cleanup_interval 60_000
  @max_cache_entries 10_000

  # Cache tables
  @policy_cache :policy_cache
  @secret_cache :secret_cache
  @query_cache :query_cache

  @cache_tables [@policy_cache, @secret_cache, @query_cache]

  ## Client API

  @doc """
  Starts the cache GenServer.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Get a value from cache.

  Returns `{:ok, value}` if found and not expired, `:error` otherwise.
  """
  def get(cache_type, key) do
    table = get_table(cache_type)

    case :ets.lookup(table, key) do
      [{^key, value, expires_at}] ->
        now = System.system_time(:second)

        if expires_at > now do
          # Cache hit
          :telemetry.execute([:secrethub, :cache, :hit], %{count: 1}, %{cache_type: cache_type})
          {:ok, value}
        else
          # Expired entry
          :ets.delete(table, key)
          :telemetry.execute([:secrethub, :cache, :miss], %{count: 1}, %{cache_type: cache_type})
          :error
        end

      [] ->
        # Cache miss
        :telemetry.execute([:secrethub, :cache, :miss], %{count: 1}, %{cache_type: cache_type})
        :error
    end
  end

  @doc """
  Put a value in cache with optional TTL.

  ## Options
    - `:ttl` - Time to live in seconds (default: #{@default_ttl_seconds})
  """
  def put(cache_type, key, value, opts \\ []) do
    table = get_table(cache_type)
    ttl = Keyword.get(opts, :ttl, @default_ttl_seconds)
    expires_at = System.system_time(:second) + ttl

    # Check cache size and evict if needed
    if :ets.info(table, :size) >= @max_cache_entries do
      evict_lru(table)
    end

    :ets.insert(table, {key, value, expires_at})
    :ok
  end

  @doc """
  Fetch value from cache, or compute and store it if not found.

  ## Example

      Cache.fetch(:policy, {policy_id, context}, fn ->
        # Expensive policy evaluation
        PolicyEvaluator.evaluate(policy_id, context)
      end)
  """
  def fetch(cache_type, key, fun, opts \\ []) when is_function(fun, 0) do
    case get(cache_type, key) do
      {:ok, value} ->
        value

      :error ->
        value = fun.()
        put(cache_type, key, value, opts)
        value
    end
  end

  @doc """
  Delete a specific key from cache.
  """
  def delete(cache_type, key) do
    table = get_table(cache_type)
    :ets.delete(table, key)
    :ok
  end

  @doc """
  Clear all entries from a specific cache.
  """
  def clear(cache_type) do
    table = get_table(cache_type)
    :ets.delete_all_objects(table)
    :ok
  end

  @doc """
  Clear all caches.
  """
  def clear_all do
    Enum.each(@cache_tables, &:ets.delete_all_objects/1)
    :ok
  end

  @doc """
  Get cache statistics.

  Returns a map with cache stats for the specified cache type.
  """
  def stats(cache_type) do
    table = get_table(cache_type)

    case :ets.whereis(table) do
      :undefined ->
        %{size: 0, memory_bytes: 0}

      _table ->
        info = :ets.info(table)

        %{
          size: info[:size],
          memory_bytes: info[:memory] * :erlang.system_info(:wordsize),
          memory_kb: div(info[:memory] * :erlang.system_info(:wordsize), 1024)
        }
    end
  end

  @doc """
  Get stats for all caches.
  """
  def stats_all do
    Map.new(@cache_tables, fn table ->
      {table, stats(table)}
    end)
  end

  ## Server Callbacks

  @impl true
  def init(_opts) do
    # Create ETS tables
    Enum.each(@cache_tables, fn table_name ->
      :ets.new(table_name, [
        :set,
        :public,
        :named_table,
        read_concurrency: true,
        write_concurrency: true
      ])
    end)

    # Schedule periodic cleanup
    schedule_cleanup()

    Logger.info("Cache system initialized",
      tables: @cache_tables,
      max_entries: @max_cache_entries,
      default_ttl: @default_ttl_seconds
    )

    {:ok, %{}}
  end

  @impl true
  def handle_info(:cleanup, state) do
    cleanup_expired()
    schedule_cleanup()
    {:noreply, state}
  end

  ## Private Functions

  defp get_table(:policy), do: @policy_cache
  defp get_table(:secret), do: @secret_cache
  defp get_table(:query), do: @query_cache
  defp get_table(table) when is_atom(table), do: table

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, @cleanup_interval)
  end

  defp cleanup_expired do
    now = System.system_time(:second)
    deleted_total = 0

    deleted_total =
      Enum.reduce(@cache_tables, deleted_total, fn table, acc ->
        match_spec = [
          {
            {:_, :_, :"$1"},
            [{:<, :"$1", now}],
            [true]
          }
        ]

        deleted = :ets.select_delete(table, match_spec)
        acc + deleted
      end)

    if deleted_total > 0 do
      Logger.debug("Cleaned up expired cache entries", deleted: deleted_total)
    end

    deleted_total
  end

  defp evict_lru(table) do
    # Evict 10% of oldest entries (simple LRU approximation)
    # In a real LRU, we'd track access times, but this is a reasonable approximation
    entries_to_evict = div(@max_cache_entries, 10)

    # Get all entries sorted by expiration (oldest first)
    entries =
      :ets.tab2list(table)
      |> Enum.sort_by(fn {_key, _value, expires_at} -> expires_at end)
      |> Enum.take(entries_to_evict)

    # Delete oldest entries
    Enum.each(entries, fn {key, _value, _expires_at} ->
      :ets.delete(table, key)
    end)

    Logger.debug("Evicted LRU cache entries",
      table: table,
      evicted: length(entries)
    )

    length(entries)
  end
end
