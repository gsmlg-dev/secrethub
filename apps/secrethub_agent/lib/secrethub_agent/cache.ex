defmodule SecretHub.Agent.Cache do
  @moduledoc """
  Local secret caching for SecretHub Agent.

  Provides:
  - In-memory caching of secrets with TTL
  - Automatic cache invalidation
  - Fallback mode when Core is unavailable
  - Cache warming on startup
  - Metrics for cache hit/miss rates

  ## Configuration

      config :secrethub_agent, SecretHub.Agent.Cache,
        enabled: true,
        ttl_seconds: 300,  # 5 minutes
        max_size: 1000,    # Max cached secrets
        fallback_enabled: true  # Use stale cache when Core unavailable

  ## Cache Key Format

  Cache keys are in the format: `"secret:<secret_path>"`

  ## Cache Entry Format

  ```elixir
  %{
    secret_path: "prod.db.postgres.password",
    data: %{"username" => "admin", "password" => "secret123"},
    fetched_at: ~U[2023-10-20 10:30:00Z],
    expires_at: ~U[2023-10-20 10:35:00Z],
    version: 1
  }
  ```
  """

  use GenServer
  require Logger

  @default_ttl_seconds 300
  @default_max_size 1000
  @cleanup_interval 60_000

  # Metrics
  @cache_hits_counter :cache_hits_total
  @cache_misses_counter :cache_misses_total

  defmodule CacheEntry do
    @moduledoc false
    defstruct [:secret_path, :data, :fetched_at, :expires_at, :version]

    @type t :: %__MODULE__{
            secret_path: String.t(),
            data: map(),
            fetched_at: DateTime.t(),
            expires_at: DateTime.t(),
            version: integer()
          }
  end

  ## Client API

  @doc """
  Start the cache GenServer.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Get a secret from cache.

  Returns `{:ok, data}` if found and not expired, `{:error, :not_found}` otherwise.
  """
  @spec get(String.t()) :: {:ok, map()} | {:error, :not_found | :expired}
  def get(secret_path) do
    GenServer.call(__MODULE__, {:get, secret_path})
  end

  @doc """
  Put a secret in cache with TTL.

  ## Options

  - `:ttl` - TTL in seconds (default: configured TTL)
  - `:version` - Secret version number
  """
  @spec put(String.t(), map(), keyword()) :: :ok
  def put(secret_path, data, opts \\ []) do
    GenServer.cast(__MODULE__, {:put, secret_path, data, opts})
  end

  @doc """
  Invalidate a secret in cache.
  """
  @spec invalidate(String.t()) :: :ok
  def invalidate(secret_path) do
    GenServer.cast(__MODULE__, {:invalidate, secret_path})
  end

  @doc """
  Clear all cached secrets.
  """
  @spec clear() :: :ok
  def clear do
    GenServer.cast(__MODULE__, :clear)
  end

  @doc """
  Get cache statistics.
  """
  @spec stats() :: map()
  def stats do
    GenServer.call(__MODULE__, :stats)
  end

  @doc """
  Check if fallback mode is enabled and get stale secret if available.

  Returns `{:ok, data}` even if expired when fallback is enabled.
  """
  @spec get_with_fallback(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_with_fallback(secret_path) do
    GenServer.call(__MODULE__, {:get_with_fallback, secret_path})
  end

  ## GenServer Callbacks

  @impl true
  def init(opts) do
    ttl_seconds = Keyword.get(opts, :ttl_seconds, @default_ttl_seconds)
    max_size = Keyword.get(opts, :max_size, @default_max_size)
    fallback_enabled = Keyword.get(opts, :fallback_enabled, true)

    # Schedule periodic cleanup
    schedule_cleanup()

    # Initialize metrics
    :ets.new(@cache_hits_counter, [:named_table, :public, :set])
    :ets.new(@cache_misses_counter, [:named_table, :public, :set])
    :ets.insert(@cache_hits_counter, {:count, 0})
    :ets.insert(@cache_misses_counter, {:count, 0})

    state = %{
      cache: %{},
      ttl_seconds: ttl_seconds,
      max_size: max_size,
      fallback_enabled: fallback_enabled,
      hits: 0,
      misses: 0
    }

    Logger.info("Secret cache initialized",
      ttl_seconds: ttl_seconds,
      max_size: max_size,
      fallback_enabled: fallback_enabled
    )

    {:ok, state}
  end

  @impl true
  def handle_call({:get, secret_path}, _from, state) do
    case Map.get(state.cache, secret_path) do
      nil ->
        increment_misses()
        {:reply, {:error, :not_found}, %{state | misses: state.misses + 1}}

      entry ->
        if expired?(entry) do
          increment_misses()
          {:reply, {:error, :expired}, %{state | misses: state.misses + 1}}
        else
          increment_hits()
          Logger.debug("Cache hit", secret_path: secret_path)
          {:reply, {:ok, entry.data}, %{state | hits: state.hits + 1}}
        end
    end
  end

  @impl true
  def handle_call({:get_with_fallback, secret_path}, _from, state) do
    case Map.get(state.cache, secret_path) do
      nil ->
        {:reply, {:error, :not_found}, state}

      entry ->
        handle_fallback_entry(entry, secret_path, state)
    end
  end

  @impl true
  def handle_call(:stats, _from, state) do
    stats = %{
      size: map_size(state.cache),
      max_size: state.max_size,
      hits: state.hits,
      misses: state.misses,
      hit_rate: calculate_hit_rate(state.hits, state.misses),
      ttl_seconds: state.ttl_seconds,
      fallback_enabled: state.fallback_enabled
    }

    {:reply, stats, state}
  end

  defp handle_fallback_entry(entry, secret_path, state) do
    cond do
      expired?(entry) and not state.fallback_enabled ->
        {:reply, {:error, :expired}, state}

      expired?(entry) ->
        Logger.warning("Using stale cached secret (fallback mode)",
          secret_path: secret_path,
          expired_at: entry.expires_at
        )

        {:reply, {:ok, entry.data}, state}

      true ->
        {:reply, {:ok, entry.data}, state}
    end
  end

  @impl true
  def handle_cast({:put, secret_path, data, opts}, state) do
    ttl = Keyword.get(opts, :ttl, state.ttl_seconds)
    version = Keyword.get(opts, :version, 1)

    entry = %CacheEntry{
      secret_path: secret_path,
      data: data,
      fetched_at: DateTime.utc_now(),
      expires_at: DateTime.add(DateTime.utc_now(), ttl, :second),
      version: version
    }

    new_cache = Map.put(state.cache, secret_path, entry)

    # Evict oldest entries if cache is full
    new_cache =
      if map_size(new_cache) > state.max_size do
        evict_oldest(new_cache)
      else
        new_cache
      end

    Logger.debug("Secret cached",
      secret_path: secret_path,
      ttl: ttl,
      expires_at: entry.expires_at
    )

    {:noreply, %{state | cache: new_cache}}
  end

  @impl true
  def handle_cast({:invalidate, secret_path}, state) do
    new_cache = Map.delete(state.cache, secret_path)

    Logger.debug("Secret invalidated from cache", secret_path: secret_path)

    {:noreply, %{state | cache: new_cache}}
  end

  @impl true
  def handle_cast(:clear, state) do
    Logger.info("Cache cleared", count: map_size(state.cache))
    {:noreply, %{state | cache: %{}}}
  end

  @impl true
  def handle_info(:cleanup, state) do
    # Remove expired entries
    new_cache =
      state.cache
      |> Enum.reject(fn {_path, entry} -> expired?(entry) end)
      |> Map.new()

    expired_count = map_size(state.cache) - map_size(new_cache)

    if expired_count > 0 do
      Logger.debug("Cleaned up expired cache entries", count: expired_count)
    end

    # Schedule next cleanup
    schedule_cleanup()

    {:noreply, %{state | cache: new_cache}}
  end

  ## Private Functions

  defp expired?(entry) do
    DateTime.compare(DateTime.utc_now(), entry.expires_at) == :gt
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, @cleanup_interval)
  end

  defp evict_oldest(cache) do
    # Find and remove the oldest entry
    {oldest_path, _} =
      cache
      |> Enum.min_by(fn {_path, entry} -> DateTime.to_unix(entry.fetched_at) end)

    Logger.debug("Evicting oldest cache entry", secret_path: oldest_path)

    Map.delete(cache, oldest_path)
  end

  defp calculate_hit_rate(hits, misses) when hits + misses > 0 do
    Float.round(hits / (hits + misses) * 100, 2)
  end

  defp calculate_hit_rate(_hits, _misses), do: 0.0

  defp increment_hits do
    :ets.update_counter(@cache_hits_counter, :count, 1)
  rescue
    _ -> :ok
  end

  defp increment_misses do
    :ets.update_counter(@cache_misses_counter, :count, 1)
  rescue
    _ -> :ok
  end
end
