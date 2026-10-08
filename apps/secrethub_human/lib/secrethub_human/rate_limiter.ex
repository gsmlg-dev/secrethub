defmodule SecretHub.Human.RateLimiter do
  @moduledoc "Bounded, fail-closed authentication attempt windows."
  use GenServer

  def start_link(opts) do
    case Keyword.get(opts, :name, __MODULE__) do
      nil -> GenServer.start_link(__MODULE__, opts)
      name -> GenServer.start_link(__MODULE__, opts, name: name)
    end
  end

  def check(key, server \\ __MODULE__), do: GenServer.call(server, {:check, key})

  @impl true
  def init(opts) do
    Process.send_after(self(), :prune, 60_000)

    {:ok,
     %{
       buckets: %{},
       max_attempts: Keyword.get(opts, :max_attempts, 5),
       window_ms: Keyword.get(opts, :window_ms, 60_000),
       max_keys: Keyword.get(opts, :max_keys, 10_000)
     }}
  end

  @impl true
  def handle_call({:check, key}, _from, state) do
    now = System.monotonic_time(:millisecond)
    hashed_key = :crypto.hash(:sha256, key)

    case Map.get(state.buckets, hashed_key) do
      {count, deadline} when deadline > now and count >= state.max_attempts ->
        {:reply, {:error, :rate_limited}, state}

      {count, deadline} when deadline > now ->
        {:reply, :ok, put_in(state.buckets[hashed_key], {count + 1, deadline})}

      _ ->
        buckets = Map.reject(state.buckets, fn {_key, {_count, deadline}} -> deadline <= now end)

        if map_size(buckets) >= state.max_keys do
          {:reply, {:error, :rate_limited}, %{state | buckets: buckets}}
        else
          {:reply, :ok,
           %{state | buckets: Map.put(buckets, hashed_key, {1, now + state.window_ms})}}
        end
    end
  end

  @impl true
  def handle_info(:prune, state) do
    now = System.monotonic_time(:millisecond)
    buckets = Map.reject(state.buckets, fn {_key, {_count, deadline}} -> deadline <= now end)
    Process.send_after(self(), :prune, 60_000)
    {:noreply, %{state | buckets: buckets}}
  end
end
