defmodule SecretHub.Human.RevealStore do
  @moduledoc "Bounded, single-node, ephemeral credential handoff. Restart destroys unrevealed values."
  use GenServer

  def start_link(opts),
    do: GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))

  def put(actor, lease, credentials, opts \\ []),
    do:
      GenServer.call(
        Keyword.get(opts, :server, __MODULE__),
        {:put, actor_binding(actor), lease, credentials}
      )

  def redeem_guarded(token, actor, authorize, opts \\ []),
    do:
      GenServer.call(
        Keyword.get(opts, :server, __MODULE__),
        {:guarded, digest(token), actor_binding(actor), authorize},
        15_000
      )

  def describe(token, actor, opts \\ []), do: call(:describe, token, actor, opts)
  def redeem(token, actor, opts \\ []), do: call(:redeem, token, actor, opts)

  defp call(operation, token, actor, opts),
    do:
      GenServer.call(
        Keyword.get(opts, :server, __MODULE__),
        {operation, digest(token), actor_binding(actor)}
      )

  @impl true
  def init(opts) do
    ttl = Keyword.get(opts, :ttl_seconds, Application.get_env(:secrethub_human, :reveal_ttl, 30))
    if ttl not in 30..60, do: raise(ArgumentError, "reveal TTL must be 30..60 seconds")

    state = %{
      table: :ets.new(__MODULE__, [:set, :private]),
      ttl: ttl,
      max_entries: Keyword.get(opts, :max_entries, 500),
      per_session: Keyword.get(opts, :per_session, 3),
      per_user: Keyword.get(opts, :per_user, 10),
      clock: Keyword.get(opts, :clock, fn -> System.monotonic_time(:millisecond) end)
    }

    Process.send_after(self(), :cleanup, 1000)
    {:ok, state}
  end

  @impl true
  def handle_call({:put, binding, lease, credentials}, _from, state) do
    cleanup(state)
    entries = :ets.tab2list(state.table)

    reply =
      cond do
        is_nil(binding) or not valid_lease?(lease) or not valid_credentials?(credentials) ->
          {:error, :invalid_credentials}

        length(entries) >= state.max_entries or
          Enum.count(entries, fn {_, b, _, _, _} -> b == binding end) >= state.per_session or
            Enum.count(entries, fn {_, {u, _, _}, _, _, _} -> u == elem(binding, 0) end) >=
              state.per_user ->
          {:error, :reveal_limit}

        true ->
          token = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)

          :ets.insert(
            state.table,
            {digest(token), binding, lease.id, credentials, state.clock.() + state.ttl * 1000}
          )

          {:ok, %{token: token, expires_in: state.ttl}}
      end

    {:reply, reply, state}
  end

  def handle_call({operation, token_digest, binding}, _from, state)
      when operation in [:describe, :redeem] do
    cleanup(state)

    reply =
      case lookup(state.table, token_digest) do
        [{^token_digest, ^binding, lease_id, credentials, _}] when not is_nil(binding) ->
          if operation == :redeem do
            :ets.delete(state.table, token_digest)
            {:ok, %{lease_id: lease_id, credentials: credentials}}
          else
            {:ok, %{lease_id: lease_id}}
          end

        _ ->
          {:error, :invalid_reveal}
      end

    {:reply, reply, state}
  end

  def handle_call({:guarded, token_digest, binding, authorize}, _from, state) do
    cleanup(state)

    reply =
      case lookup(state.table, token_digest) do
        [{^token_digest, ^binding, lease_id, credentials, expiry}] when not is_nil(binding) ->
          # Serialize authorization, evidence and consume so only one caller can audit a reveal.
          authorized =
            try do
              authorize.(lease_id)
            rescue
              _ -> {:error, :invalid_reveal}
            catch
              :exit, _ -> {:error, :invalid_reveal}
            end

          :ets.delete(state.table, token_digest)

          if authorized == :ok and expiry > state.clock.(),
            do: {:ok, %{lease_id: lease_id, credentials: credentials}},
            else: {:error, :invalid_reveal}

        _ ->
          {:error, :invalid_reveal}
      end

    {:reply, reply, state}
  end

  @impl true
  def handle_info(:cleanup, state) do
    cleanup(state)
    Process.send_after(self(), :cleanup, 1000)
    {:noreply, state}
  end

  defp cleanup(state),
    do:
      :ets.select_delete(state.table, [
        {{:_, :_, :_, :_, :"$1"}, [{:"=<", :"$1", state.clock.()}], [true]}
      ])

  defp lookup(table, token_digest) when is_binary(token_digest) do
    case :ets.lookup(table, token_digest) do
      [{stored_digest, _, _, _, _} = entry] ->
        if Plug.Crypto.secure_compare(stored_digest, token_digest), do: [entry], else: []

      _ ->
        []
    end
  end

  defp lookup(_, _), do: []

  defp actor_binding(%{user_id: u, session_id: s, device_id: d}) do
    if Enum.all?([u, s, d], &match?({:ok, _}, Ecto.UUID.cast(&1))), do: {u, s, d}
  end

  defp actor_binding(_), do: nil

  defp digest(token) when is_binary(token) and byte_size(token) == 43,
    do: :crypto.hash(:sha256, token)

  defp digest(_), do: nil

  defp valid_lease?(%{id: id, status: "active", expires_at: %DateTime{} = expiry}),
    do:
      match?({:ok, _}, Ecto.UUID.cast(id)) and DateTime.compare(expiry, DateTime.utc_now()) == :gt

  defp valid_lease?(_), do: false

  defp valid_credentials?(credentials)
       when is_map(credentials) and map_size(credentials) in 1..20 do
    Enum.all?(credentials, fn {key, value} ->
      (is_atom(key) or is_binary(key)) and
        ((is_binary(value) and byte_size(value) <= 8192) or
           (key in [:port, "port"] and is_integer(value) and value in 1..65_535))
    end) and :erlang.external_size(credentials) <= 16_384
  end

  defp valid_credentials?(_), do: false
end
