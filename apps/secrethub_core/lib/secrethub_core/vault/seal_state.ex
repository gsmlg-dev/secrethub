defmodule SecretHub.Core.Vault.SealState do
  @moduledoc """
  Durable, authenticated manual unseal. A successful database read is required
  before initialization. Process restart clears the in-memory data key; manual
  sealing intentionally remains a no-op.
  """
  use GenServer
  require Logger
  alias SecretHub.Core.{Audit, Repo}
  alias SecretHub.Core.Vault.{KeyEnvelope, LegacyRecovery}
  alias SecretHub.Shared.Crypto.{Encryption, Shamir}
  alias SecretHub.Shared.Schemas.VaultConfig

  defmodule State do
    @moduledoc false
    @derive {Inspect, except: [:master_key, :unseal_shares]}
    defstruct status: :loading,
              master_key: nil,
              unseal_epoch: nil,
              config: nil,
              unseal_shares: [],
              unseal_progress: 0,
              repo: Repo,
              dynamic_repo: nil,
              retry_interval: 1_000,
              load_timeout: 1_000,
              load_task: nil,
              task_supervisor: nil
  end

  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  def initialize(total_shares, threshold),
    do: GenServer.call(__MODULE__, {:initialize, total_shares, threshold})

  def unseal(share) do
    deadline = System.monotonic_time(:millisecond) + 5_000

    case GenServer.call(__MODULE__, {:unseal, share}) do
      {:validate_unsealed, snapshot} -> validate_unsealed(snapshot, :unseal, deadline)
      reply -> reply
    end
  end

  def seal, do: GenServer.call(__MODULE__, :seal)
  def status, do: GenServer.call(__MODULE__, :status)
  def initialized?, do: status().initialized
  def sealed?, do: status().sealed

  def get_master_key(timeout \\ 5_000) do
    deadline = System.monotonic_time(:millisecond) + timeout

    case GenServer.call(__MODULE__, :prepare_key_validation, timeout) do
      {:validate_unsealed, snapshot} -> validate_unsealed(snapshot, :key, deadline)
      reply -> reply
    end
  end

  @doc "Explicit legacy recovery; verifies against preexisting database ciphertext before replacing only the legacy envelope."
  def recover_legacy(encoded_shares, total_shares, threshold),
    do:
      GenServer.call(
        __MODULE__,
        {:recover_legacy, encoded_shares, total_shares, threshold},
        30_000
      )

  @impl true
  def init(opts) do
    {:ok, supervisor} = Task.Supervisor.start_link()
    repo = Keyword.get(opts, :repo, Repo)

    {:ok,
     %State{
       repo: repo,
       dynamic_repo: dynamic_repo(repo),
       retry_interval: Keyword.get(opts, :retry_interval, 1_000),
       load_timeout: Keyword.get(opts, :load_timeout, 1_000),
       task_supervisor: supervisor
     }, {:continue, :load}}
  end

  @impl true
  def handle_continue(:load, state), do: {:noreply, begin_load(state)}

  @impl true
  def handle_info({ref, result}, %{load_task: %{ref: ref, timer: timer}} = state) do
    Process.demonitor(ref, [:flush])
    Process.cancel_timer(timer)
    {:noreply, apply_load(%{state | load_task: nil}, result)}
  end

  def handle_info({:load_timeout, ref}, %{load_task: %{ref: ref, pid: pid}} = state) do
    Process.demonitor(ref, [:flush])
    Task.Supervisor.terminate_child(state.task_supervisor, pid)
    {:noreply, unavailable(%{state | load_task: nil})}
  end

  def handle_info({:DOWN, ref, :process, _, _}, %{load_task: %{ref: ref, timer: timer}} = state) do
    Process.cancel_timer(timer)
    {:noreply, unavailable(%{state | load_task: nil})}
  end

  def handle_info(:retry_load, %{status: :unavailable, load_task: nil} = state),
    do: {:noreply, begin_load(state)}

  def handle_info({:load_timeout, _}, state), do: {:noreply, state}
  def handle_info({ref, _}, state) when is_reference(ref), do: {:noreply, state}
  def handle_info({:DOWN, _, :process, _, _}, state), do: {:noreply, state}
  def handle_info(:retry_load, state), do: {:noreply, state}
  def handle_info(:auto_seal, state), do: {:noreply, state}

  @impl true
  def handle_call(:status, _from, state) do
    config = state.config

    {:reply,
     %{
       state: state.status,
       initialized: not is_nil(config),
       sealed: state.status != :unsealed,
       progress: state.unseal_progress,
       threshold: config && config.threshold,
       total_shares: config && config.total_shares,
       recovery_required: legacy?(config)
     }, state}
  end

  def handle_call(:prepare_key_validation, _from, %{status: :unsealed} = state),
    do: {:reply, {:validate_unsealed, validation_snapshot(state)}, state}

  def handle_call(:prepare_key_validation, _from, %{status: :loading} = state),
    do: {:reply, {:error, :unavailable}, state}

  def handle_call(:prepare_key_validation, _from, state),
    do: {:reply, {:error, state.status}, state}

  def handle_call({:finish_key_validation, snapshot, durable, operation, deadline}, _from, state) do
    cond do
      state.status != :unsealed or state.unseal_epoch != snapshot.unseal_epoch or
          state.config != snapshot.config ->
        {:reply, validation_error(operation), state}

      remaining(deadline) == 0 or durable != {:ok, state.config} ->
        {:reply, validation_error(operation), unavailable(state)}

      operation == :key ->
        {:reply, {:ok, state.master_key}, state}

      operation == :unseal ->
        {:reply, {:ok, result(state, false, state.config.threshold)}, state}
    end
  end

  def handle_call(:seal, _from, state), do: {:reply, :ok, state}

  def handle_call({:initialize, total, threshold}, _from, %{status: :not_initialized} = state) do
    with {:ok, config, shares} <- new_config(total, threshold),
         {:ok, committed} <- create_config(state.repo, config) do
      {:reply, {:ok, shares}, %{state | status: :sealed, config: committed}}
    else
      {:error, :durable_failure} ->
        {:reply, {:error, "Vault initialization failed; durable state unavailable"},
         unavailable(state)}

      {:error, :already_initialized} ->
        {:reply, {:error, "Vault already initialized"}, begin_load(%{state | status: :loading})}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:initialize, _, _}, _from, %{status: status} = state)
      when status in [:loading, :unavailable],
      do: {:reply, {:error, "Vault durable state unavailable"}, state}

  def handle_call({:initialize, _, _}, _from, state),
    do: {:reply, {:error, "Vault already initialized"}, state}

  def handle_call({:unseal, _}, _from, %{status: :unsealed} = state),
    do: {:reply, {:validate_unsealed, validation_snapshot(state)}, state}

  def handle_call({:unseal, share}, _from, %{status: :sealed} = state) do
    cond do
      not durable_config_matches?(state) ->
        {:reply, {:error, "Vault durable state unavailable"}, unavailable(state)}

      legacy?(state.config) ->
        invalid_attempt(state, "Legacy Vault recovery required")

      not matching_share?(share, state.config) ->
        invalid_attempt(state, "Invalid share or Vault generation")

      Enum.any?(state.unseal_shares, &(&1.id == share.id)) ->
        invalid_attempt(state, "Duplicate share coordinate")

      true ->
        collect_share(share, state)
    end
  end

  def handle_call({:unseal, _}, _from, state),
    do: {:reply, {:error, "Vault unavailable or not initialized"}, state}

  def handle_call(
        {:recover_legacy, shares, total, threshold},
        _from,
        %{status: :sealed, config: config} = state
      ) do
    if legacy?(config) do
      with {:ok, old_key} <- LegacyRecovery.reconstruct(shares, config),
           {:ok, candidate, new_shares} <-
             new_config(total, threshold, old_key, config.id, config.initialized_at),
           {:ok, committed} <-
             LegacyRecovery.persist(state.repo, config, candidate, old_key, fn ->
               audit_event("vault_legacy_recovered", %{threshold: threshold, total_shares: total})
             end) do
        {:reply, {:ok, new_shares},
         %{state | config: committed, unseal_shares: [], unseal_progress: 0}}
      else
        {:error, :durable_failure} ->
          {:reply, {:error, "Vault durable state unavailable"}, unavailable(state)}

        {:error, _} ->
          invalid_attempt(
            state,
            "Legacy recovery blocked: valid shares and trusted authenticated ciphertext required"
          )
      end
    else
      {:reply, {:error, "Vault does not require legacy recovery"}, state}
    end
  end

  def handle_call({:recover_legacy, _, _, _}, _from, state),
    do: {:reply, {:error, "Vault unavailable or not eligible for legacy recovery"}, state}

  defp new_config(
         total,
         threshold,
         data_key \\ Encryption.generate_key(),
         id \\ Ecto.UUID.generate(),
         initialized_at \\ nil
       ) do
    wrapping_key = Encryption.generate_key()
    generation = :crypto.strong_rand_bytes(16)

    with {:ok, shares} <- Shamir.split(wrapping_key, total, threshold, generation) do
      config = %VaultConfig{
        id: id,
        envelope_version: 1,
        share_version: 4,
        share_set_id: generation,
        threshold: threshold,
        total_shares: total,
        initialized_at: initialized_at || DateTime.utc_now() |> DateTime.truncate(:second)
      }

      {:ok, %{config | encrypted_master_key: KeyEnvelope.wrap(data_key, wrapping_key, config)},
       shares}
    end
  end

  defp create_config(repo, config) do
    case repo.transaction(fn ->
           case repo.all(VaultConfig) do
             [] ->
               case repo.insert(
                      VaultConfig.changeset(%VaultConfig{id: config.id}, Map.from_struct(config))
                    ) do
                 {:ok, committed} ->
                   case audit_event("vault_initialized", %{
                          threshold: config.threshold,
                          total_shares: config.total_shares
                        }) do
                     {:ok, _} -> committed
                     _ -> repo.rollback(:durable_failure)
                   end

                 {:error, changeset} ->
                   if Keyword.has_key?(changeset.errors, :id),
                     do: repo.rollback(:already_initialized),
                     else: repo.rollback(:durable_failure)
               end

             _ ->
               repo.rollback(:already_initialized)
           end
         end) do
      {:ok, config} -> {:ok, config}
      {:error, :already_initialized} -> {:error, :already_initialized}
      _ -> {:error, :durable_failure}
    end
  rescue
    _ -> {:error, :durable_failure}
  catch
    :exit, _ -> {:error, :durable_failure}
  end

  defp matching_share?(share, config) do
    Shamir.valid_share?(share) and share.version == config.share_version and
      share.share_set_id == config.share_set_id and share.threshold == config.threshold and
      share.total_shares == config.total_shares and share.secret_length == 32
  end

  defp collect_share(share, state) do
    shares = [share | state.unseal_shares]

    if length(shares) < state.config.threshold do
      {:reply, {:ok, result(state, true, length(shares))},
       %{state | unseal_shares: shares, unseal_progress: length(shares)}}
    else
      with {:ok, wrapping_key} <- Shamir.combine(shares),
           {:ok, data_key} <-
             KeyEnvelope.unwrap(state.config.encrypted_master_key, wrapping_key, state.config),
           {:ok, _} <- audit_event("vault_unsealed", %{}) do
        :telemetry.execute([:secrethub, :vault, :unsealed], %{}, %{})

        {:reply, {:ok, result(state, false, state.config.threshold)},
         %{
           state
           | status: :unsealed,
             master_key: data_key,
             unseal_epoch: make_ref(),
             unseal_shares: [],
             unseal_progress: 0
         }}
      else
        {:error, :audit_unavailable} -> invalid_attempt(state, "Vault audit unavailable")
        _ -> invalid_attempt(state, "Unseal key authentication failed")
      end
    end
  end

  defp invalid_attempt(state, reason),
    do: {:reply, {:error, reason}, %{state | unseal_shares: [], unseal_progress: 0}}

  defp result(state, sealed, progress),
    do: %{
      initialized: true,
      sealed: sealed,
      progress: progress,
      threshold: state.config.threshold
    }

  @impl true
  def format_status(status) do
    Map.new(status, fn
      {:state, %State{status: state}} ->
        {:state, %{vault_state: state, sensitive_material: :redacted}}

      {:state, _} ->
        {:state, :redacted}

      {:message, _} ->
        {:message, :redacted}

      {:log, _} ->
        {:log, []}

      {:reason, _} ->
        {:reason, :redacted}

      entry ->
        entry
    end)
  end

  @impl true
  def terminate(_, state) do
    if Process.alive?(state.task_supervisor), do: Supervisor.stop(state.task_supervisor)
    :ok
  end

  defp begin_load(state) do
    repo = state.repo
    timeout = state.load_timeout
    task = Task.Supervisor.async_nolink(state.task_supervisor, fn -> fetch(repo, timeout) end)
    timer = Process.send_after(self(), {:load_timeout, task.ref}, timeout)
    %{state | load_task: %{ref: task.ref, pid: task.pid, timer: timer}}
  end

  defp fetch(repo, timeout) do
    deadline = System.monotonic_time(:millisecond) + timeout

    case repo.all(VaultConfig, timeout: timeout, pool_timeout: timeout, deadline: deadline) do
      [] -> {:ok, nil}
      [config] -> if valid_config?(config), do: {:ok, config}, else: {:error, :invalid_config}
      _ -> {:error, :invalid_config}
    end
  rescue
    _ -> {:error, :durable_failure}
  catch
    :exit, _ -> {:error, :durable_failure}
  end

  defp apply_load(%{config: nil} = state, {:ok, nil}),
    do: %{state | status: :not_initialized, master_key: nil, unseal_epoch: nil}

  defp apply_load(state, {:ok, config}) when not is_nil(config) do
    if is_nil(state.config) or state.config == config,
      do: %{
        state
        | status: :sealed,
          config: config,
          master_key: nil,
          unseal_epoch: nil,
          unseal_shares: [],
          unseal_progress: 0
      },
      else: unavailable(state)
  end

  defp apply_load(state, _), do: unavailable(state)

  defp durable_config_matches?(state) do
    fetch(state.repo, state.load_timeout) == {:ok, state.config}
  end

  defp validation_snapshot(state),
    do: Map.take(state, [:config, :repo, :dynamic_repo, :load_timeout, :unseal_epoch])

  # Durable reads use the caller's checked-out connection. The server releases
  # its key only after rechecking this exact authenticated unseal session.
  defp validate_unsealed(snapshot, operation, deadline) do
    read_deadline = min(deadline, System.monotonic_time(:millisecond) + snapshot.load_timeout)
    durable = fetch_on_caller(snapshot, read_deadline)
    durable = if remaining(deadline) > 0, do: durable, else: {:error, :durable_failure}

    GenServer.call(
      __MODULE__,
      {:finish_key_validation, snapshot, durable, operation, deadline},
      max(remaining(deadline), 1)
    )
  end

  defp fetch_on_caller(snapshot, deadline) do
    previous_core_repo = Repo.get_dynamic_repo()
    previous_repo = dynamic_repo(snapshot.repo)

    try do
      if snapshot.dynamic_repo, do: snapshot.repo.put_dynamic_repo(snapshot.dynamic_repo)
      durable_match(snapshot.repo, snapshot.config, deadline)
    after
      if previous_repo, do: snapshot.repo.put_dynamic_repo(previous_repo)
      # Configured adapters may route through Core.Repo themselves.
      Repo.put_dynamic_repo(previous_core_repo)
    end
  end

  defp durable_match(repo, config, deadline) do
    expected =
      config
      |> Map.from_struct()
      |> Map.take(VaultConfig.__schema__(:fields))
      |> Map.new(fn
        {field, value}
        when field in [:encrypted_master_key, :share_set_id] and is_binary(value) ->
          {field, "\\x" <> Base.encode16(value, case: :lower)}

        entry ->
          entry
      end)
      |> Jason.encode!()
      |> Base.encode64()

    # Base64 has no SQL quote characters. PostgreSQL compares the complete
    # persisted row, decoding bytea and timestamps using its existing row type.
    sql = """
    SELECT count(*) = 1 AND COALESCE(bool_and(v IS NOT DISTINCT FROM
      jsonb_populate_record(NULL::vault_config,
        convert_from(decode('#{expected}', 'base64'), 'UTF8')::jsonb)), false)
    FROM vault_config AS v
    """

    timeout = remaining(deadline)

    # The text protocol passes this receive timeout to Postgrex even when the
    # caller already owns a transaction connection. Extended queries inherit
    # that transaction's longer checkout timer instead.
    if timeout > 0 do
      case repo.query(sql, [],
             query_type: :text,
             timeout: timeout,
             deadline: deadline,
             log: false
           ) do
        {:ok, %{rows: [["t"]]}} -> {:ok, config}
        _ -> {:error, :durable_failure}
      end
    else
      {:error, :durable_failure}
    end
  rescue
    _ -> {:error, :durable_failure}
  catch
    :exit, _ -> {:error, :durable_failure}
  end

  defp dynamic_repo(repo) do
    if function_exported?(repo, :get_dynamic_repo, 0), do: repo.get_dynamic_repo(), else: nil
  end

  defp remaining(deadline), do: max(deadline - System.monotonic_time(:millisecond), 0)
  defp validation_error(:key), do: {:error, :unavailable}
  defp validation_error(:unseal), do: {:error, "Vault durable state unavailable"}

  defp valid_config?(config) do
    is_integer(config.threshold) and is_integer(config.total_shares) and
      config.threshold >= 1 and config.threshold <= config.total_shares and
      config.total_shares <= 251 and
      is_binary(config.encrypted_master_key) and not is_nil(config.initialized_at) and
      ((legacy?(config) and byte_size(config.encrypted_master_key) == 61 and
          binary_part(config.encrypted_master_key, 0, 1) == <<1>>) or
         (config.envelope_version == 1 and config.share_version == 4 and
            is_binary(config.share_set_id) and byte_size(config.share_set_id) == 16 and
            byte_size(config.encrypted_master_key) == 61 and
            binary_part(config.encrypted_master_key, 0, 1) == <<1>>))
  end

  defp legacy?(nil), do: false

  defp legacy?(config),
    do:
      is_nil(config.envelope_version) and is_nil(config.share_version) and
        is_nil(config.share_set_id)

  defp unavailable(state) do
    Process.send_after(self(), :retry_load, state.retry_interval)

    %{
      state
      | status: :unavailable,
        master_key: nil,
        unseal_epoch: nil,
        unseal_shares: [],
        unseal_progress: 0
    }
  end

  defp audit_event(type, metadata) do
    case Audit.log_event(%{
           event_type: type,
           actor_type: "system",
           actor_id: "vault",
           event_data: metadata,
           access_granted: true,
           response_time_ms: 0
         }) do
      {:ok, _} = result -> result
      _ -> audit_failure(type)
    end
  rescue
    _ -> audit_failure(type)
  catch
    :exit, _ -> audit_failure(type)
  end

  defp audit_failure(type) do
    Logger.error("Vault audit append failed", event_type: type)
    {:error, :audit_unavailable}
  end
end
