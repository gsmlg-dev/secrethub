defmodule SecretHub.Core.Vault.CallerValidationTest do
  use ExUnit.Case, async: false
  alias SecretHub.Core.{Health, Repo, RuntimeDatabaseFixture, VaultTestHelpers}
  alias SecretHub.Core.Vault.SealState
  alias SecretHub.Shared.Schemas.VaultConfig

  defmodule ControlledRepo do
    def all(query, opts \\ []) do
      RuntimeDatabaseFixture.VaultRepo.all(query, opts)
    end

    def query(sql, params, opts) do
      control = Agent.get_and_update(__MODULE__, fn mode -> {mode, :normal} end)

      case control do
        :normal ->
          RuntimeDatabaseFixture.VaultRepo.query(sql, params, opts)

        {:result, value} ->
          respond(value)

        {:pause, owner, value} ->
          send(owner, {:validation_paused, self()})
          receive do: (:release_validation -> respond(value))
      end
    end

    defp respond(:raise), do: raise(DBConnection.ConnectionError, message: "private failure")
    defp respond(:exit), do: exit(:database_timeout)
    defp respond(value), do: value
    defdelegate transaction(fun), to: RuntimeDatabaseFixture.VaultRepo
    defdelegate insert(changeset), to: RuntimeDatabaseFixture.VaultRepo
    defdelegate rollback(reason), to: RuntimeDatabaseFixture.VaultRepo
  end

  setup_all do
    RuntimeDatabaseFixture.prepare_template()
  end

  setup context do
    RuntimeDatabaseFixture.setup(context, default_repo: context[:default_repo] || false)

    start_supervised!(%{
      id: ControlledRepo,
      start: {Agent, :start_link, [fn -> :normal end, [name: ControlledRepo]]}
    })

    repo = if context[:default_repo], do: Repo, else: ControlledRepo
    start_supervised!({SealState, repo: repo, retry_interval: 10})
    VaultTestHelpers.await_vault_state(:not_initialized)
    {:ok, shares} = SealState.initialize(3, 2)
    Enum.each(Enum.take(shares, 2), &SealState.unseal/1)
    {:ok, key} = SealState.get_master_key()
    %{shares: shares, key: key, config: Repo.one!(VaultConfig)}
  end

  test "all eight checked-out transactions can validate the Vault without a ninth connection", %{
    key: key
  } do
    owner = self()
    dynamic_repo = Repo.get_dynamic_repo()

    tasks =
      for _ <- 1..8 do
        Task.async(fn ->
          Repo.put_dynamic_repo(dynamic_repo)

          Repo.transaction(fn ->
            Repo.query!("SELECT 1")
            send(owner, {:checked_out, self()})
            receive do: (:validate -> SealState.get_master_key())
          end)
        end)
      end

    for _ <- tasks, do: assert_receive({:checked_out, _}, 2_000)
    Enum.each(tasks, &send(&1.pid, :validate))
    for task <- tasks, do: assert(Task.await(task, 10_000) == {:ok, {:ok, key}})
  end

  test "validation leaves status responsive and restores adapter caller routing", %{
    key: key
  } do
    owner = self()
    Agent.update(ControlledRepo, fn _ -> {:pause, owner, {:ok, %{rows: [["t"]]}}} end)
    task = Task.async(fn -> SealState.get_master_key() end)
    assert_receive {:validation_paused, caller}, 2_000
    assert %{state: :unsealed} = GenServer.call(SealState, :status, 200)
    send(caller, :release_validation)
    assert Task.await(task) == {:ok, key}
    Repo.put_dynamic_repo(:caller_selected_wrong_database)
    assert SealState.get_master_key() == {:ok, key}
    assert Repo.get_dynamic_repo() == :caller_selected_wrong_database
  end

  for outcome <- [:success, :failure] do
    test "stale #{outcome} cannot release a key or invalidate a same-config re-unseal", %{
      shares: shares,
      key: key
    } do
      owner = self()
      paused_result = if unquote(outcome) == :success, do: {:ok, %{rows: [["t"]]}}, else: :raise
      Agent.update(ControlledRepo, fn _ -> {:pause, owner, paused_result} end)
      task = Task.async(fn -> SealState.get_master_key() end)
      assert_receive {:validation_paused, caller}, 2_000
      Agent.update(ControlledRepo, fn _ -> {:result, {:ok, %{rows: [["f"]]}}} end)
      assert {:error, :unavailable} = SealState.get_master_key()
      VaultTestHelpers.await_vault_state(:sealed)
      Enum.each(Enum.take(shares, 2), &SealState.unseal/1)
      assert SealState.get_master_key() == {:ok, key}
      send(caller, :release_validation)
      assert Task.await(task) == {:error, :unavailable}
      assert %{state: :unsealed} = SealState.status()
      assert SealState.get_master_key() == {:ok, key}
    end
  end

  for outcome <- [:missing, :malformed, :changed, :raise, :exit] do
    test "current-session #{outcome} durable validation wipes the key and session", %{
      config: config
    } do
      case unquote(outcome) do
        :missing ->
          Repo.delete_all(VaultConfig)

        :malformed ->
          Repo.update_all(VaultConfig, set: [encrypted_master_key: <<2, 0::480>>])

        :changed ->
          Repo.update_all(VaultConfig,
            set: [initialized_at: DateTime.add(config.initialized_at, 1)]
          )

        other ->
          Agent.update(ControlledRepo, fn _ -> {:result, other} end)
      end

      assert {:error, :unavailable} = SealState.get_master_key()
      assert %{master_key: nil, unseal_epoch: nil} = :sys.get_state(SealState)
    end
  end

  test "redundant unseal and health checks validate on the caller connection", %{
    shares: [share | _]
  } do
    Repo.transaction(fn ->
      assert {:ok, %{sealed: false}} = SealState.unseal(share)
      assert {:ok, %{sealed: false}} = Health.check_seal_status()
    end)
  end

  @tag default_repo: true
  test "caller cannot redirect an Ecto repo's authoritative database", %{key: key} do
    Repo.put_dynamic_repo(:caller_selected_wrong_database)
    assert SealState.get_master_key() == {:ok, key}
    assert Repo.get_dynamic_repo() == :caller_selected_wrong_database
  end

  test "health's bounded database timeout fails closed" do
    owner = self()
    dynamic_repo = Repo.get_dynamic_repo()

    locker =
      Task.async(fn ->
        Repo.put_dynamic_repo(dynamic_repo)

        Repo.transaction(fn ->
          Repo.query!("LOCK TABLE vault_config IN ACCESS EXCLUSIVE MODE")
          send(owner, :vault_config_locked)
          receive do: (:release_lock -> :ok)
        end)
      end)

    assert_receive :vault_config_locked, 2_000
    started = System.monotonic_time(:millisecond)
    assert {:error, _} = Health.check_seal_status()
    assert System.monotonic_time(:millisecond) - started < 1_000
    assert %{master_key: nil, unseal_epoch: nil} = :sys.get_state(SealState)
    send(locker.pid, :release_lock)
    assert Task.await(locker) == {:ok, :ok}
  end

  test "health's deadline also bounds a query inside an existing transaction" do
    owner = self()
    dynamic_repo = Repo.get_dynamic_repo()
    Repo.query!("CREATE TABLE vault_validation_rollback_probe (id integer)")

    locker =
      Task.async(fn ->
        Repo.put_dynamic_repo(dynamic_repo)

        Repo.transaction(fn ->
          Repo.query!("LOCK TABLE vault_config IN ACCESS EXCLUSIVE MODE")
          send(owner, :vault_config_locked)
          receive do: (:release_lock -> :ok)
        end)
      end)

    assert_receive :vault_config_locked, 2_000

    task =
      Task.async(fn ->
        Repo.put_dynamic_repo(dynamic_repo)

        try do
          Repo.transaction(fn ->
            Repo.query!("INSERT INTO vault_validation_rollback_probe VALUES (1)")
            send(owner, :health_started)
            Health.check_seal_status()
          end)
        rescue
          error in DBConnection.ConnectionError -> {:error, error}
        catch
          :exit, reason -> {:error, reason}
        end
      end)

    assert_receive :health_started, 2_000
    # Release the lock after the bounded observation, including on failure, so
    # this regression cannot leave its own database transactions running.
    yielded = Task.yield(task, 1_000)
    send(locker.pid, :release_lock)
    result = yielded || {:ok, Task.await(task, 20_000)}
    assert Task.await(locker) == {:ok, :ok}
    assert yielded != nil
    assert {:ok, {:error, _}} = result
    assert %{rows: [[0]]} = Repo.query!("SELECT count(*) FROM vault_validation_rollback_probe")
    assert %{master_key: nil, unseal_epoch: nil} = :sys.get_state(SealState)
  end

  test "expired finalization cannot release a key" do
    assert {:validate_unsealed, snapshot} = GenServer.call(SealState, :prepare_key_validation)
    refute Map.has_key?(snapshot, :master_key)
    deadline = System.monotonic_time(:millisecond) - 1

    assert {:error, :unavailable} =
             GenServer.call(
               SealState,
               {:finish_key_validation, snapshot, {:ok, snapshot.config}, :key, deadline}
             )

    assert %{master_key: nil, unseal_epoch: nil} = :sys.get_state(SealState)
  end

  test "durable comparison includes identity, binary fields, parameters and timestamps", %{
    config: config,
    shares: shares,
    key: key
  } do
    changes = [
      id: Ecto.UUID.generate(),
      encrypted_master_key: <<2, 0::480>>,
      share_set_id: :crypto.strong_rand_bytes(16),
      threshold: 1,
      total_shares: 4,
      initialized_at: DateTime.add(config.initialized_at, 1),
      inserted_at: DateTime.add(config.inserted_at, 1),
      updated_at: DateTime.add(config.updated_at, 1)
    ]

    for {field, changed} <- changes do
      Repo.update_all(VaultConfig, set: [{field, changed}])
      assert {:error, :unavailable} = SealState.get_master_key(), "changed #{field}"
      Repo.update_all(VaultConfig, set: [{field, Map.fetch!(config, field)}])
      VaultTestHelpers.await_vault_state(:sealed)
      Enum.each(Enum.take(shares, 2), &SealState.unseal/1)
      assert SealState.get_master_key() == {:ok, key}
    end
  end
end
