defmodule SecretHub.Core.Vault.MigrationTest do
  use SecretHub.Core.DataCase, async: false
  alias SecretHub.Core.Repo.Migrations.BindVaultKeyEnvelope
  alias SecretHub.Core.Vault.SealState
  alias SecretHub.Shared.Schemas.VaultConfig
  @version 20_261_001_000_001

  Code.require_file(
    "../../../priv/repo/migrations/20261001000001_bind_vault_key_envelope.exs",
    __DIR__
  )

  test "downgrade refuses to discard authenticated generation metadata" do
    if pid = Process.whereis(SealState), do: GenServer.stop(pid)
    {:ok, _} = SealState.start_link()
    await_loaded(100)
    {:ok, _} = SealState.initialize(5, 3)
    GenServer.stop(SealState)
    before = Repo.one!(VaultConfig)

    assert_raise Postgrex.Error, ~r/Vault envelope downgrade blocked/, fn ->
      Ecto.Migrator.down(Repo, @version, BindVaultKeyEnvelope, log: false, migration_lock: false)
    end

    assert Repo.one!(VaultConfig) == before
  end

  test "bare legacy rows survive schema downgrade and reupgrade unchanged" do
    if pid = Process.whereis(SealState), do: GenServer.stop(pid)

    config =
      Repo.insert!(%VaultConfig{
        encrypted_master_key: <<1, 0::480>>,
        threshold: 3,
        total_shares: 5,
        initialized_at: DateTime.utc_now() |> DateTime.truncate(:second)
      })

    assert :ok =
             Ecto.Migrator.down(Repo, @version, BindVaultKeyEnvelope,
               log: false,
               migration_lock: false
             )

    assert %{rows: [[id, blob]]} =
             Ecto.Adapters.SQL.query!(
               Repo,
               "SELECT id::text, encrypted_master_key FROM vault_config",
               []
             )

    assert id == config.id
    assert blob == config.encrypted_master_key

    assert :ok =
             Ecto.Migrator.up(Repo, @version, BindVaultKeyEnvelope,
               log: false,
               migration_lock: false
             )

    assert Repo.one!(VaultConfig) == config
  end

  test "multiple preexisting legacy rows block migration without deleting either" do
    if pid = Process.whereis(SealState), do: GenServer.stop(pid)

    assert :ok =
             Ecto.Migrator.down(Repo, @version, BindVaultKeyEnvelope,
               log: false,
               migration_lock: false
             )

    for _ <- 1..2 do
      Ecto.Adapters.SQL.query!(
        Repo,
        "INSERT INTO vault_config (id, encrypted_master_key, threshold, total_shares, initialized_at, inserted_at, updated_at) VALUES ($1, $2, 3, 5, now(), now(), now())",
        [Ecto.UUID.dump!(Ecto.UUID.generate()), <<1, 0::480>>]
      )
    end

    assert_raise Postgrex.Error, ~r/vault_config_singleton/, fn ->
      Ecto.Migrator.up(Repo, @version, BindVaultKeyEnvelope, log: false, migration_lock: false)
    end

    assert %{rows: [[2]]} =
             Ecto.Adapters.SQL.query!(Repo, "SELECT count(*) FROM vault_config", [])
  end

  defp await_loaded(0), do: flunk("Vault did not finish loading")

  defp await_loaded(remaining) do
    if SealState.status().state == :loading do
      Process.sleep(5)
      await_loaded(remaining - 1)
    end
  end
end
