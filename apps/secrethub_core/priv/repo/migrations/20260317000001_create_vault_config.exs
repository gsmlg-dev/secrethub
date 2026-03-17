defmodule SecretHub.Core.Repo.Migrations.CreateVaultConfig do
  use Ecto.Migration

  def change do
    create table(:vault_config, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :encrypted_master_key, :binary, null: false
      add :threshold, :integer, null: false
      add :total_shares, :integer, null: false
      add :initialized_at, :utc_datetime, null: false

      timestamps(type: :utc_datetime)
    end

    # Only one vault config row should ever exist
    create unique_index(:vault_config, [:id],
      name: :vault_config_singleton,
      comment: "Ensures only one vault configuration exists"
    )
  end
end
