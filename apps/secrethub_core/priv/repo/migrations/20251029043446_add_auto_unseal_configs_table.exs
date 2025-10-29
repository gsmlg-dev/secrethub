defmodule SecretHub.Core.Repo.Migrations.AddAutoUnsealConfigsTable do
  use Ecto.Migration

  def change do
    create table(:auto_unseal_configs, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :provider, :string, null: false
      add :kms_key_id, :string, null: false
      add :region, :string
      add :encrypted_unseal_keys, {:array, :text}, null: false
      add :active, :boolean, default: true, null: false
      add :max_retries, :integer, default: 3, null: false
      add :retry_delay_ms, :integer, default: 5000, null: false
      add :metadata, :map, default: %{}

      timestamps(type: :utc_datetime)
    end

    create index(:auto_unseal_configs, [:active])
    create index(:auto_unseal_configs, [:provider])
  end
end
