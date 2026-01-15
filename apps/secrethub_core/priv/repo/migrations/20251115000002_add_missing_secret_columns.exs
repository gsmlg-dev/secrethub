defmodule SecretHub.Core.Repo.Migrations.AddMissingSecretColumns do
  use Ecto.Migration

  def change do
    # Add columns that don't have foreign key constraints
    alter table(:secrets) do
      add_if_not_exists :name, :string
      add_if_not_exists :engine_type, :string, default: "static"
      add_if_not_exists :rotation_period_hours, :integer, default: 168
      add_if_not_exists :ttl_hours, :integer, default: 24
      add_if_not_exists :next_rotation_at, :utc_datetime
      add_if_not_exists :status, :string, default: "active"
      add_if_not_exists :version_count, :integer, default: 1
      add_if_not_exists :last_version_at, :utc_datetime
    end

    # Add current_version_id column without constraint first
    execute(
      "ALTER TABLE secrets ADD COLUMN IF NOT EXISTS current_version_id UUID",
      "SELECT 1"
    )

    # Create join table for secrets and policies if it doesn't exist
    create_if_not_exists table(:secrets_policies, primary_key: false) do
      add :secret_id, references(:secrets, type: :binary_id, on_delete: :delete_all), null: false
      add :policy_id, references(:policies, type: :binary_id, on_delete: :delete_all), null: false
    end

    create_if_not_exists unique_index(:secrets_policies, [:secret_id, :policy_id])
    create_if_not_exists index(:secrets, [:name])
    create_if_not_exists index(:secrets, [:engine_type])
    create_if_not_exists index(:secrets, [:status])
  end
end
