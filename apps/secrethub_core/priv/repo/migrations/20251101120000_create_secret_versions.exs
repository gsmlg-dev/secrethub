defmodule SecretHub.Core.Repo.Migrations.CreateSecretVersions do
  use Ecto.Migration

  def change do
    # Create secret_versions table to track historical versions
    create table(:secret_versions, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :secret_id, references(:secrets, type: :binary_id, on_delete: :delete_all), null: false
      add :version_number, :integer, null: false
      add :encrypted_data, :binary, null: false
      add :metadata, :map, default: %{}
      add :description, :text
      add :created_by, :string
      add :change_description, :text
      add :archived_at, :utc_datetime, null: false

      timestamps(type: :utc_datetime, updated_at: false)
    end

    create index(:secret_versions, [:secret_id])
    create unique_index(:secret_versions, [:secret_id, :version_number])
    create index(:secret_versions, [:archived_at])

    # Add version tracking fields to secrets table
    alter table(:secrets) do
      add :current_version_id, references(:secret_versions, type: :binary_id, on_delete: :nilify_all)
      add :version_count, :integer, default: 1, null: false
      add :last_version_at, :utc_datetime
    end

    create index(:secrets, [:current_version_id])
    create index(:secrets, [:last_version_at])
  end
end
