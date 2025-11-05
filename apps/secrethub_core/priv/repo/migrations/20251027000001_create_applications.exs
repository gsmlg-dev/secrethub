defmodule SecretHub.Core.Repo.Migrations.CreateApplications do
  use Ecto.Migration

  def change do
    # Create applications table
    create table(:applications, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :description, :text
      # TODO: Add foreign key constraint when agents table is created
      add :agent_id, :binary_id, null: false
      add :status, :string, null: false, default: "active"
      add :policies, {:array, :string}, default: []
      add :metadata, :map, default: %{}

      timestamps(type: :utc_datetime)
    end

    create unique_index(:applications, [:name])
    create index(:applications, [:agent_id])
    create index(:applications, [:status])

    # Create app_bootstrap_tokens table
    create table(:app_bootstrap_tokens, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :app_id, references(:applications, type: :binary_id, on_delete: :delete_all), null: false
      add :token_hash, :string, null: false
      add :used, :boolean, null: false, default: false
      add :used_at, :utc_datetime
      add :expires_at, :utc_datetime, null: false

      timestamps(type: :utc_datetime, updated_at: false)
    end

    create unique_index(:app_bootstrap_tokens, [:token_hash])
    create index(:app_bootstrap_tokens, [:app_id])
    create index(:app_bootstrap_tokens, [:used])
    create index(:app_bootstrap_tokens, [:expires_at])

    # Create app_certificates table
    create table(:app_certificates, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :app_id, references(:applications, type: :binary_id, on_delete: :delete_all), null: false

      add :certificate_id, references(:certificates, type: :binary_id, on_delete: :delete_all),
        null: false

      add :issued_at, :utc_datetime, null: false
      add :expires_at, :utc_datetime, null: false
      add :revoked_at, :utc_datetime
      add :revocation_reason, :string

      timestamps(type: :utc_datetime, updated_at: false)
    end

    create unique_index(:app_certificates, [:app_id, :certificate_id])
    create index(:app_certificates, [:app_id])
    create index(:app_certificates, [:certificate_id])
    create index(:app_certificates, [:revoked_at])
  end
end
