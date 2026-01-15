defmodule SecretHub.Core.Repo.Migrations.CreateAgents do
  use Ecto.Migration

  def change do
    create table(:agents, primary_key: false) do
      add :id, :binary_id, primary_key: true

      # Agent identification
      add :agent_id, :string, null: false
      add :name, :string
      add :description, :string

      # Bootstrap credentials
      add :role_id, :string
      add :secret_id, :string

      # Authentication status
      add :status, :string, default: "pending_bootstrap"
      add :authenticated_at, :utc_datetime
      add :last_seen_at, :utc_datetime
      add :last_heartbeat_at, :utc_datetime

      # Network information
      add :ip_address, :string
      add :hostname, :string
      add :user_agent, :string

      # Certificate binding
      add :certificate_id, references(:certificates, type: :binary_id, on_delete: :nilify_all)

      # Configuration and metadata
      add :config, :map, default: %{}
      add :metadata, :map, default: %{}

      # Suspension/revocation
      add :suspended_reason, :string
      add :revoked_reason, :string

      timestamps(type: :utc_datetime)
    end

    create unique_index(:agents, [:agent_id])
    create index(:agents, [:status])
    create index(:agents, [:certificate_id])
    create index(:agents, [:last_heartbeat_at])

    # Create join table for agents and policies
    create table(:agents_policies, primary_key: false) do
      add :agent_id, references(:agents, type: :binary_id, on_delete: :delete_all), null: false
      add :policy_id, references(:policies, type: :binary_id, on_delete: :delete_all), null: false
    end

    create unique_index(:agents_policies, [:agent_id, :policy_id])
  end
end
