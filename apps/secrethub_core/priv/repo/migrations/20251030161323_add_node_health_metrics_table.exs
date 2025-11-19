defmodule SecretHub.Core.Repo.Migrations.AddNodeHealthMetricsTable do
  use Ecto.Migration

  def change do
    create table(:node_health_metrics, primary_key: false) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :node_id, :string, null: false
      add :timestamp, :utc_datetime, null: false
      add :health_status, :string, null: false
      add :cpu_percent, :float
      add :memory_percent, :float
      add :database_latency_ms, :float
      add :active_connections, :integer
      add :vault_sealed, :boolean
      add :vault_initialized, :boolean
      add :last_heartbeat_at, :utc_datetime
      add :metadata, :map, default: %{}

      timestamps(type: :utc_datetime)
    end

    # Index for querying by node_id and timestamp
    create index(:node_health_metrics, [:node_id, :timestamp])

    # Index for querying recent metrics
    create index(:node_health_metrics, [:timestamp])

    # Foreign key to cluster_nodes
    create index(:node_health_metrics, [:node_id])
  end
end
