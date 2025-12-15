defmodule SecretHub.Core.Repo.Migrations.AddClusterNodesTable do
  use Ecto.Migration

  def change do
    create table(:cluster_nodes, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :node_id, :string, null: false
      add :hostname, :string, null: false
      add :status, :string, null: false, default: "starting"
      add :leader, :boolean, default: false
      add :last_seen_at, :utc_datetime, null: false
      add :started_at, :utc_datetime, null: false
      add :sealed, :boolean, default: true
      add :initialized, :boolean, default: false
      add :version, :string
      add :metadata, :map, default: %{}

      timestamps(type: :utc_datetime)
    end

    create unique_index(:cluster_nodes, [:node_id])
    create index(:cluster_nodes, [:status])
    create index(:cluster_nodes, [:leader])
    create index(:cluster_nodes, [:last_seen_at])

    # Create cluster state table for global cluster metadata
    create table(:cluster_state, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :initialized, :boolean, default: false, null: false
      add :init_time, :utc_datetime
      add :threshold, :integer
      add :shares, :integer
      add :metadata, :map, default: %{}

      timestamps(type: :utc_datetime)
    end

    # Insert initial cluster state record
    execute(
      "INSERT INTO cluster_state (id, initialized, inserted_at, updated_at) VALUES (gen_random_uuid(), false, NOW(), NOW())",
      "DELETE FROM cluster_state"
    )
  end
end
