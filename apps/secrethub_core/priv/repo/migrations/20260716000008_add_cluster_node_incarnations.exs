defmodule SecretHub.Core.Repo.Migrations.AddClusterNodeIncarnations do
  use Ecto.Migration

  def up do
    alter table(:cluster_nodes) do
      add(:incarnation_id, :uuid, default: fragment("gen_random_uuid()"))
    end

    execute("""
    UPDATE cluster_nodes
    SET incarnation_id = gen_random_uuid()
    WHERE incarnation_id IS NULL
    """)

    alter table(:cluster_nodes) do
      modify(:incarnation_id, :uuid, null: false)
    end
  end

  def down do
    alter table(:cluster_nodes) do
      remove(:incarnation_id)
    end
  end
end
