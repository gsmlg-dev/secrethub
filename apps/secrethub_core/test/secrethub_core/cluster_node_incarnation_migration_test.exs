migration_path =
  Path.expand(
    "../../priv/repo/migrations/20260716000008_add_cluster_node_incarnations.exs",
    __DIR__
  )

Code.require_file(migration_path)

defmodule SecretHub.Core.ClusterNodeIncarnationMigrationTest do
  use SecretHub.Core.DataCase, async: false

  alias SecretHub.Core.Repo
  alias SecretHub.Core.Repo.Migrations.AddClusterNodeIncarnations

  test "the migrated column is non-null and supplies a UUID default" do
    assert %Postgrex.Result{
             rows: [["NO", column_default]]
           } =
             Repo.query!("""
             SELECT is_nullable, column_default
             FROM information_schema.columns
             WHERE table_schema = 'public'
               AND table_name = 'cluster_nodes'
               AND column_name = 'incarnation_id'
             """)

    assert column_default =~ "gen_random_uuid()"

    node_id = "migration-default-#{System.unique_integer([:positive])}"

    assert %Postgrex.Result{rows: [[incarnation_id]]} =
             Repo.query!(
               """
               INSERT INTO cluster_nodes (
                 id, node_id, hostname, status, last_seen_at, started_at,
                 inserted_at, updated_at
               )
               VALUES (
                 gen_random_uuid(), $1, 'migration-probe', 'shutdown', NOW(), NOW(),
                 NOW(), NOW()
               )
               RETURNING incarnation_id
               """,
               [node_id]
             )

    assert {:ok, _uuid} = Ecto.UUID.cast(incarnation_id)
  end

  test "the migration backfills existing null incarnations with UUIDs" do
    Repo.query!("""
    CREATE TEMPORARY TABLE cluster_nodes (
      incarnation_id uuid
    ) ON COMMIT DROP
    """)

    Repo.query!("INSERT INTO cluster_nodes (incarnation_id) VALUES (NULL)")
    Repo.query!(AddClusterNodeIncarnations.backfill_sql())

    assert %Postgrex.Result{rows: [[incarnation_id]]} =
             Repo.query!("SELECT incarnation_id FROM cluster_nodes")

    assert {:ok, _uuid} = Ecto.UUID.cast(incarnation_id)
  end
end
