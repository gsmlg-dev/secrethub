defmodule SecretHub.Core.AuditHashVersionMigrationTest do
  use SecretHub.Core.DataCase, async: false

  alias SecretHub.Core.Repo

  test "hash_version is a non-null smallint with v1 default on the parent" do
    assert %Postgrex.Result{
             rows: [["smallint", "NO", default]]
           } =
             Repo.query!("""
             SELECT data_type, is_nullable, column_default
             FROM information_schema.columns
             WHERE table_schema = 'public'
               AND table_name = 'audit_logs'
               AND column_name = 'hash_version'
             """)

    assert default =~ "1"

    assert %Postgrex.Result{rows: [[0]]} =
             Repo.query!("""
             SELECT COUNT(*)
             FROM audit_logs
             WHERE hash_version IS DISTINCT FROM 1
             """)
  end

  test "the default and non-null constraint propagate to an actual audit partition" do
    event_id = Ecto.UUID.generate()

    assert %Postgrex.Result{rows: [[1, partition_name]]} =
             Repo.query!(
               """
               INSERT INTO audit_logs (event_id, sequence_number, timestamp, event_type)
               VALUES ($1, 9000000000, NOW(), 'system.sealed')
               RETURNING hash_version, tableoid::regclass::text
               """,
               [Ecto.UUID.dump!(event_id)]
             )

    assert partition_name =~ ~r/\Aaudit_logs_y\d{4}m\d{2}\z/

    assert %Postgrex.Result{rows: [["smallint", true]]} =
             Repo.query!(
               """
               SELECT format_type(attribute.atttypid, attribute.atttypmod), attribute.attnotnull
               FROM pg_attribute AS attribute
               WHERE attribute.attrelid = to_regclass($1::text)
                 AND attribute.attname = 'hash_version'
                 AND NOT attribute.attisdropped
               """,
               [partition_name]
             )
  end
end
