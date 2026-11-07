defmodule SecretHub.Core.Repo.StyxMigration do
  @moduledoc false

  import Ecto.Migration, only: [execute: 1, repo: 0]

  @legacy_marker "secrethub: migrated from Oban v14"

  def install(schema), do: Styx.Migration.up(prefix: schema || "public")

  def uninstall(schema) do
    schema = schema || "public"
    reject_dual_storage!(schema)

    if table_exists?(schema, "styx_jobs") do
      Styx.Migration.down(prefix: schema, version: 1)
    else
      # Full rollback after the transition restores the original Oban objects.
      quoted = quote_identifier(schema)
      execute("DROP TABLE IF EXISTS #{quoted}.oban_peers")
      execute("DROP TABLE IF EXISTS #{quoted}.oban_jobs")
      execute("DROP TYPE IF EXISTS #{quoted}.oban_job_state")
    end
  end

  def upgrade(schema) do
    schema = schema || "public"
    reject_dual_storage!(schema)

    if table_exists?(schema, "oban_jobs") do
      unless table_comment(schema, "oban_jobs") == "14" do
        raise Ecto.MigrationError, "Oban schema must be version 14 before migrating to Styx"
      end

      quoted = quote_identifier(schema)

      # Rename rather than copy: retain job history, peers, index/sequence OIDs,
      # ID sequence ownership and its last value. Physical index names may stay Oban.
      execute("ALTER TABLE #{quoted}.oban_jobs RENAME TO styx_jobs")
      execute("ALTER TABLE #{quoted}.oban_peers RENAME TO styx_peers")
      execute("ALTER TYPE #{quoted}.oban_job_state RENAME TO styx_job_state")
      execute("COMMENT ON TABLE #{quoted}.styx_jobs IS '1'")

      execute("""
      CREATE FUNCTION #{quoted}.styx_wrap_id(value bigint) RETURNS int AS $$
      BEGIN
        RETURN (value % 2147483647)::int;
      END;
      $$ LANGUAGE plpgsql IMMUTABLE;
      """)

      # The new function carries provenance without overwriting peer comments.
      execute("COMMENT ON FUNCTION #{quoted}.styx_wrap_id(bigint) IS '#{@legacy_marker}'")
    end
  end

  def rollback(schema) do
    schema = schema || "public"
    reject_dual_storage!(schema)

    if migrated_from_oban?(schema) do
      quoted = quote_identifier(schema)
      execute("DROP FUNCTION #{quoted}.styx_wrap_id(bigint)")
      execute("ALTER TABLE #{quoted}.styx_jobs RENAME TO oban_jobs")
      execute("ALTER TABLE #{quoted}.styx_peers RENAME TO oban_peers")
      execute("ALTER TYPE #{quoted}.styx_job_state RENAME TO oban_job_state")
      execute("COMMENT ON TABLE #{quoted}.oban_jobs IS '14'")
    end
  end

  defp reject_dual_storage!(schema) do
    if table_exists?(schema, "oban_jobs") and table_exists?(schema, "styx_jobs") do
      raise Ecto.MigrationError,
            "both oban_jobs and styx_jobs exist; refusing to overwrite queued jobs"
    end
  end

  defp table_exists?(schema, name) do
    %{rows: [[exists?]]} =
      repo().query!(
        "SELECT EXISTS (SELECT 1 FROM pg_tables WHERE schemaname = $1 AND tablename = $2)",
        [schema, name]
      )

    exists?
  end

  defp table_comment(schema, name) do
    %{rows: [[comment]]} =
      repo().query!(
        "SELECT obj_description(to_regclass(format('%I.%I', $1::text, $2::text)), 'pg_class')",
        [
          schema,
          name
        ]
      )

    comment
  end

  defp migrated_from_oban?(schema) do
    %{rows: [[comment]]} =
      repo().query!(
        "SELECT obj_description(to_regprocedure(format('%I.styx_wrap_id(bigint)', $1::text)), 'pg_proc')",
        [schema]
      )

    comment == @legacy_marker
  end

  defp quote_identifier(value), do: "\"" <> String.replace(value, "\"", "\"\"") <> "\""
end
