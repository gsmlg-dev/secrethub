defmodule SecretHub.Human.AccessTokenMigrationTest do
  use ExUnit.Case, async: false

  alias SecretHub.Human.Repo
  alias SecretHub.Human.Repo.Migrations.CreateAccessTokenLifetimes
  alias SecretHub.Human.Schemas.AccessToken

  test "upgrade backfills existing session digests and exact original access expiry" do
    schema = "access_upgrade_" <> Integer.to_string(System.unique_integer([:positive]))

    {:ok, dynamic_repo} =
      Repo.start_link(
        name: nil,
        pool: DBConnection.ConnectionPool,
        pool_size: 2,
        parameters: [search_path: schema]
      )

    Process.unlink(dynamic_repo)
    previous = Repo.get_dynamic_repo()
    Repo.put_dynamic_repo(dynamic_repo)

    on_exit(fn ->
      Repo.put_dynamic_repo(dynamic_repo)
      Repo.query!("DROP SCHEMA IF EXISTS #{schema} CASCADE", [], log: false)
      GenServer.stop(dynamic_repo)
      Repo.put_dynamic_repo(previous)
    end)

    Repo.query!("CREATE SCHEMA #{schema}", [], log: false)

    Repo.query!(
      """
      CREATE TABLE human_sessions (
        id uuid PRIMARY KEY,
        access_digest bytea NOT NULL,
        expires_at timestamp(6) NOT NULL
      )
      """,
      [],
      log: false
    )

    session_id = Ecto.UUID.generate()
    digest = :crypto.hash(:sha256, "existing-unpersisted-access-token")
    expiry = DateTime.add(DateTime.utc_now(), 60)

    Repo.query!(
      "INSERT INTO human_sessions (id, access_digest, expires_at) VALUES ($1, $2, $3)",
      [Ecto.UUID.dump!(session_id), digest, DateTime.to_naive(expiry)],
      log: false
    )

    unless Code.ensure_loaded?(CreateAccessTokenLifetimes) do
      Code.require_file(
        Application.app_dir(
          :secrethub_human,
          "priv/repo/migrations/20261008000900_create_access_token_lifetimes.exs"
        )
      )
    end

    assert :ok =
             Ecto.Migrator.up(Repo, 20_261_008_000_900, CreateAccessTokenLifetimes,
               prefix: schema,
               log: false
             )

    row = Repo.get!(AccessToken, digest, prefix: schema)
    assert row.session_id == session_id
    assert row.expires_at == expiry

    Repo.query!("DELETE FROM human_sessions WHERE id = $1", [Ecto.UUID.dump!(session_id)],
      log: false
    )

    assert Repo.get(AccessToken, digest, prefix: schema) == nil
  end
end
