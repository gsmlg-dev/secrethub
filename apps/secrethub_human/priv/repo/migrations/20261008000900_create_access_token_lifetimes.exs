defmodule SecretHub.Human.Repo.Migrations.CreateAccessTokenLifetimes do
  use Ecto.Migration

  def change do
    create table(:human_access_tokens, primary_key: false) do
      add(:digest, :binary, primary_key: true)

      add(:session_id, references(:human_sessions, type: :uuid, on_delete: :delete_all),
        null: false
      )

      add(:expires_at, :utc_datetime_usec, null: false)
    end

    create(
      constraint(:human_access_tokens, :access_digest_length, check: "octet_length(digest) = 32")
    )

    create(index(:human_access_tokens, [:session_id]))
    create(index(:human_access_tokens, [:expires_at]))

    execute(
      """
      INSERT INTO human_access_tokens (digest, session_id, expires_at)
      SELECT access_digest, id, expires_at FROM human_sessions
      """,
      "DELETE FROM human_access_tokens"
    )
  end
end
