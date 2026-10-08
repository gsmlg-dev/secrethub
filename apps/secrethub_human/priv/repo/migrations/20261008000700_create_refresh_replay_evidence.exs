defmodule SecretHub.Human.Repo.Migrations.CreateRefreshReplayEvidence do
  use Ecto.Migration

  def change do
    create table(:human_used_refresh_tokens, primary_key: false) do
      add(:digest, :binary, primary_key: true)

      add(:session_id, references(:human_sessions, type: :uuid, on_delete: :delete_all),
        null: false
      )

      add(:expires_at, :utc_datetime_usec, null: false)
    end

    create(index(:human_used_refresh_tokens, [:expires_at]))
  end
end
