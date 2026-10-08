defmodule SecretHub.Human.Repo.Migrations.CreateHumanAuditOutbox do
  use Ecto.Migration

  def change do
    create table(:human_audit_outbox, primary_key: false) do
      add(:id, :uuid, primary_key: true)
      add(:event_type, :string, null: false)
      add(:actor_id, :uuid)
      add(:metadata, :map, null: false)
      add(:delivered_at, :utc_datetime_usec)
      timestamps(type: :utc_datetime_usec)
    end

    create(index(:human_audit_outbox, [:delivered_at]))
  end
end
