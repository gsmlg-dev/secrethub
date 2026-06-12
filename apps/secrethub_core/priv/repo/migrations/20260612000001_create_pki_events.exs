defmodule SecretHub.Core.Repo.Migrations.CreatePkiEvents do
  use Ecto.Migration

  def change do
    create table(:pki_events, primary_key: false) do
      add :id, :string, primary_key: true, null: false
      add :event_type, :string, null: false
      add :timestamp, :utc_datetime_usec, null: false
      add :sequence, :bigint, null: false
      add :ca_id, :string, null: false
      add :metadata, :jsonb, null: false, default: fragment("'{}'::jsonb")
      add :actor, :string
      add :correlation_id, :string
      add :inserted_at, :utc_datetime_usec, null: false, default: fragment("NOW()")
    end

    create index(:pki_events, [:ca_id, :sequence], name: :pki_events_ca_id_sequence_idx)
    create index(:pki_events, [:event_type, :timestamp], name: :pki_events_event_type_timestamp_idx)
    create index(:pki_events, [:timestamp])
    create index(:pki_events, [:correlation_id])

    execute(
      "CREATE INDEX pki_events_metadata_gin_idx ON pki_events USING GIN (metadata)",
      "DROP INDEX pki_events_metadata_gin_idx"
    )

    execute(
      "CREATE INDEX pki_events_metadata_serial_idx ON pki_events ((metadata->>'serial'))",
      "DROP INDEX pki_events_metadata_serial_idx"
    )

    create unique_index(:pki_events, [:ca_id, :sequence], name: :pki_events_ca_sequence_unique)
  end
end
