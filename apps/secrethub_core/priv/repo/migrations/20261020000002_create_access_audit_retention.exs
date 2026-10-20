defmodule SecretHub.Core.Repo.Migrations.CreateAccessAuditRetention do
  use Ecto.Migration

  def up do
    create table(:access_audit_event_tombstones, primary_key: false) do
      add(:namespace, :text, null: false)
      add(:producer_id, :uuid, null: false)
      add(:event_id, :uuid, null: false)
      add(:producer_sequence, :bigint, null: false)
      add(:request_id, :uuid, null: false)
      add(:canonical_digest, :text, null: false)
      add(:audit_sequence_number, :bigint, null: false)
    end

    create(unique_index(:access_audit_event_tombstones, [:namespace, :producer_id, :event_id]))

    create(
      unique_index(:access_audit_event_tombstones, [:namespace, :producer_id, :producer_sequence],
        name: :access_audit_tombstone_sequence_index
      )
    )

    create table(:access_audit_expired_requests, primary_key: false) do
      add(:namespace, :text, null: false)
      add(:request_id, :uuid, null: false)
      add(:expired_at, :utc_datetime_usec, null: false)
    end

    create(unique_index(:access_audit_expired_requests, [:namespace, :request_id]))

    create table(:access_audit_chain_checkpoints, primary_key: false) do
      add(:sequence_number, :bigint, primary_key: true)
      add(:prune_id, :uuid, null: false)
      add(:checkpoint, :map, null: false)
    end

    create(index(:access_audit_chain_checkpoints, [:prune_id]))
    create(index(:access_audit_requests, [:last_received_at, :id]))
  end

  def down do
    execute("""
    DO $$ BEGIN
      IF EXISTS (SELECT 1 FROM access_audit_chain_checkpoints)
        OR EXISTS (SELECT 1 FROM access_audit_event_tombstones)
        OR EXISTS (SELECT 1 FROM access_audit_expired_requests) THEN
        RAISE EXCEPTION 'retention checkpoints and replay tombstones must be preserved; rollback requires recovery from a pre-prune backup';
      END IF;
    END $$
    """)

    drop(table(:access_audit_chain_checkpoints))
    drop(index(:access_audit_requests, [:last_received_at, :id]))
    drop(table(:access_audit_expired_requests))
    drop(table(:access_audit_event_tombstones))
  end
end
