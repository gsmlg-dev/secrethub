defmodule SecretHub.Core.Repo.Migrations.CreateAccessAudit do
  use Ecto.Migration

  def change do
    create table(:access_audit_events, primary_key: false) do
      add(:id, :bigserial, primary_key: true)
      add(:namespace, :text, null: false)
      add(:event_id, :uuid, null: false)
      add(:producer_id, :uuid, null: false)
      add(:producer_sequence, :bigint, null: false)
      add(:request_id, :uuid, null: false)
      add(:envelope, :map, null: false)
      add(:canonical, :text, null: false)
      add(:observed_at, :utc_datetime_usec, null: false)
      add(:received_at, :utc_datetime_usec, null: false)
      add(:audit_log_id, :bigint, null: false)
      add(:audit_log_timestamp, :utc_datetime, null: false)
    end

    create(unique_index(:access_audit_events, [:namespace, :producer_id, :event_id]))
    create(unique_index(:access_audit_events, [:namespace, :producer_id, :producer_sequence]))
    create(index(:access_audit_events, [:namespace, :request_id, :observed_at, :id]))
    create(index(:access_audit_events, [:received_at]))
    create(constraint(:access_audit_events, :positive_sequence, check: "producer_sequence > 0"))

    create table(:access_audit_producers, primary_key: false) do
      add(:id, :bigserial, primary_key: true)
      add(:namespace, :text, null: false)
      add(:producer_id, :uuid, null: false)
      add(:last_sequence, :bigint, null: false)
      add(:event_count, :bigint, null: false)
      add(:last_received_at, :utc_datetime_usec, null: false)
      add(:last_observed_at, :utc_datetime_usec, null: false)
    end

    create(unique_index(:access_audit_producers, [:namespace, :producer_id]))

    create table(:access_audit_agent_health, primary_key: false) do
      add(:agent_id, :text, primary_key: true)
      add(:status, :map, null: false)
      add(:received_at, :utc_datetime_usec, null: false)
    end

    create table(:access_audit_requests, primary_key: false) do
      add(:id, :bigserial, primary_key: true)
      add(:namespace, :text, null: false)
      add(:request_id, :uuid, null: false)
      add(:agent_id, :text)
      add(:application_id, :uuid)
      add(:identity_status, :text, null: false)
      add(:attribution, :text, null: false)
      add(:secret_id, :uuid)
      add(:secret_path, :text)
      add(:operation, :text, null: false)
      add(:started_at, :utc_datetime_usec, null: false)
      add(:last_observed_at, :utc_datetime_usec, null: false)
      add(:last_received_at, :utc_datetime_usec, null: false)
      add(:outcome, :text, null: false)
      add(:reason_code, :text, null: false)
      add(:attempts, :integer, null: false)
      add(:incomplete, :boolean, null: false)
      add(:contradictory, :boolean, null: false)
      add(:core_outcome, :text)
      add(:core_reason_code, :text)
      add(:delivery_outcome, :text)
      add(:cache_status, :text, null: false)
    end

    create(unique_index(:access_audit_requests, [:namespace, :request_id]))
    create(index(:access_audit_requests, [:started_at, :id]))

    for field <- [:application_id, :agent_id, :secret_path, :outcome, :reason_code] do
      create(index(:access_audit_requests, [field, :started_at, :id]))
    end
  end
end
