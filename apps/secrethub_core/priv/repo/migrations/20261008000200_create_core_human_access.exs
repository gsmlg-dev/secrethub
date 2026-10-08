defmodule SecretHub.Core.Repo.Migrations.CreateCoreHumanAccess do
  use Ecto.Migration

  def change do
    create table(:core_human_grants, primary_key: false) do
      add(:id, :binary_id, primary_key: true)
      add(:subject_id, :uuid, null: false)
      add(:mount_id, :text, null: false)
      add(:role_id, :text, null: false)
      add(:allowed_operations, {:array, :text}, default: [], null: false)
      add(:max_ttl, :integer, null: false)
      add(:require_approval, :boolean, default: false, null: false)
      add(:require_device, :boolean, default: true, null: false)
      add(:require_mfa, :boolean, default: false, null: false)
      add(:approver_subject_ids, {:array, :uuid}, default: [], null: false)
      add(:enabled, :boolean, default: true, null: false)
      add(:revision, :integer, default: 1, null: false)
      timestamps(type: :utc_datetime_usec)
    end

    create(unique_index(:core_human_grants, [:subject_id, :mount_id, :role_id]))

    create(
      constraint(:core_human_grants, :valid_human_ttl, check: "max_ttl > 0 AND max_ttl <= 86400")
    )

    create table(:core_human_leases, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(:grant_id, references(:core_human_grants, type: :binary_id, on_delete: :restrict),
        null: false
      )

      add(:grant_revision, :integer, null: false)
      add(:subject_id, :uuid, null: false)
      add(:session_id, :uuid, null: false)
      add(:device_id, :uuid)
      add(:request_id, :uuid, null: false)
      add(:mount_id, :text, null: false)
      add(:role_id, :text, null: false)
      add(:username, :text, null: false)
      add(:status, :text, default: "reserved", null: false)
      add(:issued_at, :utc_datetime_usec)
      add(:expires_at, :utc_datetime_usec, null: false)
      add(:renewable, :boolean, default: true, null: false)
      timestamps(type: :utc_datetime_usec)
    end

    create(unique_index(:core_human_leases, [:subject_id, :request_id]))
    create(unique_index(:core_human_leases, [:username]))
    create(index(:core_human_leases, [:status, :expires_at]))

    create(
      constraint(:core_human_leases, :valid_human_lease_status,
        check: "status IN ('reserved','active','revoke_pending','revoked','expired','failed')"
      )
    )

    create table(:core_human_approvals, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(:grant_id, references(:core_human_grants, type: :binary_id, on_delete: :restrict),
        null: false
      )

      add(:grant_revision, :integer, null: false)
      add(:subject_id, :uuid, null: false)
      add(:session_id, :uuid, null: false)
      add(:device_id, :uuid)
      add(:request_id, :uuid, null: false)
      add(:mount_id, :text, null: false)
      add(:role_id, :text, null: false)
      add(:requested_ttl, :integer, null: false)
      add(:max_ttl, :integer, null: false)
      add(:status, :text, default: "pending", null: false)
      add(:expires_at, :utc_datetime_usec, null: false)
      add(:decided_by, :uuid)
      add(:decided_at, :utc_datetime_usec)
      add(:consumed_at, :utc_datetime_usec)
      timestamps(type: :utc_datetime_usec)
    end

    create(unique_index(:core_human_approvals, [:subject_id, :request_id]))
    create(index(:core_human_approvals, [:status, :expires_at]))
  end
end
