defmodule SecretHub.Core.Repo.Migrations.VersionAuditSignatures do
  use Ecto.Migration

  def up do
    alter table(:audit_logs) do
      add(:signature_version, :integer, null: false, default: 1)
      add(:signing_key_id, :string, size: 64)
    end

    create(
      constraint(:audit_logs, :audit_logs_signature_metadata,
        check:
          "(signature_version = 1 AND signing_key_id IS NULL) OR " <>
            "(signature_version = 2 AND signing_key_id IS NOT NULL AND " <>
            "signing_key_id ~ '^[a-zA-Z0-9_.-]{1,64}$')"
      )
    )
  end

  def down do
    execute("""
    DO $$ BEGIN
      IF EXISTS (SELECT 1 FROM audit_logs WHERE signature_version = 2) THEN
        RAISE EXCEPTION 'Audit signature metadata is in use; downgrade requires reviewed recovery';
      END IF;
    END $$;
    """)

    drop(constraint(:audit_logs, :audit_logs_signature_metadata))

    alter table(:audit_logs) do
      remove(:signing_key_id)
      remove(:signature_version)
    end
  end
end
