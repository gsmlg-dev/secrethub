defmodule SecretHub.Core.Repo.Migrations.ExpandAppCertificateSecurity do
  use Ecto.Migration

  def up do
    alter table(:certificates) do
      add(:canonical_fingerprint, :string)
    end

    create(
      constraint(:certificates, :certificates_canonical_fingerprint_format,
        check: "canonical_fingerprint IS NULL OR canonical_fingerprint ~ '^[0-9a-f]{64}$'",
        validate: false
      )
    )

    execute(
      "ALTER TABLE certificates " <>
        "VALIDATE CONSTRAINT certificates_canonical_fingerprint_format"
    )

    alter table(:app_bootstrap_tokens) do
      add(:issuance_request_id, :uuid)

      add(
        :issued_certificate_id,
        references(:certificates, type: :binary_id, on_delete: :restrict)
      )
    end

    create(
      constraint(:app_bootstrap_tokens, :app_bootstrap_tokens_issuance_result_pair,
        check:
          "(issuance_request_id IS NULL AND issued_certificate_id IS NULL) OR " <>
            "(issuance_request_id IS NOT NULL AND issued_certificate_id IS NOT NULL)",
        validate: false
      )
    )

    execute(
      "ALTER TABLE app_bootstrap_tokens " <>
        "VALIDATE CONSTRAINT app_bootstrap_tokens_issuance_result_pair"
    )

    execute("""
    ALTER TABLE applications
    ADD CONSTRAINT applications_agent_id_fkey
    FOREIGN KEY (agent_id) REFERENCES agents(id) NOT VALID
    """)

    execute("""
    DO $$
    DECLARE
      orphan_count bigint;
      sample_application_ids text;
    BEGIN
      SELECT COUNT(*)
      INTO orphan_count
      FROM applications AS application
      LEFT JOIN agents AS agent ON agent.id = application.agent_id
      WHERE agent.id IS NULL;

      IF orphan_count > 0 THEN
        SELECT string_agg(orphan.id::text, ', ' ORDER BY orphan.id)
        INTO sample_application_ids
        FROM (
          SELECT application.id
          FROM applications AS application
          LEFT JOIN agents AS agent ON agent.id = application.agent_id
          WHERE agent.id IS NULL
          ORDER BY application.id
          LIMIT 20
        ) AS orphan;

        RAISE EXCEPTION
          'cannot validate applications_agent_id_fkey: % orphan rows; sample application_ids: %',
          orphan_count,
          sample_application_ids;
      END IF;
    END
    $$;
    """)

    execute("ALTER TABLE applications VALIDATE CONSTRAINT applications_agent_id_fkey")
  end

  def down do
    execute("ALTER TABLE applications DROP CONSTRAINT applications_agent_id_fkey")

    drop(constraint(:app_bootstrap_tokens, :app_bootstrap_tokens_issuance_result_pair))

    alter table(:app_bootstrap_tokens) do
      remove(:issued_certificate_id)
      remove(:issuance_request_id)
    end

    drop(constraint(:certificates, :certificates_canonical_fingerprint_format))

    alter table(:certificates) do
      remove(:canonical_fingerprint)
    end
  end
end
