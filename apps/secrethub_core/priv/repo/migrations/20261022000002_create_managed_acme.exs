defmodule SecretHub.Core.Repo.Migrations.CreateManagedAcme do
  use Ecto.Migration

  def up do
    create table(:acme_accounts, primary_key: false) do
      add(:id, :uuid, primary_key: true)
      add(:name, :text, null: false)
      add(:environment, :text, null: false)
      add(:directory_url, :text, null: false)
      add(:contact, {:array, :text}, null: false, default: [])
      add(:terms_url, :text, null: false)
      add(:terms_accepted_at, :utc_datetime, null: false)
      add(:encrypted_key, :binary, null: false)
      add(:account_url, :text)
      add(:status, :text, null: false, default: "pending")
      add(:enabled, :boolean, null: false, default: true)
      add(:last_error, :map, null: false, default: %{})
      timestamps(type: :utc_datetime)
    end

    create(
      constraint(:acme_accounts, :acme_account_environment,
        check: "environment IN ('staging', 'production')"
      )
    )

    create(
      unique_index(:acme_accounts, [:directory_url, :account_url],
        where: "account_url IS NOT NULL"
      )
    )

    create table(:acme_dns_providers, primary_key: false) do
      add(:id, :uuid, primary_key: true)
      add(:name, :text, null: false)
      add(:provider, :text, null: false)
      add(:credential_mode, :text, null: false, default: "secret")
      add(:credential_secret_id, references(:secrets, type: :uuid, on_delete: :restrict))
      add(:zones, {:array, :map}, null: false, default: [])
      add(:enabled, :boolean, null: false, default: true)
      timestamps(type: :utc_datetime)
    end

    create(
      constraint(:acme_dns_providers, :acme_dns_provider_type,
        check: "provider IN ('cloudflare','route53')"
      )
    )

    create(
      constraint(:acme_dns_providers, :acme_dns_credentials,
        check:
          "(credential_mode = 'secret' AND credential_secret_id IS NOT NULL) OR (provider = 'route53' AND credential_mode = 'aws_environment' AND credential_secret_id IS NULL)"
      )
    )

    create table(:managed_certificates, primary_key: false) do
      add(:id, :uuid, primary_key: true)
      add(:slug, :text, null: false)
      add(:account_id, references(:acme_accounts, type: :uuid, on_delete: :restrict), null: false)
      add(:identifiers, {:array, :text}, null: false)
      add(:bindings, {:array, :map}, null: false)
      add(:key_policy, :text, null: false, default: "ec_p256")
      add(:configuration_revision, :bigint, null: false, default: 1)
      add(:publication_sequence, :bigint, null: false, default: 0)
      add(:enabled, :boolean, null: false, default: true)
      add(:current_version_id, :uuid)
      add(:output_secret_id, references(:secrets, type: :uuid, on_delete: :restrict))
      add(:next_renewal_at, :utc_datetime)
      add(:last_error, :map, null: false, default: %{})
      timestamps(type: :utc_datetime)
    end

    create(unique_index(:managed_certificates, [:slug]))
    create(unique_index(:managed_certificates, [:output_secret_id]))

    create(
      constraint(:managed_certificates, :acme_positive_revision,
        check: "configuration_revision > 0 AND publication_sequence >= 0"
      )
    )

    create table(:acme_orders, primary_key: false) do
      add(:id, :uuid, primary_key: true)

      add(
        :managed_certificate_id,
        references(:managed_certificates, type: :uuid, on_delete: :restrict),
        null: false
      )

      add(:request_id, :text, null: false)
      add(:request_digest, :text, null: false)
      add(:configuration_revision, :bigint, null: false)
      add(:expected_prior_version_id, :uuid)
      add(:state, :text, null: false, default: "queued")
      add(:phase, :text, null: false, default: "prepare")
      add(:identifiers, {:array, :text}, null: false)
      add(:bindings, {:array, :map}, null: false)
      add(:account_snapshot, :map, null: false)
      add(:directory, :map, null: false, default: %{})
      add(:remote_url, :text)
      add(:finalize_url, :text)
      add(:certificate_url, :text)
      add(:authorization_urls, {:array, :text}, null: false, default: [])
      add(:remote_status, :text)
      add(:encrypted_pending_key, :binary)
      add(:csr, :binary)
      add(:csr_digest, :text)
      add(:downloaded_chain, :text)
      add(:claim_token, :uuid)
      add(:claim_expires_at, :utc_datetime)
      add(:remote_started_at, :utc_datetime)
      add(:next_attempt_at, :utc_datetime)
      add(:deadline_at, :utc_datetime, null: false)
      add(:attempts, :integer, null: false, default: 0)
      add(:uncertain_creates, :integer, null: false, default: 0)
      add(:last_error, :map, null: false, default: %{})
      timestamps(type: :utc_datetime)
    end

    create(unique_index(:acme_orders, [:managed_certificate_id, :request_id]))

    create(
      unique_index(:acme_orders, [:managed_certificate_id],
        name: :acme_orders_one_active,
        where: "state NOT IN ('published','failed','cancelled')"
      )
    )

    create(index(:acme_orders, [:next_attempt_at]))

    create table(:acme_authorizations, primary_key: false) do
      add(:id, :uuid, primary_key: true)
      add(:order_id, references(:acme_orders, type: :uuid, on_delete: :restrict), null: false)
      add(:url, :text, null: false)
      add(:identifier, :text, null: false)
      add(:wildcard, :boolean, null: false, default: false)
      add(:challenge_url, :text)
      add(:token, :text)
      add(:status, :text, null: false, default: "pending")
      add(:expires_at, :utc_datetime)
      timestamps(type: :utc_datetime)
    end

    create(unique_index(:acme_authorizations, [:order_id, :url]))

    create table(:acme_dns_operations, primary_key: false) do
      add(:id, :uuid, primary_key: true)
      add(:order_id, references(:acme_orders, type: :uuid, on_delete: :restrict), null: false)

      add(:authorization_id, references(:acme_authorizations, type: :uuid, on_delete: :restrict),
        null: false
      )

      add(:provider_id, references(:acme_dns_providers, type: :uuid, on_delete: :restrict),
        null: false
      )

      add(:provider_snapshot, :map, null: false)
      add(:original_owner, :text, null: false)
      add(:owner, :text, null: false)
      add(:value, :text, null: false)
      add(:state, :text, null: false, default: "intent")
      add(:intent, :map, null: false, default: %{})
      add(:receipt, :map, null: false, default: %{})
      add(:cleanup_status, :text, null: false, default: "pending")
      add(:claim_token, :uuid)
      add(:claim_expires_at, :utc_datetime)
      add(:next_attempt_at, :utc_datetime)
      add(:last_error, :map, null: false, default: %{})
      timestamps(type: :utc_datetime)
    end

    create(unique_index(:acme_dns_operations, [:authorization_id]))
    create(index(:acme_dns_operations, [:provider_id, :owner]))
    create(index(:acme_dns_operations, [:cleanup_status, :next_attempt_at]))

    create table(:managed_certificate_versions, primary_key: false) do
      add(:id, :uuid, primary_key: true)

      add(
        :managed_certificate_id,
        references(:managed_certificates, type: :uuid, on_delete: :restrict),
        null: false
      )

      add(:order_id, references(:acme_orders, type: :uuid, on_delete: :restrict), null: false)
      add(:publication_sequence, :bigint, null: false)
      add(:environment, :text, null: false)
      add(:fingerprint, :text, null: false)
      add(:certificate_pem, :text, null: false)
      add(:chain_pem, :text, null: false)
      add(:fullchain_pem, :text, null: false)
      add(:identifiers, {:array, :text}, null: false)
      add(:not_before, :utc_datetime, null: false)
      add(:not_after, :utc_datetime, null: false)
      add(:key_policy, :text, null: false)
      add(:output_secret_id, references(:secrets, type: :uuid, on_delete: :restrict), null: false)
      add(:secret_version_number, :integer, null: false)
      add(:ari, :map, null: false, default: %{})
      add(:renewal_due_at, :utc_datetime)
      add(:ari_refresh_at, :utc_datetime)
      add(:quarantined_at, :utc_datetime)
      add(:revocation_state, :text, null: false, default: "none")
      add(:revocation_reason, :integer, null: false, default: 0)
      add(:revocation_next_attempt_at, :utc_datetime)
      add(:revocation_error, :map, null: false, default: %{})
      timestamps(type: :utc_datetime)
    end

    create(unique_index(:managed_certificate_versions, [:order_id]))

    create(
      unique_index(
        :managed_certificate_versions,
        [:managed_certificate_id, :publication_sequence],
        name: :managed_versions_sequence
      )
    )

    create(
      unique_index(:managed_certificate_versions, [:output_secret_id, :secret_version_number],
        name: :managed_versions_material
      )
    )

    create(
      unique_index(:managed_certificate_versions, [:id, :managed_certificate_id],
        name: :managed_versions_owner
      )
    )

    execute(
      "ALTER TABLE managed_certificates ADD CONSTRAINT managed_current_version_owner FOREIGN KEY (current_version_id,id) REFERENCES managed_certificate_versions(id,managed_certificate_id) DEFERRABLE INITIALLY DEFERRED"
    )

    execute("""
    CREATE FUNCTION secrethub_managed_material_guard() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF current_setting('secrethub.acme_publication', true) IS DISTINCT FROM 'on' AND EXISTS
        (SELECT 1 FROM managed_certificates WHERE output_secret_id = OLD.id) THEN
        RAISE EXCEPTION 'managed_certificate_output' USING ERRCODE = '23514';
      END IF;
      IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
    END $$;
    """)

    execute(
      "CREATE TRIGGER managed_material_update BEFORE UPDATE OF encrypted_data,version,secret_path,engine_type,secret_type,rotation_enabled ON secrets FOR EACH ROW EXECUTE FUNCTION secrethub_managed_material_guard()"
    )

    execute(
      "CREATE TRIGGER managed_material_delete BEFORE DELETE ON secrets FOR EACH ROW EXECUTE FUNCTION secrethub_managed_material_guard()"
    )

    execute("""
    CREATE FUNCTION secrethub_managed_history_guard() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF EXISTS (SELECT 1 FROM managed_certificate_versions
        WHERE output_secret_id = OLD.secret_id AND secret_version_number = OLD.version_number) THEN
        RAISE EXCEPTION 'retained_managed_certificate_version' USING ERRCODE = '23514';
      END IF;
      IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
    END $$;
    """)

    execute(
      "CREATE TRIGGER managed_history_retention BEFORE UPDATE OR DELETE ON secret_versions FOR EACH ROW EXECUTE FUNCTION secrethub_managed_history_guard()"
    )

    execute("""
    CREATE FUNCTION secrethub_managed_version_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF (to_jsonb(NEW) - ARRAY['ari','renewal_due_at','ari_refresh_at','quarantined_at','revocation_state','revocation_reason','revocation_next_attempt_at','revocation_error','updated_at'])
        IS DISTINCT FROM (to_jsonb(OLD) - ARRAY['ari','renewal_due_at','ari_refresh_at','quarantined_at','revocation_state','revocation_reason','revocation_next_attempt_at','revocation_error','updated_at']) THEN
        RAISE EXCEPTION 'immutable_managed_certificate_material' USING ERRCODE = '23514';
      END IF;
      RETURN NEW;
    END $$;
    """)

    execute(
      "CREATE TRIGGER managed_version_immutable BEFORE UPDATE ON managed_certificate_versions FOR EACH ROW EXECUTE FUNCTION secrethub_managed_version_immutable()"
    )
  end

  def down,
    do:
      raise(
        "managed certificate material and DNS receipts require a coordinated retention migration"
      )
end
