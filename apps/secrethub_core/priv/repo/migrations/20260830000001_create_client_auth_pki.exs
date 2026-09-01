defmodule SecretHub.Core.Repo.Migrations.CreateClientAuthPki do
  use Ecto.Migration

  def up do

    for year <- [2025, 2026, 2027, 2028], month <- 1..12 do
      next_month = if month == 12, do: 1, else: month + 1
      next_year = if month == 12, do: year + 1, else: year
      p_name = "audit_logs_y#{year}m#{String.pad_leading(to_string(month), 2, "0")}"
      from_date = "#{year}-#{String.pad_leading(to_string(month), 2, "0")}-01"
      to_date = "#{next_year}-#{String.pad_leading(to_string(next_month), 2, "0")}-01"

      execute("""
      DO $$
      BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = '#{p_name}') THEN
          CREATE TABLE #{p_name} PARTITION OF audit_logs
          FOR VALUES FROM ('#{from_date}') TO ('#{to_date}');
        END IF;
      END $$;
      """)
    end

    # 2. client_auth_authorities table
    create table(:client_auth_authorities, primary_key: false) do
      add(:id, :binary_id, primary_key: true)
      add(:slug, :string, null: false, default: "client-auth")
      add(:name, :string, null: false)
      add(:status, :string, null: false, default: "initializing")
      add(:ca_certificate_id, references(:certificates, type: :binary_id, on_delete: :nilify_all), null: true)
      add(:current_crl_id, :binary_id, null: true)
      add(:current_generation, :bigint, null: false, default: 0)
      add(:current_crl_number, :bigint, null: false, default: 0)
      add(:key_algorithm, :string, null: false, default: "ecdsa_p384")
      add(:default_ttl_seconds, :integer, null: false, default: 2_592_000)
      add(:max_ttl_seconds, :integer, null: false, default: 7_776_000)

      timestamps(type: :utc_datetime)
    end

    create(unique_index(:client_auth_authorities, [:slug]))

    # 3. client_auth_identities table
    create table(:client_auth_identities, primary_key: false) do
      add(:id, :binary_id, primary_key: true)
      add(:name, :string, null: false)
      add(:status, :string, null: false, default: "active")
      add(:metadata, :map, null: false, default: %{})

      timestamps(type: :utc_datetime)
    end

    create(unique_index(:client_auth_identities, [:name]))

    # 4. client_auth_crls table
    create table(:client_auth_crls, primary_key: false) do
      add(:id, :binary_id, primary_key: true)
      add(:authority_id, references(:client_auth_authorities, type: :binary_id, on_delete: :delete_all), null: false)
      add(:issuer_certificate_id, references(:certificates, type: :binary_id, on_delete: :restrict), null: false)
      add(:crl_number, :bigint, null: false)
      add(:generation, :bigint, null: false)
      add(:crl_pem, :text, null: false)
      add(:crl_der_sha256, :string, size: 64, null: false)
      add(:this_update, :utc_datetime, null: false)
      add(:next_update, :utc_datetime, null: false)
      add(:revoked_count, :integer, null: false, default: 0)

      timestamps(type: :utc_datetime)
    end

    create(unique_index(:client_auth_crls, [:authority_id, :crl_number]))
    create(unique_index(:client_auth_crls, [:authority_id, :generation]))

    create(
      constraint(:client_auth_crls, :client_auth_crls_next_update_after_this_update,
        check: "next_update > this_update"
      )
    )

    # 5. Add FK from client_auth_authorities.current_crl_id to client_auth_crls
    alter table(:client_auth_authorities) do
      modify(:current_crl_id, references(:client_auth_crls, type: :binary_id, on_delete: :nilify_all))
    end

    # 6. client_auth_issuance_requests table
    create table(:client_auth_issuance_requests, primary_key: false) do
      add(:id, :binary_id, primary_key: true)
      add(:request_id, :uuid, null: false)
      add(:identity_id, references(:client_auth_identities, type: :binary_id, on_delete: :restrict), null: false)
      add(:csr_sha256, :binary, null: false)
      add(:requested_ttl_seconds, :integer, null: false)
      add(:certificate_id, references(:certificates, type: :binary_id, on_delete: :restrict), null: false)

      timestamps(type: :utc_datetime)
    end

    create(unique_index(:client_auth_issuance_requests, [:request_id]))
    create(index(:client_auth_issuance_requests, [:identity_id]))
    create(index(:client_auth_issuance_requests, [:certificate_id]))

    # 7. client_auth_bundle_receipts table
    create table(:client_auth_bundle_receipts, primary_key: false) do
      add(:id, :binary_id, primary_key: true)
      add(:agent_id, :string, null: false)
      add(:client_auth_authority_id, references(:client_auth_authorities, type: :binary_id, on_delete: :delete_all), null: false)
      add(:generation, :bigint, null: false)
      add(:crl_number, :bigint, null: false)
      add(:bundle_sha256, :string, size: 64, null: false)
      add(:status, :string, null: false, default: "applied")
      add(:last_error_code, :string, null: true)
      add(:last_error_detail, :text, null: true)
      add(:applied_at, :utc_datetime, null: true)

      timestamps(type: :utc_datetime)
    end

    create(unique_index(:client_auth_bundle_receipts, [:agent_id, :client_auth_authority_id]))
    create(index(:client_auth_bundle_receipts, [:client_auth_authority_id, :generation]))

    # 8. Extend certificates table
    alter table(:certificates) do
      add(:client_auth_authority_id, references(:client_auth_authorities, type: :binary_id, on_delete: :nilify_all), null: true)
      add(:client_auth_identity_id, references(:client_auth_identities, type: :binary_id, on_delete: :nilify_all), null: true)
    end

    create(index(:certificates, [:client_auth_authority_id]))
    create(index(:certificates, [:client_auth_identity_id]))
    create(index(:certificates, [:client_auth_identity_id, :revoked]))
  end

  def down do
    # 1. Drop tables that reference other tables first
    drop(table(:client_auth_bundle_receipts))
    drop(table(:client_auth_issuance_requests))

    # 2. Remove cyclic FK from client_auth_authorities to client_auth_crls
    alter table(:client_auth_authorities) do
      remove(:current_crl_id)
    end

    # 3. Drop CRLs, identities, and authorities
    drop(table(:client_auth_crls))
    drop(table(:client_auth_identities))
    drop(table(:client_auth_authorities))

    # 4. Remove columns and indexes on certificates table
    drop(index(:certificates, [:client_auth_identity_id, :revoked]))
    drop(index(:certificates, [:client_auth_identity_id]))
    drop(index(:certificates, [:client_auth_authority_id]))

    alter table(:certificates) do
      remove(:client_auth_identity_id)
      remove(:client_auth_authority_id)
    end

    # 5. Cleanly remove Client Auth certificates from certificates table
    execute("DELETE FROM certificates WHERE cert_type = 'client_auth_client'")
    execute("DELETE FROM certificates WHERE cert_type = 'client_auth_ca'")
  end
end
