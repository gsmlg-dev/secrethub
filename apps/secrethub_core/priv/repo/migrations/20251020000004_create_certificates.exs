defmodule SecretHub.Core.Repo.Migrations.CreateCertificates do
  use Ecto.Migration

  def change do
    create table(:certificates, primary_key: false) do
      add :id, :binary_id, primary_key: true

      # Certificate identification
      add :serial_number, :string, null: false
      add :fingerprint, :string, null: false

      # Certificate data
      add :certificate_pem, :text, null: false
      add :private_key_encrypted, :binary

      # Certificate details
      add :subject, :string, null: false
      add :issuer, :string, null: false
      add :common_name, :string, null: false
      add :organization, :string
      add :organizational_unit, :string

      # Validity period
      add :valid_from, :utc_datetime, null: false
      add :valid_until, :utc_datetime, null: false

      # Certificate type and usage
      add :cert_type, :string, null: false
      add :key_usage, {:array, :string}, default: []

      # Revocation tracking
      add :revoked, :boolean, default: false
      add :revoked_at, :utc_datetime
      add :revocation_reason, :string

      # Entity binding
      add :entity_id, :string
      add :entity_type, :string

      # Metadata
      add :metadata, :map, default: %{}

      timestamps(type: :utc_datetime)
    end

    create unique_index(:certificates, [:serial_number])
    create unique_index(:certificates, [:fingerprint])
    create index(:certificates, [:cert_type])
    create index(:certificates, [:entity_id])
    create index(:certificates, [:valid_until])
    create index(:certificates, [:revoked])

    # Index for finding soon-to-expire certificates
    create index(:certificates, [:valid_until])
    where: "revoked = false"
  end
end
