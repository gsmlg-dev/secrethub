defmodule SecretHub.Core.Repo.Migrations.CreateLeases do
  use Ecto.Migration

  def change do
    create table(:leases, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      # Lease identification
      add(:lease_id, :binary_id, null: false)
      add(:secret_id, :string, null: false)

      # Entity information
      add(:agent_id, :string, null: false)
      add(:app_id, :string)
      add(:app_cert_fingerprint, :string)

      # Lease timing
      add(:issued_at, :utc_datetime, null: false)
      add(:expires_at, :utc_datetime, null: false)
      add(:ttl_seconds, :integer, null: false)

      # Renewal tracking
      add(:renewed_count, :integer, default: 0)
      add(:last_renewed_at, :utc_datetime)
      add(:max_renewals, :integer)

      # Revocation
      add(:revoked, :boolean, default: false)
      add(:revoked_at, :utc_datetime)
      add(:revocation_reason, :string)

      # Encrypted credentials
      add(:credentials, :map, null: false)

      # Engine-specific data
      add(:engine_type, :string, null: false)
      add(:engine_metadata, :map, default: %{})

      # Context
      add(:source_ip, :inet)
      add(:correlation_id, :binary_id)

      timestamps(type: :utc_datetime)
    end

    create(unique_index(:leases, [:lease_id]))
    create(index(:leases, [:secret_id]))
    create(index(:leases, [:agent_id]))
    create(index(:leases, [:app_id]))
    create(index(:leases, [:expires_at]))
    create(index(:leases, [:revoked]))

    # Index for finding leases needing renewal (expires_at is soon)
    create(index(:leases, [:agent_id, :expires_at]))
  end
end
