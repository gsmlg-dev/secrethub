defmodule SecretHub.Core.Repo.Migrations.AddReceiptInstallationState do
  use Ecto.Migration

  def change do
    alter table(:client_auth_bundle_receipts) do
      add(:last_applied_generation, :bigint, null: true)
      add(:last_applied_crl_number, :bigint, null: true)
      add(:last_applied_bundle_sha256, :string, size: 64, null: true)
      add(:last_applied_at, :utc_datetime, null: true)
      add(:observation_sequence, :bigint, default: 0, null: false)
    end
  end
end
