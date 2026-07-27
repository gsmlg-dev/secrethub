defmodule SecretHub.Core.Repo.Migrations.CreateCanonicalFingerprintIndex do
  use Ecto.Migration

  @disable_ddl_transaction true
  @disable_migration_lock true

  def up do
    create(
      unique_index(:certificates, [:canonical_fingerprint],
        name: :certificates_canonical_fingerprint_unique,
        where: "canonical_fingerprint IS NOT NULL",
        concurrently: true
      )
    )

  end

  def down do
    drop(
      index(:certificates, [:canonical_fingerprint],
        name: :certificates_canonical_fingerprint_unique,
        concurrently: true
      )
    )
  end
end
