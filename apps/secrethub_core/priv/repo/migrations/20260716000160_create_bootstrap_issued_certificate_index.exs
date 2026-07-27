defmodule SecretHub.Core.Repo.Migrations.CreateBootstrapIssuedCertificateIndex do
  use Ecto.Migration

  @disable_ddl_transaction true
  @disable_migration_lock true

  def up do
    create(
      index(:app_bootstrap_tokens, [:issued_certificate_id],
        concurrently: true
      )
    )
  end

  def down do
    drop(
      index(:app_bootstrap_tokens, [:issued_certificate_id],
        concurrently: true
      )
    )
  end
end
