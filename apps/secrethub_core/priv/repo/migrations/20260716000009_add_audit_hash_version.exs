defmodule SecretHub.Core.Repo.Migrations.AddAuditHashVersion do
  use Ecto.Migration

  def up do
    execute("""
    ALTER TABLE audit_logs
    ADD COLUMN hash_version SMALLINT NOT NULL DEFAULT 1
    """)
  end

  def down do
    execute("""
    ALTER TABLE audit_logs
    DROP COLUMN hash_version
    """)
  end
end
