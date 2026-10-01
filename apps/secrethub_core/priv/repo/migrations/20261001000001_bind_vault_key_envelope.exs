defmodule SecretHub.Core.Repo.Migrations.BindVaultKeyEnvelope do
  use Ecto.Migration

  def up do
    alter table(:vault_config) do
      # Null fields identify legacy rows, which require verified recovery.
      add(:envelope_version, :integer)
      add(:share_version, :integer)
      add(:share_set_id, :binary)
    end

    drop(unique_index(:vault_config, [:id], name: :vault_config_singleton))
    # Fail migration on multiple existing rows; never choose or delete one silently.
    create(unique_index(:vault_config, ["(true)"], name: :vault_config_singleton))

    create(
      constraint(:vault_config, :vault_config_parameters,
        check: "threshold >= 1 AND threshold <= total_shares AND total_shares <= 251"
      )
    )

    create(
      constraint(:vault_config, :vault_config_envelope,
        check:
          "(envelope_version IS NULL AND share_version IS NULL AND share_set_id IS NULL) OR (envelope_version IS NOT NULL AND share_version IS NOT NULL AND share_set_id IS NOT NULL AND envelope_version = 1 AND share_version = 4 AND octet_length(share_set_id) = 16 AND octet_length(encrypted_master_key) = 61)"
      )
    )
  end

  def down do
    execute("""
    DO $$ BEGIN
      IF EXISTS (SELECT 1 FROM vault_config WHERE envelope_version IS NOT NULL OR share_version IS NOT NULL OR share_set_id IS NOT NULL) THEN
        RAISE EXCEPTION 'Vault envelope downgrade blocked: authenticated generation metadata must be preserved';
      END IF;
    END $$;
    """)

    drop(constraint(:vault_config, :vault_config_envelope))
    drop(constraint(:vault_config, :vault_config_parameters))
    drop(unique_index(:vault_config, ["(true)"], name: :vault_config_singleton))
    create(unique_index(:vault_config, [:id], name: :vault_config_singleton))

    alter table(:vault_config) do
      remove(:envelope_version)
      remove(:share_version)
      remove(:share_set_id)
    end
  end
end
