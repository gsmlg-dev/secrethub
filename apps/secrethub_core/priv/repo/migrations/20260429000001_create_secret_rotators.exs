defmodule SecretHub.Core.Repo.Migrations.CreateSecretRotators do
  use Ecto.Migration

  @manual_rotator_id "00000000-0000-0000-0000-000000000004"

  def up do
    create_if_not_exists table(:secret_rotators, primary_key: false) do
      add(:id, :uuid, primary_key: true, default: fragment("gen_random_uuid()"))
      add(:slug, :string, null: false)
      add(:name, :string, null: false)
      add(:description, :text)
      add(:rotator_type, :string, null: false)
      add(:config, :map, default: %{}, null: false)
      add(:enabled, :boolean, default: true, null: false)

      timestamps(type: :utc_datetime)
    end

    create_if_not_exists(unique_index(:secret_rotators, [:slug]))
    create_if_not_exists(index(:secret_rotators, [:rotator_type]))
    create_if_not_exists(index(:secret_rotators, [:enabled]))

    execute("""
    INSERT INTO secret_rotators (id, slug, name, description, rotator_type, config, enabled, inserted_at, updated_at)
    VALUES
      ('00000000-0000-0000-0000-000000000001', 'built-in', 'Built-in Rotator', 'SecretHub managed rotation workflow.', 'built_in', '{}', true, now(), now()),
      ('00000000-0000-0000-0000-000000000002', 'agent', 'Agent Rotator', 'Rotation requested and completed by a connected SecretHub agent.', 'agent', '{}', true, now(), now()),
      ('00000000-0000-0000-0000-000000000003', 'api', 'API Rotator', 'Rotation performed through the SecretHub API.', 'api', '{}', true, now(), now()),
      ('#{@manual_rotator_id}', 'manual-web-ui', 'Manual Web UI', 'Manual secret updates from the admin web UI.', 'manual', '{}', true, now(), now())
    ON CONFLICT (slug) DO UPDATE
    SET name = EXCLUDED.name,
        description = EXCLUDED.description,
        rotator_type = EXCLUDED.rotator_type,
        updated_at = now()
    """)

    execute("ALTER TABLE secrets ADD COLUMN IF NOT EXISTS ttl_seconds integer NOT NULL DEFAULT 0")
    execute("ALTER TABLE secrets ADD COLUMN IF NOT EXISTS rotator_id uuid")
    execute("UPDATE secrets SET rotator_id = '#{@manual_rotator_id}' WHERE rotator_id IS NULL")
    execute("ALTER TABLE secrets ALTER COLUMN rotator_id SET NOT NULL")

    execute("""
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'secrets_rotator_id_fkey'
      ) THEN
        ALTER TABLE secrets
        ADD CONSTRAINT secrets_rotator_id_fkey
        FOREIGN KEY (rotator_id)
        REFERENCES secret_rotators(id)
        ON DELETE RESTRICT;
      END IF;
    END
    $$;
    """)

    create_if_not_exists(index(:secrets, [:rotator_id]))
    create_if_not_exists(index(:secrets, [:ttl_seconds]))
  end

  def down do
    drop_if_exists(index(:secrets, [:ttl_seconds]))
    drop_if_exists(index(:secrets, [:rotator_id]))

    execute("ALTER TABLE secrets DROP CONSTRAINT IF EXISTS secrets_rotator_id_fkey")
    execute("ALTER TABLE secrets DROP COLUMN IF EXISTS rotator_id")
    execute("ALTER TABLE secrets DROP COLUMN IF EXISTS ttl_seconds")

    drop_if_exists(table(:secret_rotators))
  end
end
