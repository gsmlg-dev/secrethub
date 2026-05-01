defmodule SecretHub.Core.Repo.Migrations.MakeSecretRotatorsPerSecret do
  use Ecto.Migration

  @manual_rotator_id "00000000-0000-0000-0000-000000000004"

  def up do
    alter table(:secret_rotators) do
      add_if_not_exists(:secret_id, references(:secrets, type: :uuid, on_delete: :delete_all))

      add_if_not_exists(
        :engine_configuration_id,
        references(:engine_configurations, type: :uuid, on_delete: :nilify_all)
      )

      add_if_not_exists(:trigger_mode, :string, default: "manual", null: false)
      add_if_not_exists(:schedule_cron, :string)
      add_if_not_exists(:grace_period_seconds, :integer, default: 300, null: false)
      add_if_not_exists(:last_rotation_at, :utc_datetime)
      add_if_not_exists(:last_rotation_status, :string)
      add_if_not_exists(:last_rotation_error, :text)
      add_if_not_exists(:next_rotation_at, :utc_datetime)
      add_if_not_exists(:rotation_count, :integer, default: 0, null: false)
      add_if_not_exists(:metadata, :map, default: %{}, null: false)
    end

    execute("ALTER TABLE secrets ALTER COLUMN rotator_id DROP NOT NULL")

    execute("""
    INSERT INTO secret_rotators (
      slug,
      name,
      description,
      rotator_type,
      config,
      enabled,
      secret_id,
      trigger_mode,
      schedule_cron,
      inserted_at,
      updated_at
    )
    SELECT
      COALESCE(template.slug, 'manual-web-ui') || '-' || s.id::text,
      COALESCE(template.name, 'Manual Web UI'),
      COALESCE(template.description, 'Manual secret updates from the admin web UI.'),
      COALESCE(template.rotator_type, 'manual'),
      COALESCE(template.config, '{}'::jsonb),
      true,
      s.id,
      'manual',
      s.rotation_schedule,
      now(),
      now()
    FROM secrets s
    LEFT JOIN secret_rotators existing ON existing.secret_id = s.id
    LEFT JOIN secret_rotators template ON template.id = s.rotator_id AND template.secret_id IS NULL
    WHERE existing.id IS NULL
    ON CONFLICT (slug) DO NOTHING
    """)

    execute("""
    UPDATE secrets s
    SET rotator_id = r.id
    FROM secret_rotators r
    WHERE r.secret_id = s.id
      AND (s.rotator_id IS NULL OR s.rotator_id = '#{@manual_rotator_id}')
    """)

    create_if_not_exists(
      unique_index(:secret_rotators, [:secret_id], where: "secret_id IS NOT NULL")
    )

    create_if_not_exists(index(:secret_rotators, [:engine_configuration_id]))
    create_if_not_exists(index(:secret_rotators, [:trigger_mode]))
    create_if_not_exists(index(:secret_rotators, [:next_rotation_at]))
  end

  def down do
    drop_if_exists(index(:secret_rotators, [:next_rotation_at]))
    drop_if_exists(index(:secret_rotators, [:trigger_mode]))
    drop_if_exists(index(:secret_rotators, [:engine_configuration_id]))
    drop_if_exists(unique_index(:secret_rotators, [:secret_id], where: "secret_id IS NOT NULL"))

    execute("""
    UPDATE secrets
    SET rotator_id = '#{@manual_rotator_id}'
    WHERE rotator_id IN (
      SELECT id FROM secret_rotators WHERE secret_id IS NOT NULL
    )
    """)

    execute("DELETE FROM secret_rotators WHERE secret_id IS NOT NULL")
    execute("ALTER TABLE secrets ALTER COLUMN rotator_id SET NOT NULL")

    alter table(:secret_rotators) do
      remove_if_exists(:metadata, :map)
      remove_if_exists(:rotation_count, :integer)
      remove_if_exists(:next_rotation_at, :utc_datetime)
      remove_if_exists(:last_rotation_error, :text)
      remove_if_exists(:last_rotation_status, :string)
      remove_if_exists(:last_rotation_at, :utc_datetime)
      remove_if_exists(:grace_period_seconds, :integer)
      remove_if_exists(:schedule_cron, :string)
      remove_if_exists(:trigger_mode, :string)
      remove_if_exists(:engine_configuration_id, references(:engine_configurations, type: :uuid))
      remove_if_exists(:secret_id, references(:secrets, type: :uuid))
    end
  end
end
