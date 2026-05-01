defmodule SecretHub.Core.Repo.Migrations.LinkRotationHistoryToRotators do
  use Ecto.Migration

  def up do
    alter table(:rotation_history) do
      add_if_not_exists(
        :rotator_id,
        references(:secret_rotators, type: :uuid, on_delete: :delete_all)
      )
    end

    execute("ALTER TABLE rotation_history ALTER COLUMN rotation_schedule_id DROP NOT NULL")
    create_if_not_exists(index(:rotation_history, [:rotator_id]))
  end

  def down do
    drop_if_exists(index(:rotation_history, [:rotator_id]))
    execute("DELETE FROM rotation_history WHERE rotation_schedule_id IS NULL")
    execute("ALTER TABLE rotation_history ALTER COLUMN rotation_schedule_id SET NOT NULL")

    alter table(:rotation_history) do
      remove_if_exists(:rotator_id, references(:secret_rotators, type: :uuid))
    end
  end
end
