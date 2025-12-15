defmodule SecretHub.Core.Repo.Migrations.CreateRotationSchedulesTable do
  use Ecto.Migration

  def change do
    create table(:rotation_schedules, primary_key: false) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :name, :string, null: false
      add :description, :text
      add :rotation_type, :string, null: false
      add :target_type, :string, null: false
      add :target_id, :uuid
      add :config, :map, default: %{}, null: false
      add :schedule_cron, :string, null: false
      add :enabled, :boolean, default: true, null: false
      add :grace_period_seconds, :integer, default: 300
      add :last_rotation_at, :utc_datetime
      add :last_rotation_status, :string
      add :last_rotation_error, :text
      add :next_rotation_at, :utc_datetime
      add :rotation_count, :integer, default: 0
      add :metadata, :map, default: %{}

      timestamps(type: :utc_datetime)
    end

    create unique_index(:rotation_schedules, [:name])
    create index(:rotation_schedules, [:rotation_type])
    create index(:rotation_schedules, [:target_type])
    create index(:rotation_schedules, [:enabled])
    create index(:rotation_schedules, [:next_rotation_at])

    # Rotation history table
    create table(:rotation_history, primary_key: false) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :rotation_schedule_id, references(:rotation_schedules, type: :uuid, on_delete: :delete_all), null: false
      add :started_at, :utc_datetime, null: false
      add :completed_at, :utc_datetime
      add :status, :string, null: false
      add :old_version, :string
      add :new_version, :string
      add :error_message, :text
      add :rollback_performed, :boolean, default: false
      add :duration_ms, :integer
      add :metadata, :map, default: %{}
    end

    create index(:rotation_history, [:rotation_schedule_id])
    create index(:rotation_history, [:started_at])
    create index(:rotation_history, [:status])
  end
end
