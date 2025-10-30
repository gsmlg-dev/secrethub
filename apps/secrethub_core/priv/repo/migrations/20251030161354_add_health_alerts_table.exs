defmodule SecretHub.Core.Repo.Migrations.AddHealthAlertsTable do
  use Ecto.Migration

  def change do
    create table(:health_alerts, primary_key: false) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :name, :string, null: false
      add :alert_type, :string, null: false
      add :threshold_value, :float
      add :threshold_operator, :string
      add :enabled, :boolean, default: true, null: false
      add :cooldown_minutes, :integer, default: 5, null: false
      add :last_triggered_at, :utc_datetime
      add :notification_channels, {:array, :string}, default: []
      add :metadata, :map, default: %{}

      timestamps(type: :utc_datetime)
    end

    # Index for querying enabled alerts
    create index(:health_alerts, [:enabled])

    # Index for querying by alert type
    create index(:health_alerts, [:alert_type])

    # Unique constraint on alert names
    create unique_index(:health_alerts, [:name])
  end
end
