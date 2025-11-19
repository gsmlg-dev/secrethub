defmodule SecretHub.Core.Repo.Migrations.AddEngineConfigurationsTable do
  use Ecto.Migration

  def change do
    create table(:engine_configurations, primary_key: false) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :name, :string, null: false
      add :engine_type, :string, null: false
      add :description, :text
      add :enabled, :boolean, default: true, null: false
      add :config, :map, default: %{}, null: false
      add :health_check_enabled, :boolean, default: true, null: false
      add :health_check_interval_seconds, :integer, default: 60
      add :last_health_check_at, :utc_datetime
      add :health_status, :string, default: "unknown"
      add :health_message, :text
      add :metadata, :map, default: %{}

      timestamps(type: :utc_datetime)
    end

    create unique_index(:engine_configurations, [:name])
    create index(:engine_configurations, [:engine_type])
    create index(:engine_configurations, [:enabled])
    create index(:engine_configurations, [:health_status])
  end
end
