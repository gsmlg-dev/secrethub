defmodule SecretHub.Core.Repo.Migrations.AddEngineHealthChecksTable do
  use Ecto.Migration

  def change do
    create table(:engine_health_checks, primary_key: false) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :engine_configuration_id, references(:engine_configurations, type: :uuid, on_delete: :delete_all), null: false
      add :checked_at, :utc_datetime, null: false
      add :status, :string, null: false
      add :response_time_ms, :integer
      add :error_message, :text
      add :metadata, :map, default: %{}
    end

    create index(:engine_health_checks, [:engine_configuration_id])
    create index(:engine_health_checks, [:checked_at])
    create index(:engine_health_checks, [:status])
    create index(:engine_health_checks, [:engine_configuration_id, :checked_at])
  end
end
