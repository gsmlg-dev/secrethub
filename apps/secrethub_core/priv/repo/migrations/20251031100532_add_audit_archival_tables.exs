defmodule SecretHub.Core.Repo.Migrations.AddAuditArchivalTables do
  use Ecto.Migration

  def change do
    # Audit archival configuration
    create table(:audit_archival_configs, primary_key: false) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :provider, :string, null: false
      add :enabled, :boolean, default: false, null: false
      add :config, :map, default: %{}, null: false
      add :retention_days, :integer, default: 90
      add :archive_after_days, :integer, default: 30
      add :last_archival_at, :utc_datetime
      add :last_archival_status, :string
      add :last_archival_error, :text
      add :metadata, :map, default: %{}

      timestamps(type: :utc_datetime)
    end

    create unique_index(:audit_archival_configs, [:provider])

    # Audit archival jobs tracking
    create table(:audit_archival_jobs, primary_key: false) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :archival_config_id, references(:audit_archival_configs, type: :uuid, on_delete: :delete_all), null: false
      add :started_at, :utc_datetime, null: false
      add :completed_at, :utc_datetime
      add :status, :string, null: false
      add :from_date, :utc_datetime, null: false
      add :to_date, :utc_datetime, null: false
      add :records_archived, :integer, default: 0
      add :archive_location, :string
      add :checksum, :string
      add :error_message, :text
      add :duration_ms, :integer
      add :metadata, :map, default: %{}

      timestamps(type: :utc_datetime, updated_at: false)
    end

    create index(:audit_archival_jobs, [:archival_config_id])
    create index(:audit_archival_jobs, [:status])
    create index(:audit_archival_jobs, [:started_at])

    # Anomaly detection rules
    create table(:anomaly_detection_rules, primary_key: false) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :name, :string, null: false
      add :description, :text
      add :rule_type, :string, null: false
      add :enabled, :boolean, default: true, null: false
      add :severity, :string, default: "medium", null: false
      add :condition, :map, null: false
      add :threshold, :map, default: %{}
      add :alert_on_trigger, :boolean, default: true, null: false
      add :cooldown_minutes, :integer, default: 60
      add :last_triggered_at, :utc_datetime
      add :trigger_count, :integer, default: 0
      add :metadata, :map, default: %{}

      timestamps(type: :utc_datetime)
    end

    create unique_index(:anomaly_detection_rules, [:name])
    create index(:anomaly_detection_rules, [:enabled])
    create index(:anomaly_detection_rules, [:rule_type])

    # Anomaly detection alerts
    create table(:anomaly_alerts, primary_key: false) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :rule_id, references(:anomaly_detection_rules, type: :uuid, on_delete: :delete_all)
      add :triggered_at, :utc_datetime, null: false
      add :severity, :string, null: false
      add :status, :string, default: "open", null: false
      add :description, :text, null: false
      add :context, :map, default: %{}
      add :resolved_at, :utc_datetime
      add :resolved_by, :string
      add :resolution_notes, :text
      add :metadata, :map, default: %{}

      timestamps(type: :utc_datetime, updated_at: false)
    end

    create index(:anomaly_alerts, [:rule_id])
    create index(:anomaly_alerts, [:status])
    create index(:anomaly_alerts, [:severity])
    create index(:anomaly_alerts, [:triggered_at])

    # Alert routing configuration
    create table(:alert_routing_configs, primary_key: false) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :name, :string, null: false
      add :channel_type, :string, null: false
      add :enabled, :boolean, default: true, null: false
      add :severity_filter, {:array, :string}, default: []
      add :config, :map, null: false
      add :last_used_at, :utc_datetime
      add :metadata, :map, default: %{}

      timestamps(type: :utc_datetime)
    end

    create unique_index(:alert_routing_configs, [:name])
    create index(:alert_routing_configs, [:enabled])
  end
end
