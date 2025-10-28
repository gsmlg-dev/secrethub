defmodule SecretHub.Core.Repo.Migrations.CreateTemplatesAndSinks do
  use Ecto.Migration

  def change do
    # Templates table - stores template definitions
    create table(:templates, primary_key: false) do
      add :id, :uuid, primary_key: true
      add :name, :string, null: false
      add :description, :text
      add :template_content, :text, null: false
      add :variable_bindings, :map, null: false, default: %{}
      add :status, :string, null: false, default: "active"
      add :agent_id, :uuid
      add :created_by, :string
      add :version, :integer, null: false, default: 1

      timestamps(type: :utc_datetime)
    end

    create index(:templates, [:agent_id])
    create index(:templates, [:status])
    create unique_index(:templates, [:name])

    # Sinks table - stores sink configurations (where templates render to)
    create table(:sinks, primary_key: false) do
      add :id, :uuid, primary_key: true
      add :name, :string, null: false
      add :template_id, references(:templates, type: :uuid, on_delete: :delete_all), null: false
      add :file_path, :string, null: false
      add :permissions, :map, default: %{}
      add :backup_enabled, :boolean, default: false
      add :reload_trigger, :map
      add :status, :string, null: false, default: "active"
      add :last_write_at, :utc_datetime
      add :last_write_status, :string
      add :last_write_error, :text

      timestamps(type: :utc_datetime)
    end

    create index(:sinks, [:template_id])
    create index(:sinks, [:status])
    create index(:sinks, [:name])
    create unique_index(:sinks, [:template_id, :name])

    # Sink write history table - audit log for sink writes
    create table(:sink_write_history, primary_key: false) do
      add :id, :uuid, primary_key: true
      add :sink_id, references(:sinks, type: :uuid, on_delete: :delete_all), null: false
      add :write_status, :string, null: false
      add :content_hash, :string
      add :bytes_written, :integer
      add :error_message, :text
      add :reload_triggered, :boolean, default: false
      add :reload_status, :string

      timestamps(type: :utc_datetime, updated_at: false)
    end

    create index(:sink_write_history, [:sink_id])
    create index(:sink_write_history, [:inserted_at])
    create index(:sink_write_history, [:write_status])
  end
end
