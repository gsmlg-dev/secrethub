defmodule SecretHub.Human.Repo.Migrations.CreateHumanDynamicMetadata do
  use Ecto.Migration

  def change do
    create table(:human_dynamic_references, primary_key: false) do
      add(:id, :uuid, primary_key: true)
      add(:user_id, references(:human_users, type: :uuid, on_delete: :delete_all), null: false)
      add(:mount_id, :text, null: false)
      add(:role_id, :text, null: false)
      add(:display_name, :text)
      add(:requested_ttl, :integer, null: false)
      timestamps(type: :utc_datetime_usec)
    end

    create(index(:human_dynamic_references, [:user_id]))

    create table(:human_dynamic_leases, primary_key: false) do
      add(:id, :uuid, primary_key: true)
      add(:user_id, references(:human_users, type: :uuid, on_delete: :delete_all), null: false)
      add(:session_id, :uuid, null: false)
      add(:device_id, :uuid, null: false)
      add(:mount_id, :text, null: false)
      add(:role_id, :text, null: false)
      add(:status, :text, null: false)
      add(:expires_at, :utc_datetime_usec, null: false)
      add(:renewable, :boolean, null: false, default: false)
      timestamps(type: :utc_datetime_usec)
    end

    create(index(:human_dynamic_leases, [:user_id, :session_id]))
  end
end
