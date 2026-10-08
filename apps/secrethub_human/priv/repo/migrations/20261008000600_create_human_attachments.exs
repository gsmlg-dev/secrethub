defmodule SecretHub.Human.Repo.Migrations.CreateHumanAttachments do
  use Ecto.Migration

  def change do
    create table(:human_attachment_usage, primary_key: false) do
      add(:user_id, references(:human_users, type: :uuid, on_delete: :delete_all),
        primary_key: true
      )

      add(:bytes, :bigint, null: false, default: 0)
    end

    create(
      constraint(:human_attachment_usage, :nonnegative_attachment_usage, check: "bytes >= 0")
    )

    create table(:human_attachments, primary_key: false) do
      add(:id, :uuid, primary_key: true)
      add(:user_id, references(:human_users, type: :uuid, on_delete: :delete_all), null: false)
      add(:item_id, references(:vault_items, type: :uuid, on_delete: :delete_all), null: false)
      add(:filename, :text, null: false)
      add(:encrypted_key, :text, null: false)
      add(:byte_size, :bigint, null: false)
      add(:deleted_at, :utc_datetime_usec)
      timestamps(type: :utc_datetime_usec)
    end

    create(index(:human_attachments, [:user_id, :item_id]))
  end
end
