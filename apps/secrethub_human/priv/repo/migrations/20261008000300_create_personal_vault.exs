defmodule SecretHub.Human.Repo.Migrations.CreatePersonalVault do
  use Ecto.Migration

  def change do
    create table(:vault_heads, primary_key: false) do
      add(:user_id, references(:human_users, type: :uuid, on_delete: :delete_all),
        primary_key: true
      )

      add(:revision, :bigint, null: false, default: 0)
    end

    create table(:vault_folders, primary_key: false) do
      add(:id, :uuid, primary_key: true)
      add(:user_id, references(:human_users, type: :uuid, on_delete: :delete_all), null: false)
      add(:name, :text, null: false)
      add(:revision, :bigint, null: false)
      add(:deleted_at, :utc_datetime_usec)
      timestamps(type: :utc_datetime_usec)
    end

    create(unique_index(:vault_folders, [:id, :user_id]))
    create(index(:vault_folders, [:user_id, :revision]))

    create table(:vault_items, primary_key: false) do
      add(:id, :uuid, primary_key: true)
      add(:user_id, references(:human_users, type: :uuid, on_delete: :delete_all), null: false)

      add(
        :folder_id,
        references(:vault_folders, type: :uuid, with: [user_id: :user_id], on_delete: :nothing)
      )

      add(:type, :string, null: false)
      add(:ciphertext, :map, null: false)
      add(:favorite, :boolean, null: false, default: false)
      add(:revision, :bigint, null: false)
      add(:deleted_at, :utc_datetime_usec)
      timestamps(type: :utc_datetime_usec)
    end

    create(index(:vault_items, [:user_id, :revision]))

    create table(:vault_item_versions, primary_key: false) do
      add(:id, :uuid, primary_key: true)
      add(:item_id, references(:vault_items, type: :uuid, on_delete: :delete_all), null: false)
      add(:revision, :bigint, null: false)
      add(:ciphertext, :map, null: false)
      timestamps(type: :utc_datetime_usec, updated_at: false)
    end

    create(unique_index(:vault_item_versions, [:item_id, :revision]))
  end
end
