defmodule SecretHub.Human.Repo.Migrations.CreateHumanOrganizations do
  use Ecto.Migration

  def change do
    create table(:human_organizations, primary_key: false) do
      add(:id, :uuid, primary_key: true)
      add(:name, :text, null: false)
      timestamps(type: :utc_datetime_usec)
    end

    create table(:human_organization_members, primary_key: false) do
      add(:id, :uuid, primary_key: true)

      add(:organization_id, references(:human_organizations, type: :uuid, on_delete: :delete_all),
        null: false
      )

      add(:user_id, references(:human_users, type: :uuid, on_delete: :delete_all), null: false)
      add(:role, :string, null: false)
      add(:encrypted_key, :text, null: false)
      add(:removed_at, :utc_datetime_usec)
      timestamps(type: :utc_datetime_usec)
    end

    create(unique_index(:human_organization_members, [:organization_id, :user_id]))

    create(
      constraint(:human_organization_members, :human_member_role,
        check: "role IN ('owner', 'admin', 'member')"
      )
    )

    create table(:human_collections, primary_key: false) do
      add(:id, :uuid, primary_key: true)

      add(:organization_id, references(:human_organizations, type: :uuid, on_delete: :delete_all),
        null: false
      )

      add(:name, :text, null: false)
      timestamps(type: :utc_datetime_usec)
    end

    create(unique_index(:human_collections, [:id, :organization_id]))

    create table(:human_collection_permissions, primary_key: false) do
      add(:id, :uuid, primary_key: true)

      add(:collection_id, references(:human_collections, type: :uuid, on_delete: :delete_all),
        null: false
      )

      add(:user_id, references(:human_users, type: :uuid, on_delete: :delete_all), null: false)
      add(:can_read, :boolean, null: false, default: false)
      add(:can_write, :boolean, null: false, default: false)
      timestamps(type: :utc_datetime_usec)
    end

    create(unique_index(:human_collection_permissions, [:collection_id, :user_id]))

    create(
      constraint(:human_collection_permissions, :human_permission_write_requires_read,
        check: "NOT can_write OR can_read"
      )
    )

    create table(:human_collection_items, primary_key: false) do
      add(:id, :uuid, primary_key: true)

      add(:organization_id, references(:human_organizations, type: :uuid, on_delete: :delete_all),
        null: false
      )

      add(
        :collection_id,
        references(:human_collections,
          type: :uuid,
          with: [organization_id: :organization_id],
          on_delete: :delete_all
        ),
        null: false
      )

      add(:type, :string, null: false)
      add(:ciphertext, :map, null: false)
      add(:revision, :bigint, null: false, default: 1)
      add(:deleted_at, :utc_datetime_usec)
      timestamps(type: :utc_datetime_usec)
    end

    create(index(:human_collection_items, [:collection_id]))

    create table(:human_organization_dynamic_references, primary_key: false) do
      add(:id, :uuid, primary_key: true)

      add(:organization_id, references(:human_organizations, type: :uuid, on_delete: :delete_all),
        null: false
      )

      add(
        :collection_id,
        references(:human_collections,
          type: :uuid,
          with: [organization_id: :organization_id],
          on_delete: :delete_all
        ),
        null: false
      )

      add(:mount_id, :string, null: false)
      add(:role_id, :string, null: false)
      add(:requested_ttl, :integer, null: false)
      timestamps(type: :utc_datetime_usec)
    end
  end
end
