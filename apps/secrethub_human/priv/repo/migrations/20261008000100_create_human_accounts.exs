defmodule SecretHub.Human.Repo.Migrations.CreateHumanAccounts do
  use Ecto.Migration

  def change do
    create table(:human_users, primary_key: false) do
      add(:id, :binary_id, primary_key: true)
      add(:email, :text, null: false)
      add(:name, :text)
      add(:encrypted_key, :text, null: false)
      add(:public_key, :text)
      add(:encrypted_private_key, :text)
      add(:kdf, :integer, default: 0, null: false)
      add(:kdf_iterations, :integer, default: 600_000, null: false)
      add(:disabled_at, :utc_datetime_usec)
      timestamps(type: :utc_datetime_usec)
    end

    create(unique_index(:human_users, [:email]))

    create table(:human_identities, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(:user_id, references(:human_users, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:provider, :text, default: "password", null: false)
      add(:password_digest, :binary, null: false)
      add(:password_salt, :binary, null: false)
      add(:password_iterations, :integer, null: false)
      add(:mfa_enabled, :boolean, default: false, null: false)
      add(:mfa_methods, :map, default: %{}, null: false)
      timestamps(type: :utc_datetime_usec)
    end

    create(unique_index(:human_identities, [:user_id, :provider]))

    create table(:human_devices, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(:user_id, references(:human_users, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:identifier, :text, null: false)
      add(:name, :text)
      add(:type, :integer, default: 9, null: false)
      add(:removed_at, :utc_datetime_usec)
      timestamps(type: :utc_datetime_usec)
    end

    create(unique_index(:human_devices, [:user_id, :identifier]))
    create(unique_index(:human_devices, [:id, :user_id]))

    create table(:human_sessions, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(:user_id, references(:human_users, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(
        :device_id,
        references(:human_devices,
          type: :binary_id,
          with: [user_id: :user_id],
          match: :full,
          on_delete: :delete_all
        ),
        null: false
      )

      add(:access_digest, :binary, null: false)
      add(:refresh_digest, :binary, null: false)
      add(:expires_at, :utc_datetime_usec, null: false)
      add(:refresh_expires_at, :utc_datetime_usec, null: false)
      add(:revoked_at, :utc_datetime_usec)
      timestamps(type: :utc_datetime_usec)
    end

    create(unique_index(:human_sessions, [:access_digest]))
    create(unique_index(:human_sessions, [:refresh_digest]))
    create(index(:human_sessions, [:user_id, :device_id]))
  end
end
