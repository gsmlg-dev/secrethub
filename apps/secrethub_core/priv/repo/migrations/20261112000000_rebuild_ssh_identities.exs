defmodule SecretHub.Core.Repo.Migrations.RebuildSSHIdentities do
  use Ecto.Migration

  # Production holds 0 identity rows. Rules referenced Agents as sources, so the
  # migration clears them; groups gain kinds when loaded.
  def up do
    drop(table(:ssh_identities))

    create table(:ssh_identities, primary_key: false) do
      add(:id, :binary_id, primary_key: true)
      add(:name, :string, null: false)
      add(:origin, :string, null: false)

      add(
        :agent_id,
        references(:agents, column: :agent_id, type: :string, on_delete: :delete_all)
      )

      add(:local_username, :string)
      add(:local_uid, :bigint)
      add(:status, :string, null: false)
      add(:rotation_days, :integer)
      add(:next_rotation_at, :utc_datetime)
      add(:requested_generation, :bigint, null: false, default: 1)
      add(:rotation_overdue, :boolean, null: false, default: false)
      timestamps(type: :utc_datetime)
    end

    create(unique_index(:ssh_identities, [:name]))
    create(unique_index(:ssh_identities, [:agent_id, :local_uid]))

    create(
      constraint(:ssh_identities, :ssh_identity_origin,
        check: """
        (origin = 'agent' AND agent_id IS NOT NULL AND local_username IS NOT NULL
          AND local_uid BETWEEN 0 AND 4294967295)
        OR (origin = 'external' AND agent_id IS NULL AND local_username IS NULL
          AND local_uid IS NULL)
        """
      )
    )

    create(
      constraint(:ssh_identities, :ssh_identity_status,
        check: "status IN ('pending', 'active', 'retired')"
      )
    )

    create(
      constraint(:ssh_identities, :ssh_identity_rotation_days,
        check: "rotation_days IS NULL OR rotation_days BETWEEN 1 AND 3650"
      )
    )

    create table(:ssh_identity_keys, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(:identity_id, references(:ssh_identities, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:generation, :bigint, null: false)
      add(:public_key, :text, null: false)
      add(:fingerprint, :string, null: false)
      add(:not_after, :utc_datetime)
      timestamps(type: :utc_datetime, updated_at: false)
    end

    create(unique_index(:ssh_identity_keys, [:fingerprint]))
    create(unique_index(:ssh_identity_keys, [:identity_id, :generation]))
    execute("UPDATE ssh_inventory SET rules = '{}'")
  end

  def down do
    drop(table(:ssh_identity_keys))
    drop(table(:ssh_identities))

    create table(:ssh_identities, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(
        :agent_id,
        references(:agents, column: :agent_id, type: :string, on_delete: :delete_all),
        null: false
      )

      add(:username, :string, null: false)
      add(:uid, :bigint, null: false)
      add(:public_key, :text, null: false)
      add(:fingerprint, :string, null: false)
      add(:private_key_encrypted, :binary, null: false)
      add(:key_revision, :bigint, null: false, default: 1)
      add(:active, :boolean, null: false, default: true)
      timestamps(type: :utc_datetime)
    end

    create(unique_index(:ssh_identities, [:agent_id, :username]))
    create(unique_index(:ssh_identities, [:agent_id, :uid]))
    create(unique_index(:ssh_identities, [:fingerprint]))
  end
end
