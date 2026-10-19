defmodule SecretHub.Core.Repo.Migrations.CreateSSHAccess do
  use Ecto.Migration

  def change do
    create table(:ssh_inventory, primary_key: false) do
      add(:id, :integer, primary_key: true)
      add(:revision, :bigint, null: false, default: 0)
      add(:groups, {:array, :map}, null: false, default: [])
      add(:endpoints, {:array, :map}, null: false, default: [])
      add(:rules, {:array, :map}, null: false, default: [])
      add(:reports, :map, null: false, default: %{})
    end

    create(
      constraint(:ssh_inventory, :ssh_inventory_singleton, check: "id = 1 AND revision >= 0")
    )

    execute(
      "INSERT INTO ssh_inventory (id, revision, groups, endpoints, rules) VALUES (1, 0, '{}', '{}', '{}')",
      "DELETE FROM ssh_inventory WHERE id = 1"
    )

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

    create(
      constraint(:ssh_identities, :ssh_identity_uid_range,
        check: "uid >= 0 AND uid <= 4294967295"
      )
    )
  end
end
