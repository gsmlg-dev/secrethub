defmodule SecretHub.Core.Repo.Migrations.CreatePolicies do
  use Ecto.Migration

  def change do
    create table(:policies, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :description, :text
      add :policy_document, :map, null: false
      add :entity_bindings, {:array, :string}, default: []
      add :max_ttl_seconds, :integer
      add :deny_policy, :boolean, default: false

      timestamps(type: :utc_datetime)
    end

    create unique_index(:policies, [:name])
    create index(:policies, [:deny_policy])

    # GIN index for JSONB policy_document for fast queries
    create index(:policies, [:policy_document], using: :gin)

    # GIN index for array searches on entity_bindings
    create index(:policies, [:entity_bindings], using: :gin)
  end
end
