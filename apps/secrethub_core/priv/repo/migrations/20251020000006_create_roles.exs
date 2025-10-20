defmodule SecretHub.Core.Repo.Migrations.CreateRoles do
  use Ecto.Migration

  def change do
    create table(:roles, primary_key: false) do
      add :id, :binary_id, primary_key: true

      # Role identification
      add :role_id, :binary_id, null: false
      add :role_name, :string, null: false

      # SecretID (hashed)
      add :secret_id_hash, :string
      add :secret_id_accessor, :string

      # Policy bindings
      add :policies, {:array, :string}, default: [], null: false
      add :token_policies, {:array, :string}, default: []

      # TTL configuration
      add :ttl_seconds, :integer, default: 3600
      add :max_ttl_seconds, :integer, default: 86400

      # Secret ID configuration
      add :bind_secret_id, :boolean, default: true
      add :secret_id_num_uses, :integer, default: 0
      add :secret_id_ttl_seconds, :integer

      # CIDR restrictions
      add :bound_cidr_list, {:array, :string}, default: []

      # Metadata
      add :metadata, :map, default: %{}
      add :description, :text

      # Enable/disable
      add :enabled, :boolean, default: true

      timestamps(type: :utc_datetime)
    end

    create unique_index(:roles, [:role_id])
    create unique_index(:roles, [:role_name])
    create unique_index(:roles, [:secret_id_accessor])
    create index(:roles, [:enabled])

    # GIN indexes for array searches
    create index(:roles, [:policies], using: :gin)
    create index(:roles, [:token_policies], using: :gin)
    create index(:roles, [:bound_cidr_list], using: :gin)
  end
end
