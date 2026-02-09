defmodule SecretHub.Core.Repo.Migrations.AddAuthTypeToRoles do
  use Ecto.Migration

  def change do
    alter table(:roles) do
      add(:auth_type, :string, default: "approle")
    end

    create(index(:roles, [:auth_type]))
  end
end
