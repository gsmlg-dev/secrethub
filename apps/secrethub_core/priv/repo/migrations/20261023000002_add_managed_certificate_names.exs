defmodule SecretHub.Core.Repo.Migrations.AddManagedCertificateNames do
  use Ecto.Migration

  def change do
    alter table(:managed_certificates) do
      add(:name, :string, size: 255)
    end

    create(unique_index(:managed_certificates, [:name], where: "name IS NOT NULL"))
  end
end
