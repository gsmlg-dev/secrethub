defmodule SecretHub.Core.Repo.Migrations.AddIssuerIdToCertificates do
  use Ecto.Migration

  def change do
    alter table(:certificates) do
      add(:issuer_id, :binary_id)
    end

    create(index(:certificates, [:issuer_id]))
  end
end
