defmodule SecretHub.Core.Repo.Migrations.AddRevocationToCliAccessRequests do
  use Ecto.Migration

  def change do
    alter table(:cli_access_requests) do
      add(:revoked_by, :string)
      add(:revoked_at, :utc_datetime)
    end

    create(index(:cli_access_requests, [:status, :revoked_at]))
  end
end
