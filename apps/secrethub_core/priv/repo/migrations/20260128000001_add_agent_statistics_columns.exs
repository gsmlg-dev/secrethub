defmodule SecretHub.Core.Repo.Migrations.AddAgentStatisticsColumns do
  use Ecto.Migration

  def change do
    alter table(:agents) do
      add :connection_count, :integer, default: 0
      add :secret_access_count, :integer, default: 0
      add :last_secret_access_at, :utc_datetime
    end
  end
end
