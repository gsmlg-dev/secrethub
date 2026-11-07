defmodule SecretHub.Human.Repo.Migrations.CreateHumanJobs do
  use Ecto.Migration
  def up, do: SecretHub.Core.Repo.StyxMigration.install(prefix())
  def down, do: SecretHub.Core.Repo.StyxMigration.uninstall(prefix())
end
