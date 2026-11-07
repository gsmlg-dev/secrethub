defmodule SecretHub.Core.Repo.Migrations.InstallCoreOban do
  use Ecto.Migration

  # Fresh installs use Styx; existing Oban v14 databases transition separately.
  def up, do: SecretHub.Core.Repo.StyxMigration.install(prefix())
  def down, do: SecretHub.Core.Repo.StyxMigration.uninstall(prefix())
end
