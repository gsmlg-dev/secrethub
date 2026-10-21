defmodule SecretHub.Core.Repo.Migrations.InstallCoreOban do
  use Ecto.Migration

  # Oban 2.24 uses PostgreSQL migration 14. Human owns a different repository.
  def up, do: Oban.Migration.up(version: 14)
  def down, do: Oban.Migration.down(version: 1)
end
