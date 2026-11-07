defmodule SecretHub.Human.Repo.Migrations.ReplaceObanWithStyx do
  use Ecto.Migration

  def up, do: SecretHub.Core.Repo.StyxMigration.upgrade(prefix())
  def down, do: SecretHub.Core.Repo.StyxMigration.rollback(prefix())
end
