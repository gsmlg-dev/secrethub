defmodule SecretHub.Core.Repo.Migrations.ExtendAgentsForHostIdentity do
  use Ecto.Migration

  def change do
    alter table(:agents) do
      add :fqdn, :string
      add :machine_id, :string
      add :ssh_host_key_algorithm, :string
      add :ssh_host_key_fingerprint, :string
    end

    create index(:agents, [:machine_id])
    create index(:agents, [:ssh_host_key_fingerprint])
  end
end
