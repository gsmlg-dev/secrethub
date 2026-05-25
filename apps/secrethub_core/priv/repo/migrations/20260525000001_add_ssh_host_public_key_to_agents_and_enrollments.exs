defmodule SecretHub.Core.Repo.Migrations.AddSshHostPublicKeyToAgentsAndEnrollments do
  use Ecto.Migration

  def change do
    alter table(:agent_enrollments) do
      add(:ssh_host_public_key, :text)
    end

    alter table(:agents) do
      add(:ssh_host_public_key, :text)
    end
  end
end
