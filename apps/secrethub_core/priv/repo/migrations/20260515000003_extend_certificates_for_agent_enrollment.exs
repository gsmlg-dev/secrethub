defmodule SecretHub.Core.Repo.Migrations.ExtendCertificatesForAgentEnrollment do
  use Ecto.Migration

  def change do
    alter table(:certificates) do
      add :enrollment_id, references(:agent_enrollments, type: :binary_id, on_delete: :nilify_all)
      add :ssh_host_key_fingerprint, :string
    end

    create index(:certificates, [:enrollment_id])
    create index(:certificates, [:ssh_host_key_fingerprint])
  end
end
