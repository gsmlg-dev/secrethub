defmodule SecretHub.Core.Repo.Migrations.CreateAgentEnrollments do
  use Ecto.Migration

  def change do
    create table(:agent_enrollments, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :agent_id, :string
      add :status, :string, null: false, default: "pending_registered"

      add :hostname, :string
      add :fqdn, :string
      add :machine_id, :string
      add :os, :string
      add :arch, :string
      add :agent_version, :string
      add :ssh_host_key_algorithm, :string, null: false
      add :ssh_host_key_fingerprint, :string, null: false
      add :source_ip, :string
      add :capabilities, :map, default: %{}

      add :pending_token_hash, :string, null: false
      add :required_csr_fields, :map, default: %{}
      add :csr_pem, :text
      add :last_error, :map

      add :approved_by, :string
      add :approved_at, :utc_datetime
      add :rejected_by, :string
      add :rejected_at, :utc_datetime
      add :expires_at, :utc_datetime, null: false

      timestamps(type: :utc_datetime)
    end

    create index(:agent_enrollments, [:status])
    create index(:agent_enrollments, [:agent_id])
    create index(:agent_enrollments, [:ssh_host_key_fingerprint])
    create index(:agent_enrollments, [:expires_at])
  end
end
