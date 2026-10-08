defmodule SecretHub.Core.Repo.Migrations.AddOrganizationHumanGrants do
  use Ecto.Migration

  def change do
    alter table(:core_human_grants) do
      modify(:subject_id, :uuid, null: true, from: {:uuid, null: false})
      add(:organization_id, :uuid)
    end

    create(unique_index(:core_human_grants, [:organization_id, :mount_id, :role_id]))

    create(
      constraint(:core_human_grants, :human_grant_one_scope,
        check: "(subject_id IS NULL) <> (organization_id IS NULL)"
      )
    )

    alter table(:core_human_leases) do
      add(:organization_id, :uuid)
    end

    create(index(:core_human_leases, [:organization_id, :subject_id, :status]))
  end
end
