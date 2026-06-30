defmodule SecretHub.Core.Repo.Migrations.CreateCliAccessRequests do
  use Ecto.Migration

  def change do
    create table(:cli_access_requests, primary_key: false) do
      add(:id, :binary_id, primary_key: true)
      add(:request_id, :uuid, null: false)
      add(:user_code, :string, null: false, size: 6)
      add(:status, :string, null: false, default: "pending")
      add(:role_id, :uuid)
      add(:source_ip, :string)
      add(:metadata, :map, default: %{}, null: false)
      add(:approved_by, :string)
      add(:approved_at, :utc_datetime)
      add(:rejected_by, :string)
      add(:rejected_at, :utc_datetime)
      add(:consumed_at, :utc_datetime)
      add(:expires_at, :utc_datetime, null: false)

      timestamps(type: :utc_datetime)
    end

    create(unique_index(:cli_access_requests, [:request_id]))
    create(index(:cli_access_requests, [:status, :expires_at]))
    create(index(:cli_access_requests, [:role_id]))

    create(
      unique_index(:cli_access_requests, [:user_code], where: "status IN ('pending', 'approved')")
    )
  end
end
