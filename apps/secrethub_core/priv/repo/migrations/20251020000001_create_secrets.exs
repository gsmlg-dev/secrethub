defmodule SecretHub.Core.Repo.Migrations.CreateSecrets do
  use Ecto.Migration

  def change do
    create table(:secrets, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :secret_path, :string, size: 500, null: false
      add :secret_type, :string, null: false
      add :encrypted_data, :binary, null: false
      add :version, :integer, default: 1, null: false
      add :metadata, :map, default: %{}
      add :description, :text
      add :rotation_enabled, :boolean, default: false
      add :rotation_schedule, :string
      add :last_rotated_at, :utc_datetime

      timestamps(type: :utc_datetime)
    end

    create unique_index(:secrets, [:secret_path])
    create index(:secrets, [:secret_type])
    create index(:secrets, [:rotation_enabled])
    create index(:secrets, [:last_rotated_at])
  end
end
