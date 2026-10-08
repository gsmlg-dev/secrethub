defmodule SecretHub.Human.Repo.Migrations.AddClientKeyIdentifier do
  use Ecto.Migration

  def change do
    alter table(:human_users) do
      add(:user_key_id, :string)
    end
  end
end
