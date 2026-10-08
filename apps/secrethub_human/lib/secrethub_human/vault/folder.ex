defmodule SecretHub.Human.Vault.Folder do
  @moduledoc false
  use Ecto.Schema
  @primary_key {:id, :binary_id, autogenerate: true}
  schema "vault_folders" do
    field(:user_id, :binary_id)
    field(:name, :string, redact: true)
    field(:revision, :integer)
    field(:deleted_at, :utc_datetime_usec)
    timestamps(type: :utc_datetime_usec)
  end
end
