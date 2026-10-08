defmodule SecretHub.Human.Vault.Item do
  @moduledoc false
  use Ecto.Schema
  @primary_key {:id, :binary_id, autogenerate: true}
  schema "vault_items" do
    field(:user_id, :binary_id)
    field(:folder_id, :binary_id)
    field(:type, :string)
    field(:ciphertext, :map, redact: true)
    field(:favorite, :boolean, default: false)
    field(:revision, :integer)
    field(:deleted_at, :utc_datetime_usec)
    timestamps(type: :utc_datetime_usec)
  end
end
