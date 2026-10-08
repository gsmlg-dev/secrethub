defmodule SecretHub.Human.Vault.Version do
  @moduledoc false
  use Ecto.Schema
  @primary_key {:id, :binary_id, autogenerate: true}
  schema "vault_item_versions" do
    field(:item_id, :binary_id)
    field(:revision, :integer)
    field(:ciphertext, :map, redact: true)
    timestamps(type: :utc_datetime_usec, updated_at: false)
  end
end
