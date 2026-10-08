defmodule SecretHub.Human.Organizations.SharedItem do
  @moduledoc false
  use Ecto.Schema
  @primary_key {:id, :binary_id, autogenerate: true}
  schema "human_collection_items" do
    field(:organization_id, :binary_id)
    field(:collection_id, :binary_id)
    field(:type, :string)
    field(:ciphertext, :map, redact: true)
    field(:revision, :integer)
    field(:deleted_at, :utc_datetime_usec)
    timestamps(type: :utc_datetime_usec)
  end
end
