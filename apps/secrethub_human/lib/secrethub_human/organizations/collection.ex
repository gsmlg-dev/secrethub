defmodule SecretHub.Human.Organizations.Collection do
  @moduledoc false
  use Ecto.Schema
  @primary_key {:id, :binary_id, autogenerate: true}
  schema "human_collections" do
    field(:organization_id, :binary_id)
    field(:name, :string, redact: true)
    timestamps(type: :utc_datetime_usec)
  end
end
