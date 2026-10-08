defmodule SecretHub.Human.Organizations.Permission do
  @moduledoc false
  use Ecto.Schema
  @primary_key {:id, :binary_id, autogenerate: true}
  schema "human_collection_permissions" do
    field(:collection_id, :binary_id)
    field(:user_id, :binary_id)
    field(:can_read, :boolean)
    field(:can_write, :boolean)
    timestamps(type: :utc_datetime_usec)
  end
end
