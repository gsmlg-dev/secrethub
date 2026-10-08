defmodule SecretHub.Human.Organizations.DynamicReference do
  @moduledoc false
  use Ecto.Schema
  @primary_key {:id, :binary_id, autogenerate: true}
  schema "human_organization_dynamic_references" do
    field(:organization_id, :binary_id)
    field(:collection_id, :binary_id)
    field(:mount_id, :string)
    field(:role_id, :string)
    field(:requested_ttl, :integer)
    timestamps(type: :utc_datetime_usec)
  end
end
