defmodule SecretHub.Human.DynamicSecrets.Reference do
  @moduledoc false
  use Ecto.Schema
  @primary_key {:id, :binary_id, autogenerate: true}
  schema "human_dynamic_references" do
    field(:user_id, :binary_id)
    field(:mount_id, :string)
    field(:role_id, :string)
    field(:display_name, :string)
    field(:requested_ttl, :integer)
    timestamps(type: :utc_datetime_usec)
  end
end
