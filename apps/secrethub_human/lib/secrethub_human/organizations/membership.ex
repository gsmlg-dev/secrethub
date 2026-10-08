defmodule SecretHub.Human.Organizations.Membership do
  @moduledoc false
  use Ecto.Schema
  @primary_key {:id, :binary_id, autogenerate: true}
  schema "human_organization_members" do
    field(:organization_id, :binary_id)
    field(:user_id, :binary_id)
    field(:role, :string)
    field(:encrypted_key, :string, redact: true)
    field(:removed_at, :utc_datetime_usec)
    timestamps(type: :utc_datetime_usec)
  end
end
