defmodule SecretHub.Human.DynamicSecrets.Lease do
  @moduledoc false
  use Ecto.Schema
  @primary_key {:id, :binary_id, autogenerate: false}
  schema "human_dynamic_leases" do
    field(:user_id, :binary_id)
    field(:session_id, :binary_id)
    field(:device_id, :binary_id)
    field(:mount_id, :string)
    field(:role_id, :string)
    field(:status, :string)
    field(:expires_at, :utc_datetime_usec)
    field(:renewable, :boolean, default: false)
    timestamps(type: :utc_datetime_usec)
  end
end
