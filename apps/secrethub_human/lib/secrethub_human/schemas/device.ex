defmodule SecretHub.Human.Schemas.Device do
  @moduledoc false
  use Ecto.Schema
  @primary_key {:id, :binary_id, autogenerate: true}

  schema "human_devices" do
    field(:user_id, :binary_id)
    field(:identifier, :string)
    field(:name, :string)
    field(:type, :integer, default: 9)
    field(:removed_at, :utc_datetime_usec)
    timestamps(type: :utc_datetime_usec)
  end
end
