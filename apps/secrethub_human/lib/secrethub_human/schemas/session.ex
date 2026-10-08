defmodule SecretHub.Human.Schemas.Session do
  @moduledoc false
  use Ecto.Schema
  @primary_key {:id, :binary_id, autogenerate: true}

  schema "human_sessions" do
    field(:user_id, :binary_id)
    field(:device_id, :binary_id)
    field(:access_digest, :binary, redact: true)
    field(:refresh_digest, :binary, redact: true)
    field(:expires_at, :utc_datetime_usec)
    field(:refresh_expires_at, :utc_datetime_usec)
    field(:revoked_at, :utc_datetime_usec)
    timestamps(type: :utc_datetime_usec)
  end
end
