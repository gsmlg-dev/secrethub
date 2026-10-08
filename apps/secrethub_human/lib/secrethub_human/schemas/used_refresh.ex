defmodule SecretHub.Human.Schemas.UsedRefresh do
  @moduledoc false
  use Ecto.Schema
  @primary_key {:digest, :binary, autogenerate: false}
  schema "human_used_refresh_tokens" do
    field(:session_id, :binary_id)
    field(:expires_at, :utc_datetime_usec)
  end
end
