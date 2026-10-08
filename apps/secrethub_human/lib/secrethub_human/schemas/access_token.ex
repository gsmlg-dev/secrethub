defmodule SecretHub.Human.Schemas.AccessToken do
  @moduledoc false
  use Ecto.Schema
  @primary_key false

  schema "human_access_tokens" do
    field(:digest, :binary, primary_key: true, redact: true)
    field(:session_id, :binary_id)
    field(:expires_at, :utc_datetime_usec)
  end
end
