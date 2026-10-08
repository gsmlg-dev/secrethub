defmodule SecretHub.Human.Schemas.User do
  @moduledoc false
  use Ecto.Schema
  @primary_key {:id, :binary_id, autogenerate: true}

  schema "human_users" do
    field(:email, :string)
    field(:name, :string)
    field(:encrypted_key, :string, redact: true)
    field(:public_key, :string)
    field(:user_key_id, :string)
    field(:encrypted_private_key, :string, redact: true)
    field(:kdf, :integer, default: 0)
    field(:kdf_iterations, :integer, default: 600_000)
    field(:disabled_at, :utc_datetime_usec)
    timestamps(type: :utc_datetime_usec)
  end
end
