defmodule SecretHub.Human.Schemas.Identity do
  @moduledoc false
  use Ecto.Schema
  @primary_key {:id, :binary_id, autogenerate: true}

  schema "human_identities" do
    field(:user_id, :binary_id)
    field(:provider, :string, default: "password")
    field(:password_digest, :binary, redact: true)
    field(:password_salt, :binary, redact: true)
    field(:password_iterations, :integer)
    field(:mfa_enabled, :boolean, default: false)
    field(:mfa_methods, :map, default: %{}, redact: true)
    timestamps(type: :utc_datetime_usec)
  end
end
