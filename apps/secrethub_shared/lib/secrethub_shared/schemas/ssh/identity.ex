defmodule SecretHub.Shared.Schemas.SSH.Identity do
  @moduledoc "Dedicated encrypted SSH user identity. Never readable through the generic secrets API."
  use Ecto.Schema
  @primary_key {:id, :binary_id, autogenerate: true}
  schema "ssh_identities" do
    field(:agent_id, :string)
    field(:username, :string)
    field(:uid, :integer)
    field(:public_key, :string)
    field(:fingerprint, :string)
    field(:private_key_encrypted, :binary, redact: true)
    field(:key_revision, :integer, default: 1)
    field(:active, :boolean, default: true)
    timestamps(type: :utc_datetime)
  end
end
