defmodule SecretHub.Shared.Schemas.SSH.IdentityKey do
  @moduledoc "One public key generation of an SSH identity. A non-nil not_after marks it superseded."
  use Ecto.Schema

  @primary_key {:id, :binary_id, autogenerate: false}
  schema "ssh_identity_keys" do
    belongs_to(:identity, SecretHub.Shared.Schemas.SSH.Identity, type: :binary_id)
    field(:generation, :integer)
    field(:public_key, :string)
    field(:fingerprint, :string)
    field(:not_after, :utc_datetime)
    timestamps(type: :utc_datetime, updated_at: false)
  end
end
