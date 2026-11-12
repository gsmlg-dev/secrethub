defmodule SecretHub.Shared.Schemas.SSH.Identity do
  @moduledoc """
  SSH source identity. Stores public keys only: Agent identities keep their
  private key on the device; external identities are held by their owner.
  """
  use Ecto.Schema
  alias SecretHub.Shared.Schemas.SSH.IdentityKey

  @primary_key {:id, :binary_id, autogenerate: false}
  schema "ssh_identities" do
    field(:name, :string)
    field(:origin, :string)
    field(:agent_id, :string)
    field(:local_username, :string)
    field(:local_uid, :integer)
    field(:status, :string, default: "pending")
    field(:rotation_days, :integer, default: 90)
    field(:next_rotation_at, :utc_datetime)
    field(:requested_generation, :integer, default: 1)
    field(:rotation_overdue, :boolean, default: false)
    has_many(:keys, IdentityKey, foreign_key: :identity_id, preload_order: [asc: :generation])
    timestamps(type: :utc_datetime)
  end
end
