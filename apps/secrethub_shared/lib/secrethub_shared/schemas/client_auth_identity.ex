defmodule SecretHub.Shared.Schemas.ClientAuthIdentity do
  @moduledoc """
  Schema for canonical Client Authentication Identity.

  Each identity has a stable UUID encoded as the CN and URI SAN in client
  certificates (`urn:secrethub:client:<UUID>`).
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @allowed_statuses ["active", "disabled"]

  schema "client_auth_identities" do
    field(:name, :string)
    field(:status, :string, default: "active")
    field(:metadata, :map, default: %{})

    has_many(:certificates, SecretHub.Shared.Schemas.Certificate,
      foreign_key: :client_auth_identity_id
    )

    has_many(:issuance_requests, SecretHub.Shared.Schemas.ClientAuthIssuanceRequest,
      foreign_key: :identity_id
    )

    timestamps(type: :utc_datetime)
  end

  @type t :: %__MODULE__{}

  def changeset(identity, attrs) do
    identity
    |> cast(attrs, [:name, :status, :metadata])
    |> validate_required([:name, :status])
    |> validate_inclusion(:status, @allowed_statuses)
    |> unique_constraint(:name)
  end
end
