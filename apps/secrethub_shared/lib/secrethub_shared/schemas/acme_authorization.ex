defmodule SecretHub.Shared.Schemas.AcmeAuthorization do
  @moduledoc "Dedicated public certificate lifecycle state; separate from internal identities."
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  schema "acme_authorizations" do
    field(:order_id, :binary_id)
    field(:url, :string)
    field(:identifier, :string)
    field(:wildcard, :boolean, default: false)
    field(:challenge_url, :string)
    field(:token, :string)
    field(:status, :string, default: "pending")
    field(:expires_at, :utc_datetime)
    timestamps(type: :utc_datetime)
  end

  def changeset(record, attrs) do
    record
    |> cast(attrs, [
      :order_id,
      :url,
      :identifier,
      :wildcard,
      :challenge_url,
      :token,
      :status,
      :expires_at
    ])
    |> validate_required([:order_id, :url, :identifier, :status])
    |> unique_constraint([:order_id, :url])
  end
end
