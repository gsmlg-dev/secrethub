defmodule SecretHub.Shared.Schemas.DNSChallengeOperation do
  @moduledoc "Dedicated public certificate lifecycle state; separate from internal identities."
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  schema "acme_dns_operations" do
    field(:order_id, :binary_id)
    field(:authorization_id, :binary_id)
    field(:provider_id, :binary_id)
    field(:provider_snapshot, :map)
    field(:original_owner, :string)
    field(:owner, :string)
    field(:value, :string)
    field(:state, :string, default: "intent")
    field(:intent, :map, default: %{})
    field(:receipt, :map, default: %{})
    field(:cleanup_status, :string, default: "pending")
    field(:claim_token, :binary_id)
    field(:claim_expires_at, :utc_datetime)
    field(:next_attempt_at, :utc_datetime)
    field(:last_error, :map, default: %{})
    timestamps(type: :utc_datetime)
  end

  def changeset(record, attrs) do
    record
    |> cast(attrs, [
      :order_id,
      :authorization_id,
      :provider_id,
      :provider_snapshot,
      :original_owner,
      :owner,
      :value,
      :state,
      :intent,
      :receipt,
      :cleanup_status,
      :claim_token,
      :claim_expires_at,
      :next_attempt_at,
      :last_error
    ])
    |> validate_required([
      :order_id,
      :authorization_id,
      :provider_id,
      :provider_snapshot,
      :original_owner,
      :owner,
      :value
    ])
    |> unique_constraint(:authorization_id)
  end
end
