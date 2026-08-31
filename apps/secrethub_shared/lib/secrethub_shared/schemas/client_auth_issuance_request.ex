defmodule SecretHub.Shared.Schemas.ClientAuthIssuanceRequest do
  @moduledoc """
  Schema for idempotent client certificate issuance requests.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "client_auth_issuance_requests" do
    field(:request_id, Ecto.UUID)
    field(:csr_sha256, :binary)
    field(:requested_ttl_seconds, :integer)

    belongs_to(:identity, SecretHub.Shared.Schemas.ClientAuthIdentity, foreign_key: :identity_id)

    belongs_to(:certificate, SecretHub.Shared.Schemas.Certificate, foreign_key: :certificate_id)

    timestamps(type: :utc_datetime)
  end

  @type t :: %__MODULE__{}

  def changeset(request, attrs) do
    request
    |> cast(attrs, [
      :request_id,
      :identity_id,
      :csr_sha256,
      :requested_ttl_seconds,
      :certificate_id
    ])
    |> validate_required([
      :request_id,
      :identity_id,
      :csr_sha256,
      :requested_ttl_seconds,
      :certificate_id
    ])
    |> validate_csr_sha256()
    |> unique_constraint(:request_id)
  end

  defp validate_csr_sha256(changeset) do
    case get_field(changeset, :csr_sha256) do
      binary when is_binary(binary) and byte_size(binary) == 32 -> changeset
      nil -> changeset
      _ -> add_error(changeset, :csr_sha256, "must be 32 bytes")
    end
  end
end
