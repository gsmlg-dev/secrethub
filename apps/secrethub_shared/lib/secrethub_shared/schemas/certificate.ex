defmodule SecretHub.Shared.Schemas.Certificate do
  @moduledoc """
  Schema for PKI certificate storage.

  Stores both CA certificates and client certificates issued to Agents and Applications.
  Used for mTLS authentication throughout the system.

  Certificate lifecycle:
  - Short-lived certificates (hours to days)
  - Automatic renewal before expiry
  - Revocation tracking with reason codes
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "certificates" do
    # Certificate identification
    field(:serial_number, :string)
    field(:fingerprint, :string)

    # Certificate data
    field(:certificate_pem, :string)
    field(:private_key_encrypted, :binary)

    # Certificate details
    field(:subject, :string)
    field(:issuer, :string)
    field(:common_name, :string)
    field(:organization, :string)
    field(:organizational_unit, :string)

    # Validity period
    field(:valid_from, :utc_datetime)
    field(:valid_until, :utc_datetime)

    # Certificate type and usage
    field(:cert_type, Ecto.Enum,
      values: [:root_ca, :intermediate_ca, :agent_client, :app_client, :admin_client]
    )

    field(:key_usage, {:array, :string}, default: [])

    # Revocation tracking
    field(:revoked, :boolean, default: false)
    field(:revoked_at, :utc_datetime)
    field(:revocation_reason, :string)

    # Issuer reference (for chain building)
    field(:issuer_id, :binary_id)

    # Entity binding (who owns this certificate)
    field(:entity_id, :string)
    field(:entity_type, :string)

    # Metadata
    field(:metadata, :map, default: %{})

    timestamps(type: :utc_datetime)
  end

  @doc """
  Changeset for creating or updating a certificate.
  """
  def changeset(certificate, attrs) do
    certificate
    |> cast(attrs, [
      :serial_number,
      :fingerprint,
      :certificate_pem,
      :private_key_encrypted,
      :subject,
      :issuer,
      :common_name,
      :organization,
      :organizational_unit,
      :valid_from,
      :valid_until,
      :cert_type,
      :key_usage,
      :revoked,
      :revoked_at,
      :revocation_reason,
      :issuer_id,
      :entity_id,
      :entity_type,
      :metadata
    ])
    |> validate_required([
      :serial_number,
      :fingerprint,
      :certificate_pem,
      :subject,
      :issuer,
      :common_name,
      :valid_from,
      :valid_until,
      :cert_type
    ])
    |> unique_constraint(:serial_number)
    |> unique_constraint(:fingerprint)
    |> validate_validity_period()
  end

  @doc """
  Changeset for revoking a certificate.
  """
  def revoke_changeset(certificate, reason) do
    certificate
    |> cast(
      %{
        revoked: true,
        revoked_at: DateTime.utc_now() |> DateTime.truncate(:second),
        revocation_reason: reason
      },
      [
        :revoked,
        :revoked_at,
        :revocation_reason
      ]
    )
    |> validate_required([:revoked, :revoked_at, :revocation_reason])
  end

  defp validate_validity_period(changeset) do
    valid_from = get_field(changeset, :valid_from)
    valid_until = get_field(changeset, :valid_until)

    if valid_from && valid_until && DateTime.compare(valid_from, valid_until) != :lt do
      add_error(changeset, :valid_until, "must be after valid_from")
    else
      changeset
    end
  end

  @doc """
  Parse a PEM-encoded certificate.

  TODO: Implement proper X.509 certificate parsing using :public_key module.
  """
  @spec from_pem(binary()) :: {:ok, map()} | {:error, String.t()}
  def from_pem(pem_string) when is_binary(pem_string) do
    # Placeholder implementation
    # TODO: Implement actual X.509 parsing with :public_key.pem_decode/1
    # For now, always return error
    if false do
      # This branch will be implemented in the future
      {:ok, %{}}
    else
      {:error, "Certificate parsing not yet implemented"}
    end
  end

  @doc """
  Calculate the fingerprint of a certificate.

  TODO: Implement SHA-256 fingerprint calculation from parsed certificate.
  """
  def fingerprint(_cert) do
    # Placeholder implementation
    ""
  end
end
