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
  Parse a PEM-encoded certificate into a map of certificate attributes.

  Uses Erlang's `:public_key` module to decode and extract X.509 fields.

  ## Returns

    - `{:ok, attrs}` - Map with `:serial_number`, `:fingerprint`, `:subject`, `:issuer`,
      `:common_name`, `:organization`, `:valid_from`, `:valid_until`, `:cert_type`,
      `:key_usage`, and `:certificate_pem`
    - `{:error, reason}` - If PEM is invalid or contains no certificate
  """
  @spec from_pem(binary()) :: {:ok, map()} | {:error, String.t()}
  def from_pem(pem_string) when is_binary(pem_string) do
    case :public_key.pem_decode(pem_string) do
      [{:Certificate, der, _} | _] ->
        cert = :public_key.der_decode(:Certificate, der)
        tbs = elem(cert, 1)

        {:ok,
         %{
           serial_number: extract_serial_number(tbs),
           fingerprint: fingerprint_from_der(der),
           subject: format_dn(elem(tbs, 5)),
           issuer: format_dn(elem(tbs, 3)),
           common_name: extract_rdn_value(elem(tbs, 5), {2, 5, 4, 3}),
           organization: extract_rdn_value(elem(tbs, 5), {2, 5, 4, 10}),
           organizational_unit: extract_rdn_value(elem(tbs, 5), {2, 5, 4, 11}),
           valid_from: parse_validity_time(elem(elem(tbs, 4), 1)),
           valid_until: parse_validity_time(elem(elem(tbs, 4), 2)),
           key_usage: extract_key_usage(tbs),
           certificate_pem: pem_string
         }}

      [] ->
        {:error, "No certificate found in PEM data"}

      _ ->
        {:error, "Invalid PEM format"}
    end
  rescue
    e -> {:error, "Failed to parse certificate: #{Exception.message(e)}"}
  end

  @doc """
  Calculate the SHA-256 fingerprint of a DER-encoded certificate.
  """
  @spec fingerprint(binary()) :: String.t()
  def fingerprint(cert_der) when is_binary(cert_der) do
    fingerprint_from_der(cert_der)
  end

  def fingerprint(_), do: ""

  @doc """
  Calculate the SHA-256 fingerprint from a PEM-encoded certificate.
  """
  @spec fingerprint_from_pem(binary()) :: String.t()
  def fingerprint_from_pem(pem_string) when is_binary(pem_string) do
    case :public_key.pem_decode(pem_string) do
      [{:Certificate, der, _} | _] -> fingerprint_from_der(der)
      _ -> ""
    end
  rescue
    _ -> ""
  end

  # Private helpers for X.509 parsing

  defp fingerprint_from_der(der) do
    :crypto.hash(:sha256, der)
    |> Base.encode16(case: :lower)
    |> String.graphemes()
    |> Enum.chunk_every(2)
    |> Enum.join(":")
  end

  defp extract_serial_number(tbs) do
    serial = elem(tbs, 1)

    serial
    |> :binary.encode_unsigned()
    |> Base.encode16(case: :lower)
    |> String.graphemes()
    |> Enum.chunk_every(2)
    |> Enum.join(":")
  end

  defp format_dn({:rdnSequence, rdn_sequence}) do
    rdn_sequence
    |> List.flatten()
    |> Enum.map(fn {:AttributeTypeAndValue, oid, value} ->
      "#{oid_to_name(oid)}=#{decode_attr_value(value)}"
    end)
    |> Enum.join(", ")
  end

  defp format_dn(_), do: ""

  defp extract_rdn_value({:rdnSequence, rdn_sequence}, target_oid) do
    rdn_sequence
    |> List.flatten()
    |> Enum.find_value(fn
      {:AttributeTypeAndValue, ^target_oid, value} -> decode_attr_value(value)
      _ -> nil
    end)
  end

  defp extract_rdn_value(_, _), do: nil

  defp decode_attr_value({:utf8String, value}), do: to_string(value)
  defp decode_attr_value({:printableString, value}), do: to_string(value)
  defp decode_attr_value({:ia5String, value}), do: to_string(value)
  defp decode_attr_value({:teletexString, value}), do: to_string(value)
  defp decode_attr_value(value) when is_binary(value), do: value
  defp decode_attr_value(value) when is_list(value), do: to_string(value)
  defp decode_attr_value(value), do: inspect(value)

  defp oid_to_name({2, 5, 4, 3}), do: "CN"
  defp oid_to_name({2, 5, 4, 6}), do: "C"
  defp oid_to_name({2, 5, 4, 7}), do: "L"
  defp oid_to_name({2, 5, 4, 8}), do: "ST"
  defp oid_to_name({2, 5, 4, 10}), do: "O"
  defp oid_to_name({2, 5, 4, 11}), do: "OU"
  defp oid_to_name(oid), do: Enum.join(Tuple.to_list(oid), ".")

  defp parse_validity_time({:utcTime, time_charlist}) do
    str = to_string(time_charlist)
    # UTCTime: YYMMDDHHMMSSZ
    <<yy::binary-size(2), mm::binary-size(2), dd::binary-size(2), hh::binary-size(2),
      mi::binary-size(2), ss::binary-size(2), _rest::binary>> = str

    year = String.to_integer(yy)
    # RFC 5280: years 00-49 are 2000s, 50-99 are 1900s
    year = if year >= 50, do: 1900 + year, else: 2000 + year

    DateTime.new!(
      Date.new!(year, String.to_integer(mm), String.to_integer(dd)),
      Time.new!(String.to_integer(hh), String.to_integer(mi), String.to_integer(ss))
    )
    |> DateTime.truncate(:second)
  end

  defp parse_validity_time({:generalTime, time_charlist}) do
    str = to_string(time_charlist)
    # GeneralizedTime: YYYYMMDDHHMMSSZ
    <<yyyy::binary-size(4), mm::binary-size(2), dd::binary-size(2), hh::binary-size(2),
      mi::binary-size(2), ss::binary-size(2), _rest::binary>> = str

    DateTime.new!(
      Date.new!(String.to_integer(yyyy), String.to_integer(mm), String.to_integer(dd)),
      Time.new!(String.to_integer(hh), String.to_integer(mi), String.to_integer(ss))
    )
    |> DateTime.truncate(:second)
  end

  defp parse_validity_time(_), do: nil

  defp extract_key_usage(tbs) do
    # Extensions are the last element of TBSCertificate
    extensions = elem(tbs, 10)
    extract_key_usage_from_extensions(extensions)
  end

  defp extract_key_usage_from_extensions(:asn1_NOVALUE), do: []

  defp extract_key_usage_from_extensions(extensions) when is_list(extensions) do
    # OID for Extended Key Usage: 2.5.29.37
    eku_oid = {2, 5, 29, 37}

    extensions
    |> Enum.find_value([], fn
      {:Extension, ^eku_oid, _critical, value} ->
        case :public_key.der_decode(:ExtKeyUsageSyntax, value) do
          oids when is_list(oids) -> Enum.map(oids, &eku_oid_to_name/1)
          _ -> []
        end

      _ ->
        nil
    end)
  rescue
    _ -> []
  end

  defp extract_key_usage_from_extensions(_), do: []

  # Common Extended Key Usage OIDs
  defp eku_oid_to_name({1, 3, 6, 1, 5, 5, 7, 3, 1}), do: "serverAuth"
  defp eku_oid_to_name({1, 3, 6, 1, 5, 5, 7, 3, 2}), do: "clientAuth"
  defp eku_oid_to_name({1, 3, 6, 1, 5, 5, 7, 3, 3}), do: "codeSigning"
  defp eku_oid_to_name({1, 3, 6, 1, 5, 5, 7, 3, 4}), do: "emailProtection"
  defp eku_oid_to_name(oid), do: Enum.join(Tuple.to_list(oid), ".")
end
