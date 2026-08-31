defmodule SecretHub.Core.PKI.ClientAuth.TrustBundle do
  @moduledoc """
  Generates deterministic public trust bundles for Client Authentication PKI.

  The bundle includes:
  - CA certificate PEM & canonical fingerprint
  - Current signed CRL PEM, number, and DER fingerprint
  - Generation and update timestamps
  - Deterministic SHA-256 transcript hash of the bundle content
  """

  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.{Certificate, ClientAuthAuthority, ClientAuthCrl}
  import Ecto.Query

  @schema_version 1

  @doc """
  Builds a deterministic map for a given authority, CA certificate, and CRL.
  """
  @spec build(ClientAuthAuthority.t(), Certificate.t(), ClientAuthCrl.t()) :: map()
  def build(%ClientAuthAuthority{} = authority, %Certificate{} = ca, %ClientAuthCrl{} = crl) do
    this_update_iso = DateTime.to_iso8601(crl.this_update)
    next_update_iso = DateTime.to_iso8601(crl.next_update)

    fields_for_hash = %{
      "schema_version" => @schema_version,
      "authority" => authority.slug,
      "generation" => authority.current_generation,
      "ca_fingerprint" => ca.canonical_fingerprint,
      "crl_number" => crl.crl_number,
      "crl_der_sha256" => crl.crl_der_sha256,
      "this_update" => this_update_iso,
      "next_update" => next_update_iso,
      "ca_bundle_pem" => ca.certificate_pem,
      "crl_pem" => crl.crl_pem
    }

    bundle_sha256 = calculate_hash(fields_for_hash)

    Map.put(fields_for_hash, "bundle_sha256", bundle_sha256)
  end

  @doc """
  Calculates the deterministic bundle SHA-256 transcript hash.
  """
  @spec calculate_hash(map()) :: String.t()
  def calculate_hash(fields) when is_map(fields) do
    # Deterministic transcript: sort keys and encode with Canonical JSON
    transcript =
      [
        fields["schema_version"],
        fields["authority"],
        fields["generation"],
        fields["ca_fingerprint"],
        fields["crl_number"],
        fields["crl_der_sha256"],
        fields["this_update"],
        fields["next_update"],
        fields["ca_bundle_pem"],
        fields["crl_pem"]
      ]
      |> Enum.map(&to_string/1)
      |> Enum.join("|")

    :crypto.hash(:sha256, transcript)
    |> Base.encode16(case: :lower)
  end

  @doc """
  Fetches the current active trust bundle from the database.
  Available even when the vault is sealed since it contains only public data.
  """
  @spec current_bundle(String.t()) ::
          {:ok, map()} | {:error, :authority_not_initialized | :bundle_unavailable}
  def current_bundle(slug \\ "client-auth") do
    query =
      from(a in ClientAuthAuthority,
        where: a.slug == ^slug and a.status == "active",
        preload: [:ca_certificate, :current_crl]
      )

    case Repo.one(query) do
      nil ->
        {:error, :authority_not_initialized}

      %ClientAuthAuthority{
        ca_certificate: %Certificate{} = ca,
        current_crl: %ClientAuthCrl{} = crl
      } = authority ->
        {:ok, build(authority, ca, crl)}

      _other ->
        {:error, :bundle_unavailable}
    end
  end
end
