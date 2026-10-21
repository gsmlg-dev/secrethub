defmodule SecretHub.Core.PKI.TrustStores do
  @moduledoc """
  Release-packaged public TLS roots. These roots never enter internal identity PKI.

  `mozilla_webpki` is a Mozilla-derived snapshot, not Firefox policy emulation.
  Updates replace the CAStore dependency snapshot through a reviewed release.
  """

  @mozilla "mozilla_webpki"
  @staging "letsencrypt_staging_issuance"

  def list do
    with {:ok, catalogue} <- catalogue(@mozilla), do: {:ok, [Map.delete(catalogue, :roots)]}
  end

  def pem(id \\ @mozilla) do
    with {:ok, profile} <- profile(id), do: {:ok, profile.pem}
  end

  def cacerts(id \\ @mozilla) do
    with {:ok, profile} <- profile(id), do: {:ok, profile.cacerts}
  end

  def catalogue(id \\ @mozilla) do
    with {:ok, profile} <- profile(id), do: {:ok, Map.drop(profile, [:pem, :cacerts])}
  end

  def profile(id) when id in [@mozilla, @staging] do
    cache_key = {__MODULE__, id}

    case :persistent_term.get(cache_key, :missing) do
      :missing ->
        with {:ok, profile} <- load_profile(id) do
          :persistent_term.put(cache_key, profile)
          {:ok, profile}
        end

      profile ->
        {:ok, profile}
    end
  end

  def profile(_id), do: {:error, :unknown_trust_store}

  @doc "Parses only nonempty, entirely valid certificate bundles; failures never weaken trust."
  def parse_bundle(pem) when is_binary(pem) do
    entries = :public_key.pem_decode(pem)

    if entries == [] or Enum.any?(entries, &(not match?({:Certificate, _, :not_encrypted}, &1))) do
      {:error, :invalid_bundle}
    else
      roots = Enum.map(entries, fn {:Certificate, der, :not_encrypted} -> root_metadata(der) end)
      {:ok, %{roots: roots, cacerts: Enum.map(entries, &elem(&1, 1)), root_count: length(roots)}}
    end
  rescue
    _ -> {:error, :invalid_bundle}
  catch
    _, _ -> {:error, :invalid_bundle}
  end

  defp load_profile(@mozilla) do
    with {:ok, pem} <- File.read(CAStore.file_path()),
         {:ok, parsed} <- parse_bundle(pem) do
      {:ok,
       Map.merge(parsed, %{
         id: @mozilla,
         name: "Mozilla-derived TLS root CA bundle",
         usage: "public_tls_server_authentication",
         pem: pem,
         sha256: digest(pem),
         package: "castore",
         package_version: package_version(),
         source: "Mozilla/NSS via CAStore",
         source_url: "https://github.com/elixir-mint/castore",
         source_date: source_date(pem),
         license: "MPL-2.0 (Mozilla certificate data); Apache-2.0 (CAStore packaging)",
         notice_url: "https://github.com/elixir-mint/castore/blob/main/README.md",
         release: app_version()
       })}
    else
      {:error, _} -> {:error, :public_trust_unavailable}
    end
  rescue
    _ -> {:error, :public_trust_unavailable}
  end

  defp load_profile(@staging) do
    directory = Application.app_dir(:secrethub_core, "priv/pki")

    with {:ok, manifest_json} <-
           File.read(Path.join(directory, "letsencrypt-staging-manifest.json")),
         {:ok, manifest} <- JSON.decode(manifest_json),
         {:ok, pems} <- load_staging_roots(directory, manifest["roots"]),
         pem = Enum.join(pems, "\n"),
         {:ok, parsed} <- parse_bundle(pem) do
      {:ok,
       Map.merge(parsed, %{
         id: @staging,
         name: "Let's Encrypt staging issuance roots",
         usage: "staging_issued_chain_validation_only",
         pem: pem,
         sha256: digest(pem),
         source: "Official Let's Encrypt staging roots",
         source_url: "https://letsencrypt.org/docs/staging-environment/",
         roots_manifest: manifest["roots"],
         release: app_version()
       })}
    else
      _ -> {:error, :staging_trust_unavailable}
    end
  rescue
    _ -> {:error, :staging_trust_unavailable}
  end

  defp load_staging_roots(directory, roots) when is_list(roots) and roots != [] do
    Enum.reduce_while(roots, {:ok, []}, fn root, {:ok, pems} ->
      with filename when is_binary(filename) <- root["file"],
           true <- Path.basename(filename) == filename,
           {:ok, pem} <- File.read(Path.join(directory, filename)),
           true <- digest(pem) == root["pem_sha256"],
           {:ok, %{roots: [%{fingerprint_sha256: fingerprint}]}} <- parse_bundle(pem),
           true <- fingerprint == root["der_sha256"] do
        {:cont, {:ok, pems ++ [pem]}}
      else
        _ -> {:halt, {:error, :invalid_staging_root}}
      end
    end)
  end

  defp load_staging_roots(_, _), do: {:error, :invalid_staging_manifest}

  defp root_metadata(der) do
    cert = X509.Certificate.from_der!(der)
    {:Validity, not_before, not_after} = X509.Certificate.validity(cert)
    public_key = X509.Certificate.public_key(cert)

    %{
      fingerprint_sha256: digest(der),
      subject: cert |> X509.Certificate.subject() |> name_text(),
      issuer: cert |> X509.Certificate.issuer() |> name_text(),
      not_before: asn1_datetime(not_before),
      not_after: asn1_datetime(not_after),
      public_key: key_metadata(public_key)
    }
  end

  defp name_text({:rdnSequence, sequence}) do
    Enum.map_join(sequence, "", fn attributes ->
      Enum.map_join(attributes, "+", fn attribute ->
        attribute_text(attribute)
      end)
    end)
  end

  defp attribute_text(attribute) do
    X509.RDNSequence.to_string({:rdnSequence, [[attribute]]})
  rescue
    _ ->
      # RFC 4514 permits unknown attribute values as their complete DER in hex.
      {:AttributeTypeAndValue, oid, value} = attribute

      encoded =
        case value do
          {:asn1_OPENTYPE, der} -> der
          der when is_binary(der) -> der
        end

      "/" <> (oid |> Tuple.to_list() |> Enum.join(".")) <> "=#" <> Base.encode16(encoded)
  end

  defp key_metadata({:RSAPublicKey, modulus, _}),
    do: %{algorithm: "RSA", bits: bit_size(:binary.encode_unsigned(modulus))}

  defp key_metadata({{:ECPoint, _}, {:namedCurve, curve}}),
    do: %{algorithm: "EC", curve: curve |> Tuple.to_list() |> Enum.join(".")}

  defp key_metadata(_), do: %{algorithm: "other"}

  # X509.DateTime assumes all UTCTime years are 20xx; public roots include 19xx.
  def asn1_datetime({:utcTime, [a, b | rest]}) do
    century = if (a - ?0) * 10 + b - ?0 >= 50, do: "19", else: "20"
    X509.DateTime.to_datetime(century <> to_string([a, b | rest]))
  end

  def asn1_datetime({:generalTime, time}), do: X509.DateTime.to_datetime({:generalTime, time})

  defp source_date(pem) do
    case Regex.run(
           ~r/(?:Certificate data from Mozilla as of:|Certificate data from Mozilla as of|as of:)\s*([^\r\n]+)/,
           pem
         ) do
      [_, date] -> String.trim(date)
      _ -> nil
    end
  end

  defp package_version do
    case :application.get_key(:castore, :vsn) do
      {:ok, version} -> to_string(version)
      :undefined -> "unknown"
    end
  end

  defp app_version do
    case :application.get_key(:secrethub_core, :vsn) do
      {:ok, version} -> to_string(version)
      :undefined -> "unknown"
    end
  end

  defp digest(bytes), do: Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)
end
