defmodule SecretHub.Core.PKI.ACME.CertificateValidation do
  @moduledoc "Validates issued server material before any managed-secret publication."

  alias SecretHub.Core.PKI.ACME.Renewal
  alias SecretHub.Core.PKI.TrustStores

  @server_auth {1, 3, 6, 1, 5, 5, 7, 3, 1}
  @any_usage {2, 5, 29, 37, 0}

  def validate(fullchain_pem, private_key_pem, identifiers, environment, opts \\ []) do
    now = Keyword.get_lazy(opts, :now, &DateTime.utc_now/0)

    with {:ok, entries} <- certificate_entries(fullchain_pem),
         [{:Certificate, leaf_der, :not_encrypted} | intermediates] = entries,
         leaf = X509.Certificate.from_der!(leaf_der),
         {:ok, key} <- private_key(private_key_pem),
         :ok <- key_match(leaf, key),
         {:ok, names} <- exact_names(leaf, identifiers),
         :ok <- server_usage(leaf),
         {:ok, not_before, not_after} <- validity(leaf, now),
         {:ok, roots} <- issuance_roots(environment, opts),
         :ok <- verify_chain(entries, roots) do
      certificate_pem = :public_key.pem_encode([hd(entries)])
      chain_pem = :public_key.pem_encode(intermediates)

      ari_id =
        case Renewal.certificate_id(leaf) do
          {:ok, id} -> id
          {:error, _} -> nil
        end

      {:ok,
       %{
         fingerprint_sha256: Base.encode16(:crypto.hash(:sha256, leaf_der), case: :lower),
         certificate_der: leaf_der,
         certificate_pem: certificate_pem,
         chain_pem: chain_pem,
         fullchain_pem: certificate_pem <> chain_pem,
         identifiers: names,
         not_before: not_before,
         not_after: not_after,
         environment: to_string(environment),
         ari_certificate_id: ari_id,
         serial_number: leaf |> X509.Certificate.serial() |> Integer.to_string(),
         key_algorithm:
           if(match?({:RSAPrivateKey, _, _, _, _, _, _, _, _, _, _}, key), do: "RSA", else: "EC")
       }}
    end
  rescue
    _ -> {:error, :invalid_certificate_chain}
  catch
    _, _ -> {:error, :invalid_certificate_chain}
  end

  defp certificate_entries(pem) when is_binary(pem) and byte_size(pem) <= 2_097_152 do
    entries = :public_key.pem_decode(pem)

    if entries != [] and length(entries) <= 10 and
         Enum.all?(entries, &match?({:Certificate, _, :not_encrypted}, &1)) do
      Enum.each(entries, fn {:Certificate, der, _} -> X509.Certificate.from_der!(der) end)
      {:ok, entries}
    else
      {:error, :invalid_certificate_chain}
    end
  end

  defp certificate_entries(_), do: {:error, :invalid_certificate_chain}

  defp private_key(pem) do
    case X509.PrivateKey.from_pem(pem) do
      {:ok, key} -> {:ok, key}
      _ -> {:error, :invalid_private_key}
    end
  end

  defp key_match(certificate, private_key) do
    if X509.Certificate.public_key(certificate) == X509.PublicKey.derive(private_key),
      do: :ok,
      else: {:error, :private_key_mismatch}
  end

  defp exact_names(certificate, expected) do
    with {:Extension, _, _, alternatives} when is_list(alternatives) <-
           X509.Certificate.extension(certificate, :subject_alt_name),
         true <- Enum.all?(alternatives, &match?({:dNSName, _}, &1)) do
      actual = alternatives |> Enum.map(&elem(&1, 1)) |> normalized_names()

      if actual == normalized_names(expected) and actual != [],
        do: {:ok, actual},
        else: {:error, :identifier_mismatch}
    else
      _ -> {:error, :identifier_mismatch}
    end
  end

  defp normalized_names(names) do
    names
    |> Enum.map(&(to_string(&1) |> String.downcase() |> String.trim_trailing(".")))
    |> Enum.uniq()
    |> Enum.sort()
  end

  defp server_usage(certificate) do
    ca = X509.Certificate.extension(certificate, :basic_constraints)
    eku = X509.Certificate.extension(certificate, :ext_key_usage)
    usage = X509.Certificate.extension(certificate, :key_usage)

    cond do
      match?({:Extension, _, _, {:BasicConstraints, true, _}}, ca) ->
        {:error, :leaf_is_ca}

      match?({:Extension, _, _, _}, eku) and not allowed_eku?(eku) ->
        {:error, :server_auth_required}

      match?({:Extension, _, _, _}, usage) and not allowed_key_usage?(usage) ->
        {:error, :server_auth_required}

      true ->
        :ok
    end
  end

  defp allowed_eku?({:Extension, _, _, purposes}),
    do: @server_auth in purposes or @any_usage in purposes

  defp allowed_key_usage?({:Extension, _, _, usage}),
    do: :digitalSignature in usage or :keyEncipherment in usage

  defp validity(certificate, now) do
    {:Validity, not_before, not_after} = X509.Certificate.validity(certificate)
    not_before = TrustStores.asn1_datetime(not_before)
    not_after = TrustStores.asn1_datetime(not_after)

    if DateTime.compare(not_before, now) != :gt and DateTime.compare(not_after, now) == :gt and
         DateTime.compare(not_before, not_after) == :lt,
       do: {:ok, not_before, not_after},
       else: {:error, :invalid_certificate_validity}
  end

  defp issuance_roots(environment, opts) do
    case Keyword.get(opts, :test_issuance_cacerts) do
      nil ->
        case to_string(environment) do
          "production" -> TrustStores.cacerts("mozilla_webpki")
          "staging" -> TrustStores.cacerts("letsencrypt_staging_issuance")
          _ -> {:error, :unsupported_environment}
        end

      roots when is_list(roots) ->
        if Keyword.get(opts, :test_mode, false) and
             to_string(environment) in ["staging", "pebble"],
           do: {:ok, roots},
           else: {:error, :test_trust_forbidden}
    end
  end

  defp verify_chain(entries, roots) do
    supplied = Enum.map(entries, &elem(&1, 1))

    valid =
      Enum.any?(roots, fn root ->
        # pkix_path_validation takes certificates from the trust anchor towards the leaf.
        path = supplied |> Enum.reject(&(&1 == root)) |> Enum.reverse()
        match?({:ok, _}, :public_key.pkix_path_validation(root, path, []))
      end)

    if valid, do: :ok, else: {:error, :untrusted_certificate_chain}
  end
end
