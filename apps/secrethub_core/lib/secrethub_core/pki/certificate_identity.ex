defmodule SecretHub.Core.PKI.CertificateIdentity do
  @moduledoc """
  Canonical application-certificate identity and fingerprint handling.

  Authorization fingerprints are lowercase, unseparated SHA-256 hashes of the
  exact DER certificate bytes. The legacy schema fingerprint uses a different
  display encoding and must not be used for new authorization decisions.
  """

  @fingerprint ~r/\A[0-9a-f]{64}\z/
  @app_organization "SecretHub Applications"
  @client_auth_oid {1, 3, 6, 1, 5, 5, 7, 3, 2}

  @spec canonical_fingerprint_from_pem(binary()) ::
          {:ok, String.t()} | {:error, :invalid_certificate}
  def canonical_fingerprint_from_pem(pem) when is_binary(pem) do
    with {:ok, der} <- der_from_pem(pem),
         {:ok, _certificate} <- decode_certificate(der) do
      {:ok, canonical_fingerprint_from_der(der)}
    end
  end

  def canonical_fingerprint_from_pem(_), do: {:error, :invalid_certificate}

  @spec canonical_fingerprint_from_der(binary()) :: String.t()
  def canonical_fingerprint_from_der(der) when is_binary(der) do
    :crypto.hash(:sha256, der) |> Base.encode16(case: :lower)
  end

  @spec decode_fingerprint(term()) ::
          {:ok, <<_::256>>} | {:error, :invalid_fingerprint}
  def decode_fingerprint(fingerprint) when is_binary(fingerprint) do
    if Regex.match?(@fingerprint, fingerprint) do
      {:ok, Base.decode16!(fingerprint, case: :lower)}
    else
      {:error, :invalid_fingerprint}
    end
  end

  def decode_fingerprint(_), do: {:error, :invalid_fingerprint}

  @spec decode_fingerprint!(term()) :: <<_::256>>
  def decode_fingerprint!(fingerprint) do
    case decode_fingerprint(fingerprint) do
      {:ok, bytes} -> bytes
      {:error, :invalid_fingerprint} -> raise ArgumentError, "invalid fingerprint"
    end
  end

  @spec validate_app_certificate(binary(), binary()) ::
          {:ok,
           %{
             app_id: Ecto.UUID.t(),
             canonical_fingerprint: String.t(),
             public_key: term()
           }}
          | {:error,
             :invalid_application_id
             | :invalid_certificate
             | :invalid_common_name
             | :invalid_organization
             | :missing_app_uri_san
             | :missing_client_auth}
  def validate_app_certificate(pem_or_der, expected_app_id) when is_binary(expected_app_id) do
    with :ok <- validate_application_id(expected_app_id),
         {:ok, der} <- der_from_input(pem_or_der),
         {:ok, certificate} <- decode_certificate(der),
         :ok <- validate_subject(certificate, expected_app_id),
         :ok <- validate_uri_san(certificate, expected_app_id),
         :ok <- validate_client_auth(certificate),
         {:ok, public_key} <- certificate_public_key(certificate) do
      {:ok,
       %{
         app_id: expected_app_id,
         canonical_fingerprint: canonical_fingerprint_from_der(der),
         public_key: public_key
       }}
    end
  rescue
    _error -> {:error, :invalid_certificate}
  end

  def validate_app_certificate(_, _), do: {:error, :invalid_certificate}

  defp validate_application_id(app_id) do
    case Ecto.UUID.cast(app_id) do
      {:ok, ^app_id} -> :ok
      _other -> {:error, :invalid_application_id}
    end
  end

  defp der_from_input(<<0x30, _::binary>> = der), do: {:ok, der}
  defp der_from_input(pem) when is_binary(pem), do: der_from_pem(pem)
  defp der_from_input(_), do: {:error, :invalid_certificate}

  defp der_from_pem(pem) do
    case :public_key.pem_decode(pem) do
      entries when is_list(entries) ->
        case Enum.find(entries, &match?({:Certificate, _, :not_encrypted}, &1)) do
          {:Certificate, der, :not_encrypted} -> {:ok, der}
          nil -> {:error, :invalid_certificate}
        end

      _ ->
        {:error, :invalid_certificate}
    end
  rescue
    _ -> {:error, :invalid_certificate}
  end

  defp decode_certificate(der) do
    case X509.Certificate.from_der(der) do
      {:ok, certificate} -> {:ok, certificate}
      {:error, _reason} -> {:error, :invalid_certificate}
    end
  rescue
    _ -> {:error, :invalid_certificate}
  end

  defp certificate_public_key(certificate) do
    {:ok, X509.Certificate.public_key(certificate)}
  rescue
    _ -> {:error, :invalid_certificate}
  end

  defp validate_subject(certificate, app_id) do
    case X509.Certificate.subject(certificate, "CN") do
      [^app_id] ->
        if X509.Certificate.subject(certificate, "O") == [@app_organization],
          do: :ok,
          else: {:error, :invalid_organization}

      _ ->
        {:error, :invalid_common_name}
    end
  end

  defp validate_uri_san(certificate, app_id) do
    expected = ~c"urn:secrethub:app:" ++ to_charlist(app_id)

    case extension_values(certificate, :subject_alt_name, :SubjectAltName) do
      {:ok, [{:uniformResourceIdentifier, ^expected}]} -> :ok
      _other -> {:error, :missing_app_uri_san}
    end
  end

  defp validate_client_auth(certificate) do
    validate_extension_value(
      certificate,
      :ext_key_usage,
      :ExtKeyUsageSyntax,
      @client_auth_oid,
      :missing_client_auth
    )
  end

  defp validate_extension_value(certificate, extension, der_type, expected, error) do
    case extension_values(certificate, extension, der_type) do
      {:ok, values} -> if expected in values, do: :ok, else: {:error, error}
      :error -> {:error, error}
    end
  end

  defp extension_values(certificate, extension, der_type) do
    certificate
    |> X509.Certificate.extension(extension)
    |> normalize_extension_values(der_type)
  rescue
    _error -> :error
  end

  defp normalize_extension_values({:Extension, _, _, values}, _der_type)
       when is_list(values),
       do: {:ok, values}

  defp normalize_extension_values({:Extension, _, _, der}, der_type)
       when is_binary(der),
       do: decode_extension_values(der, der_type)

  defp normalize_extension_values(_extension, _der_type), do: :error

  defp decode_extension_values(der, der_type) do
    case :public_key.der_decode(der_type, der) do
      values when is_list(values) -> {:ok, values}
      _other -> :error
    end
  rescue
    _error -> :error
  end
end
