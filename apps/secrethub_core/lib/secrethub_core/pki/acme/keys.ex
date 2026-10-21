defmodule SecretHub.Core.PKI.ACME.Keys do
  @moduledoc "Caller-owned ACME account/leaf keys and PKCS#10 requests."

  alias X509.Certificate.Extension

  def generate(policy \\ "ec_p256") do
    with {:ok, key} <- private_key(policy) do
      pem = X509.PrivateKey.to_pem(key)
      jwk = JOSE.JWK.from_pem(pem)
      {_module, public} = JOSE.JWK.to_public_map(jwk)

      {:ok,
       %{
         private_key_pem: pem,
         public_jwk: public,
         thumbprint: JOSE.JWK.thumbprint(jwk)
       }}
    end
  rescue
    _ -> {:error, :key_generation_failed}
  end

  def csr(private_key_pem, identifiers) when is_list(identifiers) and identifiers != [] do
    case X509.PrivateKey.from_pem(private_key_pem) do
      {:ok, key} ->
        csr =
          X509.CSR.new(key, X509.RDNSequence.new([]),
            extension_request: [Extension.subject_alt_name(identifiers)]
          )

        der = X509.CSR.to_der(csr)

        {:ok,
         %{
           der: der,
           base64url: Base.url_encode64(der, padding: false),
           sha256: Base.encode16(:crypto.hash(:sha256, der), case: :lower)
         }}

      _ ->
        {:error, :invalid_private_key}
    end
  rescue
    _ -> {:error, :invalid_csr}
  end

  def csr(_, _), do: {:error, :invalid_identifiers}

  defp private_key(policy) when policy in ["ec_p256", :ec_p256],
    do: {:ok, X509.PrivateKey.new_ec(:secp256r1)}

  defp private_key(policy) when policy in ["rsa_2048", :rsa_2048],
    do: {:ok, X509.PrivateKey.new_rsa(2048)}

  defp private_key(_), do: {:error, :unsupported_key_policy}
end
