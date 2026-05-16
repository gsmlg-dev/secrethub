defmodule SecretHub.Core.PKI.CSR do
  @moduledoc """
  CSR parsing and validation helpers for Agent enrollment.
  """

  @supported_algorithms ~w(rsa ecdsa)

  def parse(csr_pem) when is_binary(csr_pem) do
    with {:ok, csr} <- X509.CSR.from_pem(csr_pem),
         true <- X509.CSR.valid?(csr) do
      {:ok, csr}
    else
      false -> {:error, "CSR signature is invalid"}
      {:error, :not_found} -> {:error, "CSR PEM block not found"}
      {:error, :malformed} -> {:error, "CSR is malformed"}
      {:error, reason} -> {:error, "CSR parse failed: #{inspect(reason)}"}
    end
  rescue
    e -> {:error, "CSR parse failed: #{Exception.message(e)}"}
  end

  def parse(_), do: {:error, "CSR must be PEM text"}

  def supported_host_key_algorithm?(algorithm), do: algorithm in @supported_algorithms

  def public_key_fingerprint(csr) do
    csr
    |> X509.CSR.public_key()
    |> ssh_fingerprint()
  end

  def ssh_fingerprint(public_key) do
    public_key
    |> ssh_public_key_blob()
    |> :crypto.hash(:sha256)
    |> Base.encode64(padding: false)
    |> then(&"SHA256:#{&1}")
  end

  defp ssh_public_key_blob({:RSAPublicKey, modulus, exponent}) do
    string("ssh-rsa") <> mpint(exponent) <> mpint(modulus)
  end

  defp ssh_public_key_blob({{:ECPoint, point}, {:namedCurve, {1, 2, 840, 10045, 3, 1, 7}}}) do
    curve = "nistp256"
    string("ecdsa-sha2-#{curve}") <> string(curve) <> string(point)
  end

  defp ssh_public_key_blob({point, {:namedCurve, {1, 2, 840, 10045, 3, 1, 7}}})
       when is_binary(point) do
    curve = "nistp256"
    string("ecdsa-sha2-#{curve}") <> string(curve) <> string(point)
  end

  defp ssh_public_key_blob(public_key) do
    :public_key.der_encode(:SubjectPublicKeyInfo, X509.PublicKey.wrap(public_key))
  end

  defp string(value) when is_binary(value), do: <<byte_size(value)::32, value::binary>>

  defp mpint(integer) when is_integer(integer) do
    bytes = :binary.encode_unsigned(integer)
    bytes = if match?(<<1::1, _::bitstring>>, bytes), do: <<0, bytes::binary>>, else: bytes
    <<byte_size(bytes)::32, bytes::binary>>
  end
end
