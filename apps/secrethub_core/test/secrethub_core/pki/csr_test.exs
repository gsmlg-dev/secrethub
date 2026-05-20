defmodule SecretHub.Core.PKI.CSRTest do
  use ExUnit.Case, async: true

  alias SecretHub.Core.PKI.CSR

  test "computes an OpenSSH SHA256 fingerprint from a CSR public key" do
    private_key = :public_key.generate_key({:rsa, 2048, 65_537})
    {:RSAPrivateKey, :"two-prime", modulus, exponent, _, _, _, _, _, _, _} = private_key

    csr = X509.CSR.new(private_key, "/O=SecretHub Agents/CN=agent-test")

    expected =
      {:RSAPublicKey, modulus, exponent}
      |> rsa_ssh_public_key_blob()
      |> then(&:crypto.hash(:sha256, &1))
      |> Base.encode64(padding: false)
      |> then(&"SHA256:#{&1}")

    assert CSR.public_key_fingerprint(csr) == expected
  end

  defp rsa_ssh_public_key_blob({:RSAPublicKey, modulus, exponent}) do
    string("ssh-rsa") <> mpint(exponent) <> mpint(modulus)
  end

  defp string(value), do: <<byte_size(value)::32, value::binary>>

  defp mpint(integer) do
    bytes = :binary.encode_unsigned(integer)
    bytes = if match?(<<1::1, _::bitstring>>, bytes), do: <<0, bytes::binary>>, else: bytes
    <<byte_size(bytes)::32, bytes::binary>>
  end
end
