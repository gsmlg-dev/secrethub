defmodule SecretHub.Agent.TLSIdentityTest do
  use ExUnit.Case, async: true

  alias SecretHub.Agent.TLSIdentity

  test "generates a valid CSR whose public key matches the TLS private key" do
    required_fields = required_csr_fields()

    assert {:ok, %TLSIdentity{} = identity} = TLSIdentity.generate(required_fields)
    assert String.contains?(identity.private_key_pem, "BEGIN PRIVATE KEY")
    assert String.contains?(identity.csr_pem, "BEGIN CERTIFICATE REQUEST")

    assert {:ok, csr} = X509.CSR.from_pem(identity.csr_pem)
    assert X509.CSR.valid?(csr)
    assert X509.CSR.public_key(csr) == :ssh_file.extract_public_key(identity.private_key)
    assert X509.RDNSequence.get_attr(X509.CSR.subject(csr), "O") == ["SecretHub Agents"]
    assert X509.RDNSequence.get_attr(X509.CSR.subject(csr), "CN") == ["agent-123"]

    extensions = X509.CSR.extension_request(csr)
    san_extension = X509.Certificate.Extension.find(extensions, :subject_alt_name)

    assert {:uniformResourceIdentifier, ~c"spiffe://secrethub/agent/agent-123"} in elem(
             san_extension,
             3
           )

    assert {:dNSName, ~c"agent-123.internal.example"} in elem(san_extension, 3)

    assert elem(X509.Certificate.Extension.find(extensions, :key_usage), 3) == [
             :digitalSignature
           ]

    assert X509.Certificate.Extension.find(extensions, :ext_key_usage)
  end

  defp required_csr_fields do
    %{
      "subject" => %{
        "O" => "SecretHub Agents",
        "CN" => "agent-123"
      },
      "san" => %{
        "uri" => ["spiffe://secrethub/agent/agent-123"],
        "dns" => ["agent-123.internal.example"]
      }
    }
  end
end
