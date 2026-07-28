defmodule SecretHub.Core.PKI.CertificateIdentityTest do
  use ExUnit.Case, async: true

  alias SecretHub.Core.PKI.CertificateIdentity
  alias X509.Certificate.Extension

  test "canonical fingerprints hash DER as lowercase unseparated SHA-256 and decode to 32 bytes" do
    pem = app_certificate_pem(Ecto.UUID.generate())
    [{:Certificate, der, _}] = :public_key.pem_decode(pem)
    expected = :crypto.hash(:sha256, der) |> Base.encode16(case: :lower)

    assert {:ok, ^expected} = CertificateIdentity.canonical_fingerprint_from_pem(pem)
    assert ^expected = CertificateIdentity.canonical_fingerprint_from_der(der)
    assert {:ok, <<_::binary-size(32)>>} = CertificateIdentity.decode_fingerprint(expected)
    assert <<_::binary-size(32)>> = CertificateIdentity.decode_fingerprint!(expected)
  end

  test "rejects noncanonical fingerprint encodings and malformed PEM" do
    assert {:error, :invalid_fingerprint} =
             CertificateIdentity.decode_fingerprint("aa:" <> String.duplicate("aa", 31))

    assert {:error, :invalid_fingerprint} =
             CertificateIdentity.decode_fingerprint(String.duplicate("A", 64))

    assert {:error, :invalid_certificate} =
             CertificateIdentity.canonical_fingerprint_from_pem("not a certificate")

    assert_raise ArgumentError, "invalid fingerprint", fn ->
      CertificateIdentity.decode_fingerprint!("invalid")
    end
  end

  test "validates only canonical application certificate identity" do
    app_id = Ecto.UUID.generate()
    pem = app_certificate_pem(app_id)
    [{:Certificate, der, :not_encrypted}] = :public_key.pem_decode(pem)

    assert {:ok,
            %{
              app_id: ^app_id,
              canonical_fingerprint: fingerprint,
              public_key: public_key
            }} =
             CertificateIdentity.validate_app_certificate(pem, app_id)

    assert String.match?(fingerprint, ~r/\A[0-9a-f]{64}\z/)
    assert public_key == X509.Certificate.from_der!(der) |> X509.Certificate.public_key()

    assert {:ok, %{app_id: ^app_id, canonical_fingerprint: ^fingerprint}} =
             CertificateIdentity.validate_app_certificate(der, app_id)
  end

  test "rejects a non-UUID expected application identity and malformed DER" do
    assert {:error, :invalid_application_id} =
             CertificateIdentity.validate_app_certificate(
               app_certificate_pem(Ecto.UUID.generate()),
               "legacy-app-name"
             )

    assert {:error, :invalid_certificate} =
             CertificateIdentity.validate_app_certificate(
               <<0x30, 0x01, 0x00>>,
               Ecto.UUID.generate()
             )
  end

  test "fails closed for wrong CN, organization, URI SAN, and clientAuth" do
    app_id = Ecto.UUID.generate()

    assert {:error, :invalid_common_name} =
             CertificateIdentity.validate_app_certificate(
               app_certificate_pem(app_id, cn: Ecto.UUID.generate()),
               app_id
             )

    assert {:error, :invalid_organization} =
             CertificateIdentity.validate_app_certificate(
               app_certificate_pem(app_id, organization: "Other"),
               app_id
             )

    assert {:error, :missing_app_uri_san} =
             CertificateIdentity.validate_app_certificate(
               app_certificate_pem(app_id, uri: "urn:secrethub:app:#{Ecto.UUID.generate()}"),
               app_id
             )

    assert {:error, :missing_app_uri_san} =
             CertificateIdentity.validate_app_certificate(
               app_certificate_pem(app_id, uri: nil),
               app_id
             )

    assert {:error, :missing_app_uri_san} =
             CertificateIdentity.validate_app_certificate(
               app_certificate_pem(app_id,
                 uri: [
                   "urn:secrethub:app:#{app_id}",
                   "urn:secrethub:app:#{Ecto.UUID.generate()}"
                 ]
               ),
               app_id
             )

    assert {:error, :missing_client_auth} =
             CertificateIdentity.validate_app_certificate(
               app_certificate_pem(app_id, client_auth?: false),
               app_id
             )
  end

  defp app_certificate_pem(app_id, overrides \\ []) do
    private_key = X509.PrivateKey.new_rsa(2048)
    cn = Keyword.get(overrides, :cn, app_id)
    organization = Keyword.get(overrides, :organization, "SecretHub Applications")
    uri = Keyword.get(overrides, :uri, "urn:secrethub:app:#{app_id}")

    extensions =
      if uri do
        uris = if is_list(uri), do: uri, else: [uri]

        [
          subject_alt_name:
            Extension.subject_alt_name(
              Enum.map(uris, &{:uniformResourceIdentifier, to_charlist(&1)})
            )
        ]
      else
        [subject_alt_name: false]
      end

    extensions =
      if Keyword.get(overrides, :client_auth?, true),
        do: Keyword.put(extensions, :ext_key_usage, Extension.ext_key_usage([:clientAuth])),
        else: Keyword.put(extensions, :ext_key_usage, false)

    private_key
    |> X509.Certificate.self_signed("/O=#{organization}/CN=#{cn}", extensions: extensions)
    |> X509.Certificate.to_pem()
  end
end
