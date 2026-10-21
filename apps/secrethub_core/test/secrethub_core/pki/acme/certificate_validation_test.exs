defmodule SecretHub.Core.PKI.ACME.CertificateValidationTest do
  use ExUnit.Case, async: true

  alias SecretHub.Core.PKI.ACME.{CertificateValidation, Keys, Renewal}
  alias X509.Certificate.Extension

  setup do
    root_key = X509.PrivateKey.new_ec(:secp256r1)

    root =
      X509.Certificate.self_signed(root_key, "/CN=ACME isolated test root", template: :root_ca)

    {:ok, leaf} = Keys.generate()
    leaf_key = X509.PrivateKey.from_pem!(leaf.private_key_pem)

    cert =
      X509.Certificate.new(X509.PublicKey.derive(leaf_key), "/CN=example.com", root, root_key,
        template: :server,
        extensions: [
          subject_alt_name: Extension.subject_alt_name(["example.com", "*.example.com"]),
          ext_key_usage: Extension.ext_key_usage([:serverAuth])
        ]
      )

    %{
      root: root,
      root_key: root_key,
      leaf: leaf,
      leaf_key: leaf_key,
      cert: cert,
      opts: [test_mode: true, test_issuance_cacerts: [X509.Certificate.to_der(root)]]
    }
  end

  test "validates coherent key, exact names, TLS purpose and injected test chain", ctx do
    fullchain = X509.Certificate.to_pem(ctx.cert)

    assert {:ok, material} =
             CertificateValidation.validate(
               fullchain,
               ctx.leaf.private_key_pem,
               ["*.example.com", "example.com"],
               "staging",
               ctx.opts
             )

    assert material.fingerprint_sha256 ==
             Base.encode16(:crypto.hash(:sha256, X509.Certificate.to_der(ctx.cert)), case: :lower)

    assert material.certificate_pem == fullchain
    assert material.chain_pem == ""
    assert material.identifiers == ["*.example.com", "example.com"]
    assert {:ok, ari_id} = Renewal.certificate_id(ctx.cert)
    assert material.ari_certificate_id == ari_id

    {:Extension, _, _, {:AuthorityKeyIdentifier, aki, _, _}} =
      X509.Certificate.extension(ctx.cert, :authority_key_identifier)

    assert ari_id ==
             Base.url_encode64(aki, padding: false) <>
               "." <>
               Base.url_encode64(:binary.encode_unsigned(X509.Certificate.serial(ctx.cert)),
                 padding: false
               )
  end

  test "rejects mismatching leaf key, missing SAN and untrusted issuer", ctx do
    fullchain = X509.Certificate.to_pem(ctx.cert)
    {:ok, wrong} = Keys.generate()

    assert {:error, :private_key_mismatch} =
             CertificateValidation.validate(
               fullchain,
               wrong.private_key_pem,
               ["*.example.com", "example.com"],
               "staging",
               ctx.opts
             )

    assert {:error, :identifier_mismatch} =
             CertificateValidation.validate(
               fullchain,
               ctx.leaf.private_key_pem,
               ["example.com"],
               "staging",
               ctx.opts
             )

    assert {:error, :untrusted_certificate_chain} =
             CertificateValidation.validate(
               fullchain,
               ctx.leaf.private_key_pem,
               ["*.example.com", "example.com"],
               "staging",
               Keyword.put(ctx.opts, :test_issuance_cacerts, [])
             )
  end

  test "staging and production validation profiles cannot be swapped", ctx do
    assert {:error, :test_trust_forbidden} =
             CertificateValidation.validate(
               X509.Certificate.to_pem(ctx.cert),
               ctx.leaf.private_key_pem,
               ["*.example.com", "example.com"],
               "production",
               ctx.opts
             )
  end

  test "client-only certificates and expired certificates are never published", ctx do
    client_cert =
      X509.Certificate.new(
        X509.PublicKey.derive(ctx.leaf_key),
        "/CN=example.com",
        ctx.root,
        ctx.root_key,
        template: :server,
        extensions: [
          subject_alt_name: Extension.subject_alt_name(["example.com"]),
          ext_key_usage: Extension.ext_key_usage([:clientAuth])
        ]
      )

    assert {:error, :server_auth_required} =
             CertificateValidation.validate(
               X509.Certificate.to_pem(client_cert),
               ctx.leaf.private_key_pem,
               ["example.com"],
               "staging",
               ctx.opts
             )

    future = DateTime.add(DateTime.utc_now(), 500 * 86_400)

    assert {:error, :invalid_certificate_validity} =
             CertificateValidation.validate(
               X509.Certificate.to_pem(ctx.cert),
               ctx.leaf.private_key_pem,
               ["*.example.com", "example.com"],
               "staging",
               Keyword.put(ctx.opts, :now, future)
             )
  end

  test "malformed output cannot become a serving version", ctx do
    assert {:error, :invalid_certificate_chain} =
             CertificateValidation.validate(
               "bad PEM",
               ctx.leaf.private_key_pem,
               ["example.com"],
               "staging",
               ctx.opts
             )
  end
end
