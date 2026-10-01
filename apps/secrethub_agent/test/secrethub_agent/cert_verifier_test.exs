defmodule SecretHub.Agent.CertVerifierTest do
  use ExUnit.Case, async: false
  alias SecretHub.Agent.CertVerifier
  alias X509.Certificate.Extension

  setup do
    start_supervised!(CertVerifier)
    :ok
  end

  test "expired, incorrectly signed and noncanonical application identities fail closed" do
    ca_key = X509.PrivateKey.new_rsa(2048)
    ca_cert = X509.Certificate.self_signed(ca_key, "/CN=Core CA", template: :root_ca)
    assert :ok = CertVerifier.configure_trust(X509.Certificate.to_pem(ca_cert))
    app_id = Ecto.UUID.generate()
    key = X509.PrivateKey.new_rsa(2048)
    now = DateTime.utc_now()

    for pem <- [
          app_cert(key, String.upcase(app_id), ca_cert, ca_key),
          app_cert(key, app_id, ca_cert, X509.PrivateKey.new_rsa(2048)),
          app_cert(key, app_id, ca_cert, ca_key, [],
            validity:
              X509.Certificate.Validity.new(
                DateTime.add(now, -7200, :second),
                DateTime.add(now, -3600, :second)
              )
          ),
          app_cert(key, app_id, ca_cert, ca_key,
            subject_alt_name:
              Extension.subject_alt_name([
                {:uniformResourceIdentifier, ~c"urn:secrethub:app:wrong"}
              ])
          )
        ] do
      assert {:error, "INVALID_CERTIFICATE"} = CertVerifier.verify_app_cert_pem(pem)
    end
  end

  test "absence or malformed trust material fails closed" do
    assert {:error, "CA_UNAVAILABLE"} = CertVerifier.verify_app_cert_pem("malformed")
    assert {:error, "CA_UNAVAILABLE"} = CertVerifier.configure_trust("malformed")
    assert {:error, "CA_UNAVAILABLE"} = CertVerifier.verify_app_cert_pem("malformed")
  end

  test "configured CA accepts canonical app identity and rejects self-signed or missing EKU/SAN" do
    ca_key = X509.PrivateKey.new_rsa(2048)
    ca_cert = X509.Certificate.self_signed(ca_key, "/CN=Core CA", template: :root_ca)
    assert :ok = CertVerifier.configure_trust(X509.Certificate.to_pem(ca_cert))
    app_id = Ecto.UUID.generate()
    key = X509.PrivateKey.new_rsa(2048)
    pem = app_cert(key, app_id, ca_cert, ca_key)

    assert {:ok, %{app_id: ^app_id, canonical_fingerprint: fingerprint, public_key: _}} =
             CertVerifier.verify_app_cert_pem(pem)

    assert byte_size(fingerprint) == 64

    assert {:error, "INVALID_CERTIFICATE"} =
             CertVerifier.verify_app_cert_pem(
               X509.Certificate.to_pem(X509.Certificate.self_signed(key, "/CN=#{app_id}"))
             )

    assert {:error, "INVALID_CERTIFICATE"} =
             CertVerifier.verify_app_cert_pem(
               app_cert(key, app_id, ca_cert, ca_key, ext_key_usage: false)
             )

    assert {:error, "INVALID_CERTIFICATE"} =
             CertVerifier.verify_app_cert_pem(
               app_cert(key, app_id, ca_cert, ca_key, subject_alt_name: false)
             )
  end

  defp app_cert(key, app_id, ca_cert, ca_key, overrides \\ [], opts \\ []) do
    extensions =
      Keyword.merge(
        [
          ext_key_usage: Extension.ext_key_usage([:clientAuth]),
          subject_alt_name:
            Extension.subject_alt_name([
              {:uniformResourceIdentifier, to_charlist("urn:secrethub:app:#{app_id}")}
            ])
        ],
        overrides
      )

    X509.Certificate.new(
      X509.PublicKey.derive(key),
      "/O=SecretHub Applications/CN=#{app_id}",
      ca_cert,
      ca_key,
      Keyword.merge([template: :server, extensions: extensions], opts)
    )
    |> X509.Certificate.to_pem()
  end
end
