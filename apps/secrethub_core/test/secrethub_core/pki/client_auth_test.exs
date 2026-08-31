defmodule SecretHub.Core.PKI.ClientAuthTest do
  use SecretHub.Core.DataCase, async: false

  alias SecretHub.Core.PKI.ClientAuth
  alias SecretHub.Core.Repo

  alias SecretHub.Shared.Schemas.{
    Certificate,
    ClientAuthAuthority,
    ClientAuthCrl,
    ClientAuthIdentity,
    ClientAuthIssuanceRequest
  }

  setup do
    # Ensure clean state for client auth tests
    Repo.delete_all(ClientAuthIssuanceRequest)
    Repo.delete_all(ClientAuthCrl)

    Repo.delete_all(
      from(c in Certificate, where: c.cert_type in [:client_auth_ca, :client_auth_client])
    )

    Repo.delete_all(ClientAuthAuthority)
    Repo.delete_all(ClientAuthIdentity)
    :ok
  end

  describe "Authority Initialization & Lifecycle" do
    test "initializes a singleton ECDSA P-384 CA authority and initial CRL" do
      assert {:ok, %{authority: authority, ca_certificate: ca_cert, initial_crl: crl}} =
               ClientAuth.initialize_authority(%{
                 "name" => "Test Client Auth CA",
                 "key_algorithm" => "ecdsa_p384"
               })

      assert authority.status == "active"
      assert authority.slug == "client-auth"
      assert authority.key_algorithm == "ecdsa_p384"
      assert authority.current_generation == 1
      assert authority.current_crl_number == 1
      assert authority.ca_certificate_id == ca_cert.id
      assert authority.current_crl_id == crl.id

      # Verify CA certificate properties
      assert ca_cert.cert_type == :client_auth_ca
      assert ca_cert.common_name == "Test Client Auth CA"
      assert ca_cert.organization == "SecretHub"
      assert String.starts_with?(ca_cert.subject, "O=SecretHub, CN=Test Client Auth CA")
      assert String.length(ca_cert.canonical_fingerprint) == 64
      assert "keyCertSign" in ca_cert.key_usage
      assert "cRLSign" in ca_cert.key_usage

      # CA private key is encrypted
      assert is_binary(ca_cert.private_key_encrypted)

      # Verify initial CRL properties
      assert crl.crl_number == 1
      assert crl.generation == 1
      assert crl.revoked_count == 0
      assert String.length(crl.crl_der_sha256) == 64
      assert DateTime.compare(crl.next_update, crl.this_update) == :gt

      # Verify parsed CRL signature
      {:ok, parsed_ca} = X509.Certificate.from_pem(ca_cert.certificate_pem)
      {:ok, parsed_crl} = X509.CRL.from_pem(crl.crl_pem)

      assert X509.CRL.valid?(
               parsed_crl,
               parsed_crl |> X509.CRL.issuer() |> then(fn _ -> parsed_ca end)
             )
    end

    test "initializes an RSA-4096 CA authority" do
      assert {:ok, %{authority: authority, ca_certificate: ca_cert}} =
               ClientAuth.initialize_authority(%{
                 "name" => "RSA Client CA",
                 "key_algorithm" => "rsa_4096"
               })

      assert authority.key_algorithm == "rsa_4096"
      assert ca_cert.cert_type == :client_auth_ca
    end

    test "rejects duplicate authority initialization" do
      assert {:ok, _} = ClientAuth.initialize_authority()
      assert {:error, :authority_already_initialized} = ClientAuth.initialize_authority()
    end

    test "status/0 returns detailed authority public status" do
      assert {:error, :authority_not_initialized} = ClientAuth.status()

      assert {:ok, _} = ClientAuth.initialize_authority()
      assert {:ok, status} = ClientAuth.status()

      assert status.status == "active"
      assert status.slug == "client-auth"
      assert status.generation == 1
      assert status.crl_number == 1
      assert status.ca.common_name == "SecretHub Client Authentication CA"
      assert is_binary(status.ca.canonical_fingerprint)
      assert status.crl.crl_number == 1
      assert status.stats.active_identities_count == 0
      assert status.stats.active_certificates_count == 0
    end
  end

  describe "Identity Management" do
    setup do
      {:ok, initialized} = ClientAuth.initialize_authority()
      %{authority: initialized.authority, ca: initialized.ca_certificate}
    end

    test "creates and retrieves a client identity" do
      assert {:ok, identity} =
               ClientAuth.create_identity(%{
                 "name" => "backup-agent-1",
                 "metadata" => %{"role" => "backup", "datacenter" => "ams"}
               })

      assert identity.name == "backup-agent-1"
      assert identity.status == "active"
      assert identity.metadata["role"] == "backup"

      assert {:ok, retrieved} = ClientAuth.get_identity(identity.id)
      assert retrieved.id == identity.id
      assert retrieved.name == identity.name

      identities = ClientAuth.list_identities()
      assert length(identities) == 1
      assert hd(identities).id == identity.id
    end

    test "rejects duplicate identity names" do
      assert {:ok, _} = ClientAuth.create_identity(%{"name" => "unique-agent"})
      assert {:error, changeset} = ClientAuth.create_identity(%{"name" => "unique-agent"})
      assert %{name: ["has already been taken"]} = errors_on(changeset)
    end

    test "disables an identity without certificates" do
      assert {:ok, identity} = ClientAuth.create_identity(%{"name" => "idle-agent"})
      assert {:ok, disabled} = ClientAuth.disable_identity(identity.id)
      assert disabled.status == "disabled"
    end
  end

  describe "Certificate Issuance & Inspection" do
    setup do
      {:ok, initialized} = ClientAuth.initialize_authority()
      {:ok, identity} = ClientAuth.create_identity(%{"name" => "app-client-1"})
      %{authority: initialized.authority, ca: initialized.ca_certificate, identity: identity}
    end

    test "issues a canonical client certificate from a valid ECDSA P-256 CSR", %{
      identity: identity,
      ca: ca
    } do
      client_key = X509.PrivateKey.new_ec(:secp256r1)
      csr_pem = client_key |> X509.CSR.new("/CN=hostile-name/O=HostileOrg") |> X509.CSR.to_pem()
      request_id = Ecto.UUID.generate()

      assert {:ok, %{certificate: cert_pem, cert_record: cert_record, replayed: false}} =
               ClientAuth.issue_certificate(identity.id, csr_pem, request_id, ttl_seconds: 86_400)

      # Verify server-controlled subject and URI SAN
      assert cert_record.common_name == identity.id
      assert cert_record.subject == "O=SecretHub Client Authentication, CN=#{identity.id}"
      assert cert_record.issuer == ca.subject
      assert cert_record.cert_type == :client_auth_client
      assert cert_record.client_auth_identity_id == identity.id
      assert cert_record.metadata["extended_key_usage"] == ["clientAuth"]
      assert cert_record.metadata["san_uri"] == ["urn:secrethub:client:#{identity.id}"]
      assert String.length(cert_record.canonical_fingerprint) == 64

      # Verify X.509 structure using X509 lib
      {:ok, parsed} = X509.Certificate.from_pem(cert_pem)
      {:ok, parsed_ca} = X509.Certificate.from_pem(ca.certificate_pem)

      assert :public_key.pkix_is_issuer(parsed, parsed_ca)

      assert :public_key.pkix_verify(
               X509.Certificate.to_der(parsed),
               X509.Certificate.public_key(parsed_ca)
             )

      # Verify SAN extension
      {:Extension, {2, 5, 29, 17}, false, san_values} =
        X509.Certificate.extension(parsed, :subject_alt_name)

      expected_uri = ~c"urn:secrethub:client:" ++ to_charlist(identity.id)
      assert {:uniformResourceIdentifier, expected_uri} in san_values

      # Verify BasicConstraints CA:FALSE
      {:Extension, {2, 5, 29, 19}, _critical, {:BasicConstraints, false, _}} =
        X509.Certificate.extension(parsed, :basic_constraints)
    end

    test "issues a canonical client certificate from a valid RSA-2048 CSR", %{identity: identity} do
      client_key = X509.PrivateKey.new_rsa(2048)
      csr_pem = client_key |> X509.CSR.new("/CN=rsa-client") |> X509.CSR.to_pem()
      request_id = Ecto.UUID.generate()

      assert {:ok, %{certificate: cert_pem, cert_record: cert, replayed: false}} =
               ClientAuth.issue_certificate(identity.id, csr_pem, request_id)

      assert cert.cert_type == :client_auth_client
      assert is_binary(cert_pem)
    end

    test "idempotently replays identical issuance request", %{identity: identity} do
      client_key = X509.PrivateKey.new_ec(:secp256r1)
      csr_pem = client_key |> X509.CSR.new("/CN=client") |> X509.CSR.to_pem()
      request_id = Ecto.UUID.generate()

      assert {:ok, first} =
               ClientAuth.issue_certificate(identity.id, csr_pem, request_id, ttl_seconds: 3600)

      assert first.replayed == false

      # Replay with same parameters returns exact same certificate
      assert {:ok, replayed} =
               ClientAuth.issue_certificate(identity.id, csr_pem, request_id, ttl_seconds: 3600)

      assert replayed.replayed == true
      assert replayed.cert_record.id == first.cert_record.id
      assert replayed.certificate == first.certificate
    end

    test "rejects conflicting replay with different CSR", %{identity: identity} do
      key1 = X509.PrivateKey.new_ec(:secp256r1)
      key2 = X509.PrivateKey.new_ec(:secp256r1)
      csr1 = key1 |> X509.CSR.new("/CN=client1") |> X509.CSR.to_pem()
      csr2 = key2 |> X509.CSR.new("/CN=client2") |> X509.CSR.to_pem()
      request_id = Ecto.UUID.generate()

      assert {:ok, _} = ClientAuth.issue_certificate(identity.id, csr1, request_id)

      assert {:error, :idempotency_conflict} =
               ClientAuth.issue_certificate(identity.id, csr2, request_id)
    end

    test "rejects CSR with invalid signature", %{identity: identity} do
      key = X509.PrivateKey.new_ec(:secp256r1)
      csr = X509.CSR.new(key, "/CN=test")
      der = X509.CSR.to_der(csr)
      tampered_der = :binary.part(der, 0, byte_size(der) - 5) <> <<0, 0, 0, 0, 0>>
      entry = {:CertificationRequest, tampered_der, :not_encrypted}
      csr_pem = :public_key.pem_encode([entry])
      request_id = Ecto.UUID.generate()

      assert {:error, :invalid_csr} =
               ClientAuth.issue_certificate(identity.id, csr_pem, request_id)
    end

    test "rejects unsupported EC curves (P-521)", %{identity: identity} do
      key = X509.PrivateKey.new_ec(:secp521r1)
      csr_pem = key |> X509.CSR.new("/CN=p521") |> X509.CSR.to_pem()
      request_id = Ecto.UUID.generate()

      assert {:error, :unsupported_key} =
               ClientAuth.issue_certificate(identity.id, csr_pem, request_id)
    end

    test "rejects weak RSA key (<2048)", %{identity: identity} do
      key = X509.PrivateKey.new_rsa(1024)
      csr_pem = key |> X509.CSR.new("/CN=weak-rsa") |> X509.CSR.to_pem()
      request_id = Ecto.UUID.generate()

      assert {:error, :unsupported_key} =
               ClientAuth.issue_certificate(identity.id, csr_pem, request_id)
    end

    test "rejects issuance for disabled identity", %{identity: identity} do
      assert {:ok, _} = ClientAuth.disable_identity(identity.id)

      key = X509.PrivateKey.new_ec(:secp256r1)
      csr_pem = key |> X509.CSR.new("/CN=client") |> X509.CSR.to_pem()
      request_id = Ecto.UUID.generate()

      assert {:error, :identity_disabled} =
               ClientAuth.issue_certificate(identity.id, csr_pem, request_id)
    end
  end

  describe "Revocation & CRL Management" do
    setup do
      {:ok, initialized} = ClientAuth.initialize_authority()
      {:ok, identity} = ClientAuth.create_identity(%{"name" => "revocation-agent"})
      key = X509.PrivateKey.new_ec(:secp256r1)
      csr_pem = key |> X509.CSR.new("/CN=client") |> X509.CSR.to_pem()

      {:ok, issued} = ClientAuth.issue_certificate(identity.id, csr_pem, Ecto.UUID.generate())

      %{
        authority: initialized.authority,
        ca: initialized.ca_certificate,
        identity: identity,
        certificate: issued.cert_record
      }
    end

    test "revokes a certificate and generates a new signed CRL", %{certificate: cert, ca: ca} do
      assert {:ok, result} = ClientAuth.revoke_certificate(cert.id, "key_compromise")

      assert result.certificate.revoked == true
      assert result.certificate.revocation_reason == "key_compromise"
      assert result.crl.crl_number == 2
      assert result.crl.generation == 2
      assert result.crl.revoked_count == 1

      # Check CRL in X509 parser
      {:ok, parsed_crl} = X509.CRL.from_pem(result.crl.crl_pem)
      {:ok, parsed_ca} = X509.Certificate.from_pem(ca.certificate_pem)
      assert X509.CRL.valid?(parsed_crl, parsed_ca)

      entries = X509.CRL.list(parsed_crl)
      assert length(entries) == 1

      # Verify authority state was bumped
      assert {:ok, status} = ClientAuth.status()
      assert status.generation == 2
      assert status.crl_number == 2
      assert status.stats.revoked_certificates_count == 1
    end

    test "re-revoking an already revoked certificate is idempotent without generating extra CRL",
         %{certificate: cert} do
      assert {:ok, first} = ClientAuth.revoke_certificate(cert.id, "key_compromise")
      assert first.crl_number == 2

      assert {:ok, second} = ClientAuth.revoke_certificate(cert.id, "key_compromise")
      assert second.crl_number == 2
      assert second.generation == 2
    end

    test "disable_identity revokes all active certificates and produces one CRL", %{
      identity: identity,
      ca: ca
    } do
      # Issue a second certificate for the same identity
      key2 = X509.PrivateKey.new_ec(:secp256r1)
      csr2 = key2 |> X509.CSR.new("/CN=client2") |> X509.CSR.to_pem()
      {:ok, _issued2} = ClientAuth.issue_certificate(identity.id, csr2, Ecto.UUID.generate())

      assert {:ok, disabled} = ClientAuth.disable_identity(identity.id, "cessation_of_operation")
      assert disabled.status == "disabled"

      assert {:ok, status} = ClientAuth.status()
      assert status.generation == 2
      assert status.crl_number == 2
      assert status.crl.revoked_count == 2

      # Check CRL contents
      {:ok, crl_record} = Repo.get(ClientAuthCrl, status.crl.id) |> then(&{:ok, &1})
      {:ok, parsed_crl} = X509.CRL.from_pem(crl_record.crl_pem)
      {:ok, parsed_ca} = X509.Certificate.from_pem(ca.certificate_pem)
      assert X509.CRL.valid?(parsed_crl, parsed_ca)
      assert length(X509.CRL.list(parsed_crl)) == 2
    end

    test "manual CRL refresh generates new generation and CRL number" do
      assert {:ok, refresh_result} = ClientAuth.refresh_crl()
      assert refresh_result.crl_number == 2
      assert refresh_result.generation == 2
    end
  end

  describe "Trust Bundle Generation" do
    setup do
      {:ok, initialized} = ClientAuth.initialize_authority()
      %{authority: initialized.authority, ca: initialized.ca_certificate}
    end

    test "current_bundle/0 returns valid deterministic public bundle" do
      assert {:ok, bundle} = ClientAuth.current_bundle()

      assert bundle["schema_version"] == 1
      assert bundle["authority"] == "client-auth"
      assert bundle["generation"] == 1
      assert bundle["crl_number"] == 1
      assert String.length(bundle["ca_fingerprint"]) == 64
      assert String.length(bundle["crl_der_sha256"]) == 64
      assert String.length(bundle["bundle_sha256"]) == 64
      assert String.starts_with?(bundle["ca_bundle_pem"], "-----BEGIN CERTIFICATE-----")
      assert String.starts_with?(bundle["crl_pem"], "-----BEGIN X509 CRL-----")
    end

    test "record_bundle_receipt tracks agent applied status" do
      assert {:ok, receipt} =
               ClientAuth.record_bundle_receipt(%{
                 "agent_id" => "agent-amsterdam-1",
                 "generation" => 1,
                 "crl_number" => 1,
                 "bundle_sha256" =>
                   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                 "status" => "applied",
                 "applied_at" => DateTime.utc_now()
               })

      assert receipt.agent_id == "agent-amsterdam-1"
      assert receipt.status == "applied"

      receipts = ClientAuth.list_bundle_receipts()
      assert length(receipts) == 1
    end
  end
end
