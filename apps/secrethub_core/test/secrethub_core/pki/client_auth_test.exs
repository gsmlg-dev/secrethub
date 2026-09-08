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
      assert ca_cert.subject == "/O=SecretHub/CN=Test Client Auth CA"
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

    test "rejects non-binary, nil, or empty CSR", %{identity: identity} do
      request_id = Ecto.UUID.generate()
      assert {:error, :invalid_csr} = ClientAuth.issue_certificate(identity.id, nil, request_id)
      assert {:error, :invalid_csr} = ClientAuth.issue_certificate(identity.id, "", request_id)
      assert {:error, :invalid_csr} = ClientAuth.issue_certificate(identity.id, 12345, request_id)
      assert {:error, :invalid_csr} = ClientAuth.issue_certificate(identity.id, %{}, request_id)
    end

    test "rejects oversized CSR (>64KB)", %{identity: identity} do
      oversized = String.duplicate("A", 65_537)
      request_id = Ecto.UUID.generate()

      assert {:error, :invalid_csr} =
               ClientAuth.issue_certificate(identity.id, oversized, request_id)
    end

    test "strictly compares TTL on replay: omitted vs explicit is a conflict", %{
      identity: identity
    } do
      client_key = X509.PrivateKey.new_ec(:secp256r1)
      csr_pem = client_key |> X509.CSR.new("/CN=client-ttl-test") |> X509.CSR.to_pem()
      request_id = Ecto.UUID.generate()

      # First request with explicit TTL 3600
      assert {:ok, first} =
               ClientAuth.issue_certificate(identity.id, csr_pem, request_id, ttl_seconds: 3600)

      assert first.replayed == false

      # Replay with omitted TTL -> MUST conflict
      assert {:error, :idempotency_conflict} =
               ClientAuth.issue_certificate(identity.id, csr_pem, request_id)

      # Replay with same explicit TTL -> succeeds
      assert {:ok, replayed} =
               ClientAuth.issue_certificate(identity.id, csr_pem, request_id, ttl_seconds: 3600)

      assert replayed.replayed == true
    end

    test "strictly compares TTL on replay: omitted vs omitted succeeds", %{identity: identity} do
      client_key = X509.PrivateKey.new_ec(:secp256r1)
      csr_pem = client_key |> X509.CSR.new("/CN=client-ttl-nil") |> X509.CSR.to_pem()
      request_id = Ecto.UUID.generate()

      # First request with default (omitted) TTL
      assert {:ok, first} =
               ClientAuth.issue_certificate(identity.id, csr_pem, request_id)

      assert first.replayed == false

      # Replay with omitted TTL -> succeeds
      assert {:ok, replayed} =
               ClientAuth.issue_certificate(identity.id, csr_pem, request_id)

      assert replayed.replayed == true

      # Replay with explicit TTL -> MUST conflict
      assert {:error, :idempotency_conflict} =
               ClientAuth.issue_certificate(identity.id, csr_pem, request_id, ttl_seconds: 7200)
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

    test "record_bundle_receipt tracks agent applied status and validates authenticity" do
      {:ok, bundle} = ClientAuth.current_bundle()

      # 1. Authentic applied receipt succeeds
      assert {:ok, receipt} =
               ClientAuth.record_bundle_receipt(%{
                 "agent_id" => "agent-amsterdam-1",
                 "generation" => bundle["generation"],
                 "crl_number" => bundle["crl_number"],
                 "bundle_sha256" => bundle["bundle_sha256"],
                 "status" => "applied",
                 "applied_at" => DateTime.utc_now()
               })

      assert receipt.agent_id == "agent-amsterdam-1"
      assert receipt.status == "applied"

      # 2. Same-generation failure does NOT get suppressed
      assert {:ok, failed_receipt} =
               ClientAuth.record_bundle_receipt(%{
                 "agent_id" => "agent-amsterdam-1",
                 "generation" => bundle["generation"],
                 "crl_number" => bundle["crl_number"],
                 "bundle_sha256" => bundle["bundle_sha256"],
                 "status" => "failed",
                 "last_error_code" => "caddy_reload_failed",
                 "last_error_detail" => "connection refused"
               })

      assert failed_receipt.status == "failed"
      assert failed_receipt.last_error_code == "caddy_reload_failed"

      # 3. Agent recovers from failure back to applied without being wedged
      assert {:ok, recovered_receipt} =
               ClientAuth.record_bundle_receipt(%{
                 "agent_id" => "agent-amsterdam-1",
                 "generation" => bundle["generation"],
                 "crl_number" => bundle["crl_number"],
                 "bundle_sha256" => bundle["bundle_sha256"],
                 "status" => "applied",
                 "applied_at" => DateTime.utc_now()
               })

      assert recovered_receipt.status == "applied"
      assert recovered_receipt.last_error_code == nil

      # 4. Bogus hash for applied bundle is rejected, marked failed, and logs equivocation
      bogus_sha = String.duplicate("0", 64)

      assert {:ok, rejected_receipt} =
               ClientAuth.record_bundle_receipt(%{
                 "agent_id" => "agent-amsterdam-1",
                 "generation" => bundle["generation"],
                 "crl_number" => bundle["crl_number"],
                 "bundle_sha256" => bogus_sha,
                 "status" => "applied",
                 "applied_at" => DateTime.utc_now()
               })

      assert rejected_receipt.status == "failed"
      assert rejected_receipt.last_error_code == "bundle_hash_mismatch_equivocation"

      # Verify equivocation audit event was logged
      audit_query =
        from(a in SecretHub.Shared.Schemas.AuditLog,
          where: a.event_type == "pki.client_auth.agent_equivocation_detected",
          order_by: [desc: a.sequence_number]
        )

      assert [%{event_type: "pki.client_auth.agent_equivocation_detected"} | _] =
               SecretHub.Core.Repo.all(audit_query)

      # 5. Monotonic guard: older receipt for same agent does not overwrite newer generation
      assert {:ok, receipt_older} =
               ClientAuth.record_bundle_receipt(%{
                 "agent_id" => "agent-amsterdam-1",
                 "generation" => 0,
                 "crl_number" => 0,
                 "bundle_sha256" => "old-sha",
                 "status" => "failed",
                 "last_error_code" => "stale_update"
               })

      assert receipt_older.generation == bundle["generation"]

      receipts = ClientAuth.list_bundle_receipts()
      assert length(receipts) == 1
      assert hd(receipts).generation == bundle["generation"]
    end

    test "delayed authentic historical receipt is accepted after authority generation advances" do
      {:ok, gen1_bundle} = ClientAuth.current_bundle()
      assert gen1_bundle["generation"] == 1

      # Force a CRL refresh / advance authority generation
      {:ok, gen2_crl} = ClientAuth.refresh_crl()
      assert gen2_crl.crl_number == 2

      # Now verify agent submitting authentic gen 1 bundle receipt is accepted as applied
      assert {:ok, receipt} =
               ClientAuth.record_bundle_receipt(%{
                 "agent_id" => "agent-delayed-historical",
                 "generation" => gen1_bundle["generation"],
                 "crl_number" => gen1_bundle["crl_number"],
                 "bundle_sha256" => gen1_bundle["bundle_sha256"],
                 "status" => "applied",
                 "applied_at" => DateTime.utc_now()
               })

      assert receipt.status == "applied"
      assert receipt.generation == 1
      assert receipt.crl_number == 1
    end

    test "stale failure receipt with older timestamp cannot overwrite applied status for the same generation" do
      {:ok, bundle} = ClientAuth.current_bundle()
      t_applied = DateTime.utc_now()
      t_stale_failure = DateTime.add(t_applied, -60, :second)

      # 1. Agent successfully applies bundle
      assert {:ok, receipt1} =
               ClientAuth.record_bundle_receipt(%{
                 "agent_id" => "agent-out-of-order",
                 "generation" => bundle["generation"],
                 "crl_number" => bundle["crl_number"],
                 "bundle_sha256" => bundle["bundle_sha256"],
                 "status" => "applied",
                 "applied_at" => t_applied
               })

      assert receipt1.status == "applied"

      # 2. Delayed failure receipt arriving later with older timestamp
      assert {:ok, receipt2} =
               ClientAuth.record_bundle_receipt(%{
                 "agent_id" => "agent-out-of-order",
                 "generation" => bundle["generation"],
                 "crl_number" => bundle["crl_number"],
                 "bundle_sha256" => bundle["bundle_sha256"],
                 "status" => "failed",
                 "applied_at" => t_stale_failure,
                 "last_error_code" => "transient_stale_error"
               })

      # Must remain applied because failure occurred before the applied timestamp
      assert receipt2.status == "applied"
    end

    test "stale failure receipt with ISO-8601 string timestamp cannot overwrite applied status" do
      {:ok, bundle} = ClientAuth.current_bundle()
      t_applied = DateTime.utc_now()
      t_stale_failure = DateTime.add(t_applied, -60, :second)

      assert {:ok, receipt1} =
               ClientAuth.record_bundle_receipt(%{
                 "agent_id" => "agent-iso-string-test",
                 "generation" => bundle["generation"],
                 "crl_number" => bundle["crl_number"],
                 "bundle_sha256" => bundle["bundle_sha256"],
                 "status" => "applied",
                 "applied_at" => DateTime.to_iso8601(t_applied)
               })

      assert receipt1.status == "applied"

      # Stale failure with ISO-8601 string timestamp
      assert {:ok, receipt2} =
               ClientAuth.record_bundle_receipt(%{
                 "agent_id" => "agent-iso-string-test",
                 "generation" => bundle["generation"],
                 "crl_number" => bundle["crl_number"],
                 "bundle_sha256" => bundle["bundle_sha256"],
                 "status" => "failed",
                 "applied_at" => DateTime.to_iso8601(t_stale_failure),
                 "last_error_code" => "stale_error_string"
               })

      assert receipt2.status == "applied"
    end

    test "delayed success receipt cannot overwrite newer failure observation" do
      {:ok, bundle} = ClientAuth.current_bundle()
      t_failure = DateTime.utc_now()
      t_stale_success = DateTime.add(t_failure, -60, :second)

      # 1. Agent reports failure at t_failure
      assert {:ok, receipt1} =
               ClientAuth.record_bundle_receipt(%{
                 "agent_id" => "agent-delayed-success-test",
                 "generation" => bundle["generation"],
                 "crl_number" => bundle["crl_number"],
                 "bundle_sha256" => bundle["bundle_sha256"],
                 "status" => "failed",
                 "applied_at" => DateTime.to_iso8601(t_failure),
                 "last_error_code" => "caddy_reload_failed"
               })

      assert receipt1.status == "failed"
      assert receipt1.last_error_code == "caddy_reload_failed"

      # 2. Delayed success arrives from earlier t_stale_success
      assert {:ok, receipt2} =
               ClientAuth.record_bundle_receipt(%{
                 "agent_id" => "agent-delayed-success-test",
                 "generation" => bundle["generation"],
                 "crl_number" => bundle["crl_number"],
                 "bundle_sha256" => bundle["bundle_sha256"],
                 "status" => "applied",
                 "applied_at" => DateTime.to_iso8601(t_stale_success)
               })

      # Must remain failed because failure is newer
      assert receipt2.status == "failed"
      assert receipt2.last_error_code == "caddy_reload_failed"
    end

    test "candidate failure preserves last_applied watermark and sequence ordering" do
      {:ok, bundle} = ClientAuth.current_bundle()
      t1 = DateTime.utc_now()
      t2 = DateTime.add(t1, 10, :second)
      t3 = DateTime.add(t1, 20, :second)
      candidate_sha = String.duplicate("b", 64)

      # 1. Agent successfully applies Generation 1
      assert {:ok, r1} =
               ClientAuth.record_bundle_receipt(%{
                 "agent_id" => "agent-watermark-seq-test",
                 "generation" => bundle["generation"],
                 "crl_number" => bundle["crl_number"],
                 "bundle_sha256" => bundle["bundle_sha256"],
                 "status" => "applied",
                 "applied_at" => t1
               })

      assert r1.status == "applied"
      assert r1.generation == bundle["generation"]
      assert r1.last_applied_generation == bundle["generation"]
      assert r1.last_applied_crl_number == bundle["crl_number"]
      assert r1.last_applied_bundle_sha256 == bundle["bundle_sha256"]
      assert r1.observation_sequence == 1

      # 2. Agent attempts candidate Generation 42 and fails
      assert {:ok, r2} =
               ClientAuth.record_bundle_receipt(%{
                 "agent_id" => "agent-watermark-seq-test",
                 "generation" => 42,
                 "crl_number" => 42,
                 "bundle_sha256" => candidate_sha,
                 "status" => "failed",
                 "last_error_code" => "connection_timeout",
                 "applied_at" => t2
               })

      assert r2.status == "failed"
      assert r2.generation == 42
      # Watermark is preserved!
      assert r2.last_applied_generation == bundle["generation"]
      assert r2.last_applied_crl_number == bundle["crl_number"]
      assert r2.last_applied_bundle_sha256 == bundle["bundle_sha256"]
      assert r2.observation_sequence == 2

      # 3. Agent recovers back to authentic Generation 1
      assert {:ok, r3} =
               ClientAuth.record_bundle_receipt(%{
                 "agent_id" => "agent-watermark-seq-test",
                 "generation" => bundle["generation"],
                 "crl_number" => bundle["crl_number"],
                 "bundle_sha256" => bundle["bundle_sha256"],
                 "status" => "applied",
                 "applied_at" => t3
               })

      assert r3.status == "applied"
      assert r3.generation == bundle["generation"]
      assert r3.last_applied_generation == bundle["generation"]
      assert r3.observation_sequence == 3
    end

    test "duplicate receipt at identical timestamp is idempotent and ignored" do
      {:ok, bundle} = ClientAuth.current_bundle()
      t = DateTime.utc_now()

      assert {:ok, r1} =
               ClientAuth.record_bundle_receipt(%{
                 "agent_id" => "agent-idempotent-test",
                 "generation" => bundle["generation"],
                 "crl_number" => bundle["crl_number"],
                 "bundle_sha256" => bundle["bundle_sha256"],
                 "status" => "applied",
                 "applied_at" => t
               })

      assert {:ok, r2} =
               ClientAuth.record_bundle_receipt(%{
                 "agent_id" => "agent-idempotent-test",
                 "generation" => bundle["generation"],
                 "crl_number" => bundle["crl_number"],
                 "bundle_sha256" => bundle["bundle_sha256"],
                 "status" => "applied",
                 "applied_at" => t
               })

      assert r2.id == r1.id
      assert r2.observation_sequence == r1.observation_sequence
    end

    test "sequence-first ordering applies higher sequence regardless of arrival order or identical timestamp" do
      {:ok, bundle} = ClientAuth.current_bundle()
      t_same = DateTime.utc_now() |> DateTime.truncate(:second)

      # Report sequence 100 (applied) and sequence 101 (failed) with identical timestamp
      # Case A: 101 arrives after 100
      assert {:ok, r100} =
               ClientAuth.record_bundle_receipt(%{
                 "agent_id" => "agent-seq-order-test-a",
                 "generation" => bundle["generation"],
                 "crl_number" => bundle["crl_number"],
                 "bundle_sha256" => bundle["bundle_sha256"],
                 "status" => "applied",
                 "applied_at" => t_same,
                 "observation_sequence" => 100
               })

      assert r100.status == "applied"
      assert r100.observation_sequence == 100

      assert {:ok, r101} =
               ClientAuth.record_bundle_receipt(%{
                 "agent_id" => "agent-seq-order-test-a",
                 "generation" => bundle["generation"],
                 "crl_number" => bundle["crl_number"],
                 "bundle_sha256" => bundle["bundle_sha256"],
                 "status" => "failed",
                 "last_error_code" => "caddy_reload_failed",
                 "applied_at" => t_same,
                 "observation_sequence" => 101
               })

      # Final status must be failed because sequence 101 > 100
      assert r101.status == "failed"
      assert r101.last_error_code == "caddy_reload_failed"
      assert r101.observation_sequence == 101

      # Case B: 100 arrives after 101 (out of order arrival)
      assert {:ok, r_init} =
               ClientAuth.record_bundle_receipt(%{
                 "agent_id" => "agent-seq-order-test-b",
                 "generation" => bundle["generation"],
                 "crl_number" => bundle["crl_number"],
                 "bundle_sha256" => bundle["bundle_sha256"],
                 "status" => "failed",
                 "last_error_code" => "caddy_reload_failed",
                 "applied_at" => t_same,
                 "observation_sequence" => 101
               })

      assert r_init.status == "failed"
      assert r_init.observation_sequence == 101

      assert {:ok, r_stale} =
               ClientAuth.record_bundle_receipt(%{
                 "agent_id" => "agent-seq-order-test-b",
                 "generation" => bundle["generation"],
                 "crl_number" => bundle["crl_number"],
                 "bundle_sha256" => bundle["bundle_sha256"],
                 "status" => "applied",
                 "applied_at" => t_same,
                 "observation_sequence" => 100
               })

      # Final status must remain failed because sequence 100 is stale relative to 101
      assert r_stale.status == "failed"
      assert r_stale.observation_sequence == 101
    end

    test "conflicting observation payload with duplicate sequence is rejected and audited" do
      {:ok, bundle} = ClientAuth.current_bundle()
      t = DateTime.utc_now()

      assert {:ok, r1} =
               ClientAuth.record_bundle_receipt(%{
                 "agent_id" => "agent-conflict-seq-test",
                 "generation" => bundle["generation"],
                 "crl_number" => bundle["crl_number"],
                 "bundle_sha256" => bundle["bundle_sha256"],
                 "status" => "applied",
                 "applied_at" => t,
                 "observation_sequence" => 42
               })

      assert r1.status == "applied"
      assert r1.observation_sequence == 42

      # Duplicate sequence with conflicting payload (different status / error)
      assert {:error, :conflicting_observation_sequence} =
               ClientAuth.record_bundle_receipt(%{
                 "agent_id" => "agent-conflict-seq-test",
                 "generation" => bundle["generation"],
                 "crl_number" => bundle["crl_number"],
                 "bundle_sha256" => bundle["bundle_sha256"],
                 "status" => "failed",
                 "last_error_code" => "differing_event",
                 "applied_at" => t,
                 "observation_sequence" => 42
               })

      # Conflicting sequence rejection audit event must survive transaction and persist in DB
      events =
        SecretHub.Core.Audit.search_logs(%{
          event_type: "pki.client_auth.agent_equivocation_detected"
        })

      assert Enum.any?(events, fn ev ->
               ev.actor_id == "agent-conflict-seq-test" and
                 ev.access_granted == false and
                 ev.hash_version == 2
             end)

      assert {:ok, :valid} = SecretHub.Core.Audit.verify_chain()
    end

    test "authentic applied receipt recovers agent after a failed candidate generation" do
      {:ok, bundle} = ClientAuth.current_bundle()
      candidate_sha = String.duplicate("a", 64)

      # 1. Agent reports candidate failure at generation 1000
      assert {:ok, failed_receipt} =
               ClientAuth.record_bundle_receipt(%{
                 "agent_id" => "agent-failed-candidate",
                 "generation" => 1000,
                 "crl_number" => 1000,
                 "bundle_sha256" => candidate_sha,
                 "status" => "failed",
                 "last_error_code" => "download_failed"
               })

      assert failed_receipt.status == "failed"
      assert failed_receipt.generation == 1000

      # 2. Agent now applies authentic current bundle (generation 1)
      assert {:ok, applied_receipt} =
               ClientAuth.record_bundle_receipt(%{
                 "agent_id" => "agent-failed-candidate",
                 "generation" => bundle["generation"],
                 "crl_number" => bundle["crl_number"],
                 "bundle_sha256" => bundle["bundle_sha256"],
                 "status" => "applied",
                 "applied_at" => DateTime.utc_now()
               })

      # Must successfully update to applied status at generation 1
      assert applied_receipt.status == "applied"
      assert applied_receipt.generation == bundle["generation"]
      assert applied_receipt.last_error_code == nil
    end

    test "list_bundle_receipts supports authority slug and pagination options" do
      {:ok, bundle} = ClientAuth.current_bundle()

      for i <- 1..5 do
        {:ok, _} =
          ClientAuth.record_bundle_receipt(%{
            "agent_id" => "agent-list-#{i}",
            "generation" => bundle["generation"],
            "crl_number" => bundle["crl_number"],
            "bundle_sha256" => bundle["bundle_sha256"],
            "status" => "applied"
          })
      end

      # List by slug
      receipts = ClientAuth.list_bundle_receipts("client-auth", limit: 3, offset: 0)
      assert length(receipts) == 3

      receipts_page2 = ClientAuth.list_bundle_receipts("client-auth", limit: 3, offset: 3)
      assert length(receipts_page2) == 2

      # Unknown slug returns empty list
      assert [] == ClientAuth.list_bundle_receipts("unknown-slug")
    end
  end

  describe "CAValidator" do
    alias SecretHub.Core.PKI.ClientAuth.CAValidator

    setup do
      {:ok, initialized} = ClientAuth.initialize_authority()
      %{authority: initialized.authority, ca: initialized.ca_certificate}
    end

    test "validates active authority and CA key successfully", %{authority: authority, ca: ca} do
      {:ok, key} = SecretHub.Core.PKI.ClientAuth.Issuer.decrypt_ca_key(ca)
      assert :ok = CAValidator.validate(authority, ca, key, requested_ttl: 86_400)
    end

    test "rejects expired CA", %{authority: authority, ca: ca} do
      {:ok, key} = SecretHub.Core.PKI.ClientAuth.Issuer.decrypt_ca_key(ca)
      future_now = DateTime.add(DateTime.utc_now(), 3650 * 86_400, :second)
      assert {:error, :ca_expired, _} = CAValidator.validate(authority, ca, key, now: future_now)
    end

    test "rejects CA with insufficient remaining lifetime", %{authority: authority, ca: ca} do
      {:ok, key} = SecretHub.Core.PKI.ClientAuth.Issuer.decrypt_ca_key(ca)
      # Ask for TTL longer than CA validity
      assert {:error, :ca_insufficient_lifetime, _} =
               CAValidator.validate(authority, ca, key, requested_ttl: 3650 * 86_400)
    end

    test "rejects mismatched private key", %{authority: authority, ca: ca} do
      wrong_key = X509.PrivateKey.new_ec(:secp384r1)
      assert {:error, :ca_key_mismatch, _} = CAValidator.validate(authority, ca, wrong_key)
    end

    test "rejects CA record with wrong cert_type", %{authority: authority, ca: ca} do
      {:ok, key} = SecretHub.Core.PKI.ClientAuth.Issuer.decrypt_ca_key(ca)
      bad_ca = %{ca | cert_type: :server_cert}
      assert {:error, :ca_record_invalid, _} = CAValidator.validate(authority, bad_ca, key)
    end

    test "rejects revoked CA record", %{authority: authority, ca: ca} do
      {:ok, key} = SecretHub.Core.PKI.ClientAuth.Issuer.decrypt_ca_key(ca)
      bad_ca = %{ca | revoked: true}
      assert {:error, :ca_revoked, _} = CAValidator.validate(authority, bad_ca, key)
    end

    test "rejects CA record not bound to authority", %{authority: authority, ca: ca} do
      {:ok, key} = SecretHub.Core.PKI.ClientAuth.Issuer.decrypt_ca_key(ca)
      bad_ca = %{ca | client_auth_authority_id: Ecto.UUID.generate()}
      assert {:error, :ca_authority_mismatch, _} = CAValidator.validate(authority, bad_ca, key)
    end

    test "rejects CA record with null canonical fingerprint", %{authority: authority, ca: ca} do
      {:ok, key} = SecretHub.Core.PKI.ClientAuth.Issuer.decrypt_ca_key(ca)
      bad_ca = %{ca | canonical_fingerprint: nil}
      assert {:error, :ca_fingerprint_mismatch, _} = CAValidator.validate(authority, bad_ca, key)
    end

    test "rejects CA record with mismatched Subject CN", %{authority: authority, ca: ca} do
      {:ok, key} = SecretHub.Core.PKI.ClientAuth.Issuer.decrypt_ca_key(ca)
      mismatched_auth = %{authority | name: "Completely Different CA Name"}
      assert {:error, :ca_subject_mismatch, _} = CAValidator.validate(mismatched_auth, ca, key)
    end
  end

  describe "Lock ordering & Concurrency" do
    setup do
      {:ok, initialized} = ClientAuth.initialize_authority()
      {:ok, identity} = ClientAuth.create_identity(%{"name" => "concurrent-agent"})

      %{
        authority: initialized.authority,
        ca: initialized.ca_certificate,
        identity: identity
      }
    end

    test "concurrent issuance and disable_identity do not deadlock", %{identity: identity} do
      key = X509.PrivateKey.new_ec(:secp256r1)
      csr_pem = key |> X509.CSR.new("/CN=concurrent") |> X509.CSR.to_pem()

      task1 =
        Task.async(fn ->
          ClientAuth.issue_certificate(identity.id, csr_pem, Ecto.UUID.generate())
        end)

      task2 =
        Task.async(fn ->
          ClientAuth.disable_identity(identity.id, "concurrent_test")
        end)

      res1 = Task.await(task1, 5_000)
      res2 = Task.await(task2, 5_000)

      # Both tasks succeed or return clean business logic results without deadlock
      assert match?({:ok, _}, res1) or match?({:error, :identity_disabled}, res1)
      assert match?({:ok, _}, res2)
    end

    test "concurrent identical requests with same request_id are serialized and succeed idempotently",
         %{identity: identity} do
      key = X509.PrivateKey.new_ec(:secp256r1)
      csr_pem = key |> X509.CSR.new("/CN=concurrent-same-req") |> X509.CSR.to_pem()
      request_id = Ecto.UUID.generate()

      # Launch 4 concurrent requests with the exact same request_id and payload
      tasks =
        for _ <- 1..4 do
          Task.async(fn ->
            ClientAuth.issue_certificate(identity.id, csr_pem, request_id, ttl_seconds: 3600)
          end)
        end

      results = Task.await_many(tasks, 5_000)

      # All 4 must succeed
      for res <- results do
        assert match?({:ok, _}, res)
      end

      # Exactly one should have replayed: false, the rest replayed: true
      non_replayed_count =
        Enum.count(results, fn {:ok, r} -> r.replayed == false end)

      replayed_count =
        Enum.count(results, fn {:ok, r} -> r.replayed == true end)

      assert non_replayed_count == 1
      assert replayed_count == 3
    end

    test "concurrent conflicting requests with same request_id return idempotency conflict", %{
      identity: identity
    } do
      key1 = X509.PrivateKey.new_ec(:secp256r1)
      key2 = X509.PrivateKey.new_ec(:secp256r1)
      csr1 = key1 |> X509.CSR.new("/CN=concurrent-conflict-1") |> X509.CSR.to_pem()
      csr2 = key2 |> X509.CSR.new("/CN=concurrent-conflict-2") |> X509.CSR.to_pem()
      request_id = Ecto.UUID.generate()

      task1 = Task.async(fn -> ClientAuth.issue_certificate(identity.id, csr1, request_id) end)
      task2 = Task.async(fn -> ClientAuth.issue_certificate(identity.id, csr2, request_id) end)

      res1 = Task.await(task1, 5_000)
      res2 = Task.await(task2, 5_000)

      # One must succeed, and the other must return idempotency_conflict (no crash or unhandled constraint violation)
      results = [res1, res2]
      assert Enum.count(results, fn r -> match?({:ok, _}, r) end) == 1
      assert Enum.count(results, fn r -> match?({:error, :idempotency_conflict}, r) end) == 1
    end
  end

  describe "Authority Initialization Validation" do
    test "validates key_algorithm parameter" do
      assert {:error, {:invalid_key_algorithm, _}} =
               ClientAuth.initialize_authority(%{"key_algorithm" => "rsa_2048"})

      assert {:error, {:invalid_key_algorithm, _}} =
               ClientAuth.initialize_authority(%{"key_algorithm" => "unsupported"})
    end

    test "validates ca_validity_days parameter" do
      # Reject < 30 days
      assert {:error, {:invalid_ca_validity_days, _}} =
               ClientAuth.initialize_authority(%{"ca_validity_days" => 10})

      # Reject > 3650 days
      assert {:error, {:invalid_ca_validity_days, _}} =
               ClientAuth.initialize_authority(%{"ca_validity_days" => 5000})

      # Reject non-integer
      assert {:error, {:invalid_ca_validity_days, _}} =
               ClientAuth.initialize_authority(%{"ca_validity_days" => "infinite"})

      # Reject CA validity <= max_ttl_seconds
      assert {:error, {:ca_validity_too_short, _}} =
               ClientAuth.initialize_authority(%{
                 "ca_validity_days" => 30,
                 "default_ttl_seconds" => 86_400,
                 "max_ttl_seconds" => 40 * 86_400
               })
    end
  end
end
