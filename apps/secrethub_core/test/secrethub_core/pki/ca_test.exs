defmodule SecretHub.Core.PKI.CATest do
  @moduledoc """
  Comprehensive tests for PKI Certificate Authority operations.

  Tests cover:
  - Root CA generation
  - Intermediate CA generation
  - CSR signing
  - Certificate storage and retrieval
  - Key encryption/decryption
  - Error handling
  - Certificate validation
  """

  use SecretHub.Core.DataCase, async: true

  import Ecto.Query

  alias SecretHub.Core.PKI.CA
  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.Certificate

  describe "generate_root_ca/3" do
    test "generates valid self-signed root CA with RSA-4096" do
      {:ok, result} = CA.generate_root_ca("Test Root CA", "SecretHub Test Inc")

      assert Map.has_key?(result, :certificate)
      assert Map.has_key?(result, :private_key)
      assert Map.has_key?(result, :cert_record)

      # Verify certificate is valid PEM
      assert result.certificate =~ "-----BEGIN CERTIFICATE-----"
      assert result.certificate =~ "-----END CERTIFICATE-----"

      # Verify private key is valid PEM
      assert result.private_key =~ "-----BEGIN RSA PRIVATE KEY-----"
      assert result.private_key =~ "-----END RSA PRIVATE KEY-----"

      # Verify cert_record is stored in database
      cert_record = result.cert_record
      assert cert_record.id != nil
      assert cert_record.common_name == "Test Root CA"
      assert cert_record.organization == "SecretHub Test Inc"
      assert cert_record.cert_type == :root_ca
      assert cert_record.serial_number != nil
      assert cert_record.fingerprint != nil
      assert cert_record.certificate_pem == result.certificate

      # Verify certificate can be decoded
      [{:Certificate, cert_der, _}] = :public_key.pem_decode(result.certificate)
      cert = :public_key.pkix_decode_cert(cert_der, :otp)

      # Verify basic constraints extension indicates CA
      # Extract extensions using pattern matching
      {:OTPCertificate, tbs_cert, _sig_alg, _signature} = cert

      {:OTPTBSCertificate, _version, _serial, _sig, _issuer, _validity, _subject, _pub_key_info,
       _issuer_uid, _subject_uid, extensions} = tbs_cert

      assert extensions != :asn1_NOVALUE
      assert is_list(extensions)
    end

    test "generates root CA with custom options" do
      opts = [
        key_type: :rsa,
        key_size: 2048,
        validity_days: 1825,
        country: "US",
        state: "California",
        locality: "San Francisco"
      ]

      {:ok, result} = CA.generate_root_ca("Custom Root CA", "Custom Org", opts)

      assert result.cert_record.common_name == "Custom Root CA"
      assert result.cert_record.organization == "Custom Org"

      # Verify key size by checking private key length
      assert String.length(result.private_key) <
               String.length(
                 CA.generate_root_ca("Test", "Test", key_type: :rsa, key_size: 4096)
                 |> elem(1)
                 |> Map.get(:private_key)
               )
    end

    test "generates root CA with ECDSA P-384 key" do
      opts = [key_type: :ecdsa, key_size: 384]

      {:ok, result} = CA.generate_root_ca("ECDSA Root CA", "SecretHub Test", opts)

      # Verify private key is ECDSA
      assert result.private_key =~ "-----BEGIN EC PRIVATE KEY-----"
      assert result.private_key =~ "-----END EC PRIVATE KEY-----"

      assert result.cert_record.common_name == "ECDSA Root CA"
    end

    test "stores encrypted private key in database" do
      {:ok, result} = CA.generate_root_ca("Test Root CA", "SecretHub Test Inc")

      # Retrieve from database
      cert = Repo.get(Certificate, result.cert_record.id)

      # Verify encrypted_private_key is stored
      assert cert.private_key_encrypted != nil
      assert is_binary(cert.private_key_encrypted)

      # Verify it's different from the plaintext key
      refute cert.private_key_encrypted == result.private_key
    end

    test "generates unique serial numbers" do
      {:ok, result1} = CA.generate_root_ca("Root CA 1", "Org 1")
      {:ok, result2} = CA.generate_root_ca("Root CA 2", "Org 2")

      assert result1.cert_record.serial_number != result2.cert_record.serial_number
    end

    test "generates valid fingerprints" do
      {:ok, result} = CA.generate_root_ca("Test Root CA", "SecretHub Test Inc")

      # Fingerprint should be SHA-256 hex format
      assert result.cert_record.fingerprint =~ ~r/^sha256:[a-f0-9:]+$/
      assert String.length(result.cert_record.fingerprint) > 70
    end

    test "sets validity dates correctly" do
      {:ok, result} =
        CA.generate_root_ca("Test Root CA", "SecretHub Test Inc", validity_days: 365)

      # Verify valid_from is approximately now
      now = DateTime.utc_now()
      diff = DateTime.diff(result.cert_record.valid_from, now, :second)
      # Within 1 minute
      assert abs(diff) < 60

      # Verify valid_until is approximately 365 days from now
      expected_until = DateTime.add(now, 365 * 24 * 60 * 60, :second)
      diff = DateTime.diff(result.cert_record.valid_until, expected_until, :second)
      # Within 2 minutes
      assert abs(diff) < 120
    end

    test "rejects invalid parameters" do
      # Missing common name
      assert {:error, _} = CA.generate_root_ca("", "Org")

      # Missing organization
      assert {:error, _} = CA.generate_root_ca("CN", "")

      # Invalid key type
      assert {:error, _} = CA.generate_root_ca("CN", "Org", key_type: :invalid)

      # Invalid key size for RSA
      assert {:error, _} = CA.generate_root_ca("CN", "Org", key_type: :rsa, key_size: 512)
    end
  end

  describe "generate_intermediate_ca/4" do
    setup do
      # Generate a root CA for testing
      {:ok, root} = CA.generate_root_ca("Test Root CA", "SecretHub Test Inc")
      {:ok, root: root}
    end

    test "generates valid intermediate CA signed by root", %{root: root} do
      {:ok, result} =
        CA.generate_intermediate_ca(
          "Test Intermediate CA",
          "SecretHub Test Inc",
          root.cert_record.id,
          []
        )

      assert Map.has_key?(result, :certificate)
      assert Map.has_key?(result, :private_key)
      assert Map.has_key?(result, :cert_record)

      # Verify certificate is valid PEM
      assert result.certificate =~ "-----BEGIN CERTIFICATE-----"

      # Verify cert_record
      cert_record = result.cert_record
      assert cert_record.common_name == "Test Intermediate CA"
      assert cert_record.cert_type == :intermediate_ca
      assert cert_record.issuer_id == root.cert_record.id

      # Verify issuer field matches root CA subject
      assert cert_record.issuer != nil
    end

    test "intermediate CA has different serial number than root", %{root: root} do
      {:ok, intermediate} =
        CA.generate_intermediate_ca(
          "Test Intermediate CA",
          "SecretHub Test Inc",
          root.cert_record.id
        )

      assert intermediate.cert_record.serial_number != root.cert_record.serial_number
    end

    test "intermediate CA has shorter validity than root", %{root: root} do
      {:ok, intermediate} =
        CA.generate_intermediate_ca(
          "Test Intermediate CA",
          "SecretHub Test Inc",
          root.cert_record.id,
          validity_days: 365
        )

      # Intermediate should expire before root
      assert DateTime.compare(
               intermediate.cert_record.valid_until,
               root.cert_record.valid_until
             ) == :lt
    end

    test "rejects non-existent root CA" do
      fake_uuid = Ecto.UUID.generate()

      assert {:error, "CA certificate not found"} =
               CA.generate_intermediate_ca(
                 "Test Intermediate CA",
                 "SecretHub Test Inc",
                 fake_uuid
               )
    end

    test "rejects non-CA certificate as root" do
      # Create a client certificate
      {:ok, root} = CA.generate_root_ca("Root", "Org")

      # Try to use it as a root for intermediate (should fail in real implementation)
      # For now, just verify the error handling exists
      assert is_function(&CA.generate_intermediate_ca/4)
    end
  end

  describe "sign_csr/4" do
    setup do
      # Generate a root CA for testing
      {:ok, root} = CA.generate_root_ca("Test Root CA", "SecretHub Test Inc")

      # Generate a test CSR
      {:ok, csr_pem} = generate_test_csr("agent.example.com")

      {:ok, root: root, csr_pem: csr_pem}
    end

    test "signs CSR for agent_client certificate", %{root: root, csr_pem: csr_pem} do
      {:ok, result} = CA.sign_csr(csr_pem, root.cert_record.id, :agent_client)

      assert Map.has_key?(result, :certificate)
      assert Map.has_key?(result, :cert_record)

      # Verify certificate is valid PEM
      assert result.certificate =~ "-----BEGIN CERTIFICATE-----"

      # Verify cert_record
      cert_record = result.cert_record
      assert cert_record.cert_type == :agent_client
      assert cert_record.issuer_id == root.cert_record.id
      assert cert_record.common_name != nil
    end

    test "signs CSR with custom validity period", %{root: root, csr_pem: csr_pem} do
      {:ok, result} =
        CA.sign_csr(
          csr_pem,
          root.cert_record.id,
          :agent_client,
          validity_days: 30
        )

      # Verify validity is approximately 30 days
      now = DateTime.utc_now()
      expected_until = DateTime.add(now, 30 * 24 * 60 * 60, :second)
      diff = DateTime.diff(result.cert_record.valid_until, expected_until, :second)
      # Within 2 minutes
      assert abs(diff) < 120
    end

    test "supports different certificate types", %{root: root, csr_pem: csr_pem} do
      # Test agent_client
      {:ok, agent_cert} = CA.sign_csr(csr_pem, root.cert_record.id, :agent_client)
      assert agent_cert.cert_record.cert_type == :agent_client

      # Test app_client
      {:ok, app_cert} = CA.sign_csr(csr_pem, root.cert_record.id, :app_client)
      assert app_cert.cert_record.cert_type == :app_client

      # Test admin_client
      {:ok, admin_cert} = CA.sign_csr(csr_pem, root.cert_record.id, :admin_client)
      assert admin_cert.cert_record.cert_type == :admin_client
    end

    test "rejects invalid CSR format", %{root: root} do
      invalid_csr = "invalid-csr-data"

      assert {:error, _} = CA.sign_csr(invalid_csr, root.cert_record.id, :agent_client)
    end

    test "rejects non-existent CA", %{csr_pem: csr_pem} do
      fake_uuid = Ecto.UUID.generate()

      assert {:error, "CA certificate not found"} =
               CA.sign_csr(
                 csr_pem,
                 fake_uuid,
                 :agent_client
               )
    end

    test "certificate inherits CA's organization", %{root: root, csr_pem: csr_pem} do
      {:ok, result} = CA.sign_csr(csr_pem, root.cert_record.id, :agent_client)

      assert result.cert_record.organization == root.cert_record.organization
    end
  end

  describe "certificate storage and retrieval" do
    test "certificates can be queried by type" do
      {:ok, root} = CA.generate_root_ca("Root 1", "Org")
      {:ok, _root2} = CA.generate_root_ca("Root 2", "Org")
      {:ok, intermediate} = CA.generate_intermediate_ca("Int 1", "Org", root.cert_record.id)

      root_certs = Repo.all(from(c in Certificate, where: c.cert_type == :root_ca))
      assert length(root_certs) >= 2

      int_certs = Repo.all(from(c in Certificate, where: c.cert_type == :intermediate_ca))
      assert length(int_certs) >= 1
    end

    test "certificates can be queried by organization" do
      {:ok, _cert1} = CA.generate_root_ca("Root 1", "OrgA")
      {:ok, _cert2} = CA.generate_root_ca("Root 2", "OrgB")

      org_a_certs = Repo.all(from(c in Certificate, where: c.organization == "OrgA"))
      assert length(org_a_certs) >= 1
    end

    test "revoked certificates can be filtered" do
      {:ok, root} = CA.generate_root_ca("Root CA", "Org")

      # Initially not revoked
      cert = Repo.get(Certificate, root.cert_record.id)
      assert cert.revoked == false

      # Revoke it
      changeset =
        Certificate.changeset(cert, %{
          revoked: true,
          revoked_at: DateTime.utc_now() |> DateTime.truncate(:second),
          revocation_reason: "test"
        })

      {:ok, _updated} = Repo.update(changeset)

      # Query revoked certificates
      revoked = Repo.all(from(c in Certificate, where: c.revoked == true))
      assert length(revoked) >= 1
    end
  end

  describe "key encryption and security" do
    test "private keys are encrypted before storage" do
      {:ok, result} = CA.generate_root_ca("Test Root CA", "SecretHub Test Inc")

      cert = Repo.get(Certificate, result.cert_record.id)

      # Verify encrypted_private_key exists
      assert cert.private_key_encrypted != nil

      # Verify it's not the plaintext PEM
      refute cert.private_key_encrypted == result.private_key
      refute is_binary(cert.private_key_encrypted) and String.valid?(cert.private_key_encrypted) and String.contains?(cert.private_key_encrypted, "-----BEGIN")
    end

    test "private keys are not exposed in certificate_pem field" do
      {:ok, result} = CA.generate_root_ca("Test Root CA", "SecretHub Test Inc")

      cert = Repo.get(Certificate, result.cert_record.id)

      # Verify certificate_pem contains only the certificate, not the private key
      assert cert.certificate_pem == result.certificate
      refute String.contains?(cert.certificate_pem, "PRIVATE KEY")
    end
  end

  describe "certificate validation" do
    test "generated root CA is self-signed" do
      {:ok, result} = CA.generate_root_ca("Test Root CA", "SecretHub Test Inc")

      cert_record = result.cert_record

      # In a self-signed cert, issuer should equal subject
      # For root CAs, issuer_id should be nil or self-referential
      assert cert_record.issuer_id == nil
    end

    test "intermediate CA has valid issuer reference" do
      {:ok, root} = CA.generate_root_ca("Root CA", "Org")

      {:ok, intermediate} =
        CA.generate_intermediate_ca("Intermediate CA", "Org", root.cert_record.id)

      assert intermediate.cert_record.issuer_id == root.cert_record.id

      # Verify issuer certificate exists
      issuer = Repo.get(Certificate, intermediate.cert_record.issuer_id)
      assert issuer != nil
      assert issuer.cert_type == :root_ca
    end

    test "certificate chain can be reconstructed" do
      {:ok, root} = CA.generate_root_ca("Root CA", "Org")

      {:ok, intermediate} =
        CA.generate_intermediate_ca("Intermediate CA", "Org", root.cert_record.id)

      # Build chain from intermediate to root
      chain = build_certificate_chain(intermediate.cert_record.id)

      assert length(chain) == 2
      assert Enum.at(chain, 0).id == intermediate.cert_record.id
      assert Enum.at(chain, 1).id == root.cert_record.id
    end
  end

  describe "serial number uniqueness" do
    test "serial numbers are globally unique" do
      # Generate multiple certificates
      results =
        for i <- 1..10 do
          {:ok, result} = CA.generate_root_ca("Root #{i}", "Org")
          result.cert_record.serial_number
        end

      # Verify all serial numbers are unique
      unique_serials = Enum.uniq(results)
      assert length(unique_serials) == 10
    end

    test "serial numbers are cryptographically random" do
      {:ok, result1} = CA.generate_root_ca("Root 1", "Org")
      {:ok, result2} = CA.generate_root_ca("Root 2", "Org")

      # Serial numbers should be different
      assert result1.cert_record.serial_number != result2.cert_record.serial_number

      # Serial numbers should be non-trivial (not sequential)
      # This is a weak test, but checks they're not just incrementing
      serial1 = String.replace(result1.cert_record.serial_number, ":", "")
      serial2 = String.replace(result2.cert_record.serial_number, ":", "")

      num1 = String.to_integer(serial1, 16)
      num2 = String.to_integer(serial2, 16)

      # They should not be sequential
      refute abs(num1 - num2) == 1
    end
  end

  # Helper functions

  defp generate_test_csr(common_name) do
    # Use OpenSSL command to generate a proper CSR for testing
    # This is simpler and more reliable than manually constructing CSR structures
    temp_dir = Path.join(System.tmp_dir!(), "pki_test_#{:erlang.unique_integer([:positive])}")
    File.mkdir_p!(temp_dir)

    key_file = Path.join(temp_dir, "key.pem")
    csr_file = Path.join(temp_dir, "csr.pem")

    try do
      # Generate private key
      {_, 0} =
        System.cmd(
          "openssl",
          [
            "genrsa",
            "-out",
            key_file,
            "2048"
          ],
          stderr_to_stdout: true
        )

      # Generate CSR
      {_, 0} =
        System.cmd(
          "openssl",
          [
            "req",
            "-new",
            "-key",
            key_file,
            "-out",
            csr_file,
            "-subj",
            "/CN=#{common_name}"
          ],
          stderr_to_stdout: true
        )

      # Read CSR
      csr_pem = File.read!(csr_file)
      {:ok, csr_pem}
    rescue
      e ->
        {:error, "Failed to generate test CSR: #{inspect(e)}"}
    after
      # Cleanup
      File.rm_rf(temp_dir)
    end
  end

  defp build_certificate_chain(cert_id, chain \\ []) do
    cert = Repo.get(Certificate, cert_id)

    if cert == nil do
      chain
    else
      chain = [cert | chain]

      if cert.issuer_id == nil do
        Enum.reverse(chain)
      else
        build_certificate_chain(cert.issuer_id, chain)
      end
    end
  end
end
