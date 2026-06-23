defmodule SecretHub.Core.PKI.LifecycleTest do
  use SecretHub.Core.DataCase, async: true

  alias SecretHub.Core.PKI.{CA, Events, Issuer}
  alias SecretHub.Shared.Schemas.Certificate

  test "covers CA, CSR, certificate database, service certificate, and CRL lifecycle" do
    root_cn = unique_cn("Lifecycle Root CA")
    intermediate_cn = unique_cn("Lifecycle Intermediate CA")
    csr_intermediate_cn = unique_cn("Lifecycle CSR Intermediate CA")
    service_cn = unique_cn("service.lifecycle.internal")
    csr_service_cn = unique_cn("csr-service.lifecycle.internal")

    {:ok, root} =
      CA.generate_root_ca(root_cn, "SecretHub Lifecycle Test",
        key_size: 2048,
        validity_days: 3650
      )

    assert_ca_record(root.cert_record, :root_ca, nil, root_cn)
    root_cert = X509.Certificate.from_pem!(root.certificate)
    assert X509.Certificate.subject(root_cert, "CN") == [root_cn]
    assert X509.Certificate.issuer(root_cert, "CN") == [root_cn]

    {:ok, intermediate} =
      CA.generate_intermediate_ca(
        intermediate_cn,
        "SecretHub Lifecycle Test",
        root.cert_record.id,
        key_size: 2048,
        validity_days: 1825
      )

    assert_ca_record(
      intermediate.cert_record,
      :intermediate_ca,
      root.cert_record.id,
      intermediate_cn
    )

    intermediate_cert = X509.Certificate.from_pem!(intermediate.certificate)
    assert X509.Certificate.subject(intermediate_cert, "CN") == [intermediate_cn]
    assert X509.Certificate.issuer(intermediate_cert, "CN") == [root_cn]
    assert :public_key.pkix_is_issuer(intermediate_cert, root_cert)

    {csr_intermediate_key, csr_intermediate_pem} = new_csr(csr_intermediate_cn)

    {:ok, csr_intermediate} =
      CA.sign_csr(csr_intermediate_pem, root.cert_record.id, :intermediate_ca, validity_days: 365)

    assert_ca_record(
      csr_intermediate.cert_record,
      :intermediate_ca,
      root.cert_record.id,
      csr_intermediate_cn
    )

    csr_intermediate_cert = X509.Certificate.from_pem!(csr_intermediate.certificate)
    parsed_csr_intermediate = X509.CSR.from_pem!(csr_intermediate_pem)

    assert X509.Certificate.subject(csr_intermediate_cert, "CN") == [csr_intermediate_cn]
    assert X509.Certificate.issuer(csr_intermediate_cert, "CN") == [root_cn]
    assert :public_key.pkix_is_issuer(csr_intermediate_cert, root_cert)

    assert X509.Certificate.public_key(csr_intermediate_cert) ==
             X509.CSR.public_key(parsed_csr_intermediate)

    assert X509.Certificate.public_key(csr_intermediate_cert) ==
             X509.PublicKey.derive(csr_intermediate_key)

    {:ok, server_cert} =
      Issuer.issue_server_certificate(service_cn, [service_cn, "127.0.0.1"])

    assert server_cert.certificate_pem =~ "-----BEGIN CERTIFICATE-----"
    assert server_cert.private_key_pem =~ "-----BEGIN RSA PRIVATE KEY-----"
    assert server_cert.ca_certificate_pem =~ "-----BEGIN CERTIFICATE-----"

    server_signing_ca = Repo.get_by!(Certificate, fingerprint: server_cert.ca_fingerprint)
    parsed_server_cert = X509.Certificate.from_pem!(server_cert.certificate_pem)
    parsed_server_ca = X509.Certificate.from_pem!(server_cert.ca_certificate_pem)

    assert server_signing_ca.cert_type in [:root_ca, :intermediate_ca]
    assert X509.Certificate.subject(parsed_server_cert, "CN") == [service_cn]
    assert X509.Certificate.issuer(parsed_server_cert, "CN") == [server_signing_ca.common_name]
    assert :public_key.pkix_is_issuer(parsed_server_cert, parsed_server_ca)

    {_csr_service_key, csr_service_pem} = new_csr(csr_service_cn)

    {:ok, csr_service} =
      CA.sign_csr(csr_service_pem, intermediate.cert_record.id, :app_client, validity_days: 90)

    assert %Certificate{} = service_record = Repo.get(Certificate, csr_service.cert_record.id)
    assert service_record.cert_type == :app_client
    assert service_record.common_name == csr_service_cn
    assert service_record.issuer_id == intermediate.cert_record.id
    assert service_record.private_key_encrypted == nil
    assert service_record.revoked == false

    parsed_csr_service_cert = X509.Certificate.from_pem!(csr_service.certificate)
    assert X509.Certificate.subject(parsed_csr_service_cert, "CN") == [csr_service_cn]
    assert X509.Certificate.issuer(parsed_csr_service_cert, "CN") == [intermediate_cn]
    assert :public_key.pkix_is_issuer(parsed_csr_service_cert, intermediate_cert)

    assert {:ok, fetched_service_record} = CA.get_certificate(service_record.id)
    assert fetched_service_record.id == service_record.id

    certificate_ids = CA.list_certificates() |> MapSet.new(& &1.id)

    assert MapSet.subset?(
             MapSet.new([
               root.cert_record.id,
               intermediate.cert_record.id,
               csr_intermediate.cert_record.id,
               service_record.id
             ]),
             certificate_ids
           )

    assert {:ok, ca_chain_pem} = CA.get_ca_chain()
    ca_chain_entries = :public_key.pem_decode(ca_chain_pem)

    assert Enum.count(ca_chain_entries, &match?({:Certificate, _der, :not_encrypted}, &1)) >= 3
    assert ca_chain_pem =~ root.certificate
    assert ca_chain_pem =~ intermediate.certificate
    assert ca_chain_pem =~ csr_intermediate.certificate

    assert {:ok, revoked_service_record} =
             CA.revoke_certificate(service_record.id, "keyCompromise")

    assert revoked_service_record.revoked
    assert revoked_service_record.revocation_reason == "keyCompromise"

    assert {:ok, [%{serial: serial, reason: :keyCompromise, revocation_date: revoked_at}]} =
             Events.get_revocations(intermediate.cert_record.id)

    assert serial == service_record.serial_number

    crl_entry =
      X509.CRL.Entry.new(serial_to_integer(serial), revoked_at, [
        X509.CRL.Extension.reason_code(:keyCompromise)
      ])

    intermediate_key = X509.PrivateKey.from_pem!(intermediate.private_key)

    crl =
      X509.CRL.new([crl_entry], intermediate_cert, intermediate_key,
        extensions: [crl_number: X509.CRL.Extension.crl_number(1)]
      )

    assert X509.CRL.valid?(crl, intermediate_cert)
    assert [stored_crl_entry] = X509.CRL.list(crl)

    assert X509.CRL.Entry.serial(stored_crl_entry) ==
             serial_to_integer(service_record.serial_number)

    crl_pem = X509.CRL.to_pem(crl)
    assert crl_pem =~ "-----BEGIN X509 CRL-----"
    assert {:ok, parsed_crl} = X509.CRL.from_pem(crl_pem)
    assert X509.CRL.valid?(parsed_crl, intermediate_cert)
  end

  defp assert_ca_record(%Certificate{} = record, cert_type, issuer_id, common_name) do
    assert record.id
    assert record.cert_type == cert_type
    assert record.issuer_id == issuer_id
    assert record.common_name == common_name
    assert record.certificate_pem =~ "-----BEGIN CERTIFICATE-----"
    assert record.key_usage == ["keyCertSign", "cRLSign"]
    assert record.revoked == false

    assert %Certificate{} = persisted = Repo.get(Certificate, record.id)
    assert persisted.serial_number == record.serial_number
    assert persisted.fingerprint == record.fingerprint
  end

  defp new_csr(common_name) do
    private_key = X509.PrivateKey.new_rsa(2048)
    csr = X509.CSR.new(private_key, "/O=SecretHub Lifecycle Test/CN=#{common_name}")

    {private_key, X509.CSR.to_pem(csr)}
  end

  defp serial_to_integer(serial) when is_binary(serial) do
    serial
    |> String.replace(":", "")
    |> String.to_integer(16)
  end

  defp unique_cn(prefix) do
    "#{prefix} #{System.unique_integer([:positive])}"
  end
end
