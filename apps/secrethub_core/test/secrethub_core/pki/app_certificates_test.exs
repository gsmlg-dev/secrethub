defmodule SecretHub.Core.PKI.AppCertificatesTest do
  use SecretHub.Core.DataCase, async: false

  alias SecretHub.Core.{Apps, Repo}
  alias SecretHub.Core.PKI.{AppCertificates, CA, CertificateIdentity}
  alias X509.Certificate.Extension

  alias SecretHub.Shared.Schemas.{
    Agent,
    AppBootstrapToken,
    AppCertificate,
    AppCertificateRenewal,
    AuditLog,
    Certificate
  }

  @post_rollback_audit_failure_log "Application certificate post-rollback audit could not be recorded"

  setup do
    unique = System.unique_integer([:positive])

    {:ok, ca} =
      CA.generate_root_ca(
        "App Issuance Root #{unique}",
        "SecretHub Test",
        key_size: 2048
      )

    {:ok, agent} =
      %Agent{}
      |> Agent.changeset(%{
        agent_id: "app-issuance-agent-#{unique}",
        name: "App Issuance Agent #{unique}",
        status: :active
      })
      |> Repo.insert()

    {:ok, %{app: app, token: token}} =
      Apps.register_app(%{
        name: "app-issuance-#{unique}",
        agent_id: agent.id
      })

    %{agent: agent, app: app, token: token, ca: ca.cert_record}
  end

  test "builds the exact domain-separated application certificate renewal transcript" do
    app_id = "00000000-0000-4000-8000-000000000001"
    request_id = "00000000-0000-4000-8000-000000000002"
    current_fingerprint = String.duplicate("ab", 32)

    csr_pem =
      "-----BEGIN CERTIFICATE REQUEST-----\nAA==\n-----END CERTIFICATE REQUEST-----\n"

    csr_sha256 = :crypto.hash(:sha256, csr_pem)

    canonical_json =
      ~s({"app_id":"#{app_id}","csr_sha256":"#{Base.encode16(csr_sha256, case: :lower)}","current_fingerprint":"#{current_fingerprint}","request_id":"#{request_id}"})

    normalized_payload_sha256 = :crypto.hash(:sha256, canonical_json)
    fingerprint_bytes = Base.decode16!(current_fingerprint, case: :lower)

    expected =
      for value <- [
            "secrethub-app-cert-renewal-v1",
            app_id,
            fingerprint_bytes,
            csr_sha256,
            request_id,
            normalized_payload_sha256
          ],
          into: <<>> do
        <<byte_size(value)::unsigned-big-32, value::binary>>
      end

    assert {:ok, ^expected} =
             AppCertificates.renewal_signing_payload(
               app_id,
               current_fingerprint,
               csr_pem,
               request_id
             )
  end

  test "renews a canonical application certificate with an RSA-PSS possession proof", %{
    app: app,
    token: token
  } do
    current_key = X509.PrivateKey.new_rsa(2048)
    current_csr = current_key |> X509.CSR.new("/CN=current") |> X509.CSR.to_pem()

    assert {:ok, current} =
             AppCertificates.issue_from_bootstrap(token, current_csr, Ecto.UUID.generate())

    replacement_key = X509.PrivateKey.new_rsa(2048)
    replacement_csr = replacement_key |> X509.CSR.new("/CN=replacement") |> X509.CSR.to_pem()

    request =
      renewal_request(
        app.id,
        current.cert_record.canonical_fingerprint,
        replacement_csr,
        current_key,
        "rsa-pss-sha256"
      )

    assert {:ok,
            %{
              certificate: replacement_pem,
              cert_record: %Certificate{} = replacement,
              app_certificate: %AppCertificate{} = replacement_association,
              replayed: false
            }} = AppCertificates.renew(request)

    assert X509.Certificate.public_key(X509.Certificate.from_pem!(replacement_pem)) ==
             X509.PublicKey.derive(replacement_key)

    assert %AppCertificate{
             revoked_at: %DateTime{},
             revocation_reason: "superseded"
           } = Repo.get!(AppCertificate, current.app_certificate.id)

    assert %Certificate{revoked: true, revocation_reason: "superseded"} =
             Repo.get!(Certificate, current.cert_record.id)

    assert replacement_association.certificate_id == replacement.id
    refute replacement.revoked

    assert %AppCertificateRenewal{
             app_id: app_id,
             current_certificate_id: current_certificate_id,
             issued_certificate_id: issued_certificate_id,
             request_id: request_id,
             original_fingerprint: original_fingerprint,
             proof_algorithm: "rsa-pss-sha256"
           } = Repo.get_by!(AppCertificateRenewal, app_id: app.id, request_id: request.request_id)

    assert app_id == app.id
    assert current_certificate_id == current.cert_record.id
    assert issued_certificate_id == replacement.id
    assert request_id == request.request_id
    assert original_fingerprint == current.cert_record.canonical_fingerprint
  end

  test "renews a canonical application certificate with an ECDSA possession proof", %{
    app: app,
    token: token
  } do
    current_key = X509.PrivateKey.new_ec(:secp256r1)
    current_csr = current_key |> X509.CSR.new("/CN=current-ec") |> X509.CSR.to_pem()

    assert {:ok, current} =
             AppCertificates.issue_from_bootstrap(token, current_csr, Ecto.UUID.generate())

    replacement_key = X509.PrivateKey.new_ec(:secp384r1)

    replacement_csr =
      replacement_key |> X509.CSR.new("/CN=replacement-ec") |> X509.CSR.to_pem()

    request =
      renewal_request(
        app.id,
        current.cert_record.canonical_fingerprint,
        replacement_csr,
        current_key,
        "ecdsa-sha256"
      )

    assert {:ok, %{certificate: replacement_pem, replayed: false}} =
             AppCertificates.renew(request)

    assert X509.Certificate.public_key(X509.Certificate.from_pem!(replacement_pem)) ==
             X509.PublicKey.derive(replacement_key)
  end

  test "rejects a renewal proof signed by a different private key", %{
    app: app,
    token: token
  } do
    current_key = X509.PrivateKey.new_rsa(2048)
    current_csr = current_key |> X509.CSR.new("/CN=current") |> X509.CSR.to_pem()

    assert {:ok, current} =
             AppCertificates.issue_from_bootstrap(token, current_csr, Ecto.UUID.generate())

    replacement_csr =
      X509.PrivateKey.new_rsa(2048)
      |> X509.CSR.new("/CN=replacement")
      |> X509.CSR.to_pem()

    request =
      renewal_request(
        app.id,
        current.cert_record.canonical_fingerprint,
        replacement_csr,
        X509.PrivateKey.new_rsa(2048),
        "rsa-pss-sha256"
      )

    assert {:error, :invalid_proof} = AppCertificates.renew(request)
    assert Repo.aggregate(AppCertificateRenewal, :count) == 0
    assert Repo.aggregate(AppCertificate, :count) == 1

    assert %AppCertificate{revoked_at: nil, revocation_reason: nil} =
             Repo.get!(AppCertificate, current.app_certificate.id)

    assert %Certificate{revoked: false, revoked_at: nil, revocation_reason: nil} =
             Repo.get!(Certificate, current.cert_record.id)

    assert %AuditLog{
             event_type: "auth.app_certificate_renewal_denied",
             access_granted: false,
             denial_reason: "invalid_proof",
             correlation_id: request_id,
             event_data: %{
               "app_certificate_renewal" => %{
                 "request_id" => request_id,
                 "result_code" => "invalid_proof"
               }
             }
           } =
             denied =
             Repo.one!(
               from(a in AuditLog,
                 where: a.event_type == "auth.app_certificate_renewal_denied"
               )
             )

    assert request_id == request.request_id
    refute inspect(denied) =~ replacement_csr
    refute inspect(denied) =~ Base.encode64(request.proof)
  end

  test "replays the exact stored renewal after the original certificate is superseded", %{
    app: app,
    token: token
  } do
    current_key = X509.PrivateKey.new_rsa(2048)
    current_csr = current_key |> X509.CSR.new("/CN=current") |> X509.CSR.to_pem()

    assert {:ok, current} =
             AppCertificates.issue_from_bootstrap(token, current_csr, Ecto.UUID.generate())

    replacement_csr =
      X509.PrivateKey.new_rsa(2048)
      |> X509.CSR.new("/CN=replacement")
      |> X509.CSR.to_pem()

    request =
      renewal_request(
        app.id,
        current.cert_record.canonical_fingerprint,
        replacement_csr,
        current_key,
        "rsa-pss-sha256"
      )

    assert {:ok, first} = AppCertificates.renew(request)
    assert Repo.get!(Certificate, current.cert_record.id).revoked

    assert {:ok, replay} = AppCertificates.renew(request)
    assert replay.replayed
    assert replay.certificate == first.certificate
    assert replay.ca_chain == first.ca_chain
    assert replay.cert_record.id == first.cert_record.id
    assert replay.app_certificate.id == first.app_certificate.id
    assert Repo.aggregate(AppCertificateRenewal, :count) == 1
    assert Repo.aggregate(AppCertificate, :count) == 2
  end

  test "audits renewal, supersession, and replay with only sanitized lifecycle evidence", %{
    app: app,
    token: token
  } do
    current_key = X509.PrivateKey.new_rsa(2048)
    current_csr = current_key |> X509.CSR.new("/CN=current-audit") |> X509.CSR.to_pem()

    assert {:ok, current} =
             AppCertificates.issue_from_bootstrap(token, current_csr, Ecto.UUID.generate())

    replacement_csr =
      X509.PrivateKey.new_rsa(2048)
      |> X509.CSR.new("/CN=replacement-audit")
      |> X509.CSR.to_pem()

    request =
      renewal_request(
        app.id,
        current.cert_record.canonical_fingerprint,
        replacement_csr,
        current_key,
        "rsa-pss-sha256"
      )

    assert {:ok, renewed} = AppCertificates.renew(request)
    assert {:ok, %{replayed: true}} = AppCertificates.renew(request)

    assert [revocation] =
             Repo.all(
               from(a in AuditLog,
                 where: a.event_type == "auth.app_certificate_revoked"
               )
             )

    assert revocation.event_data == %{
             "app_certificate_revocation" => %{
               "app_id" => app.id,
               "certificate_id" => current.cert_record.id,
               "reason" => "superseded",
               "result_code" => "revoked"
             }
           }

    assert [allowed, replayed] =
             Repo.all(
               from(a in AuditLog,
                 where: a.event_type == "auth.app_certificate_renewal_allowed",
                 order_by: [asc: a.sequence_number]
               )
             )

    assert allowed.correlation_id == request.request_id
    assert replayed.correlation_id == request.request_id

    assert allowed.event_data == %{
             "app_certificate_renewal" => %{
               "app_id" => app.id,
               "current_certificate_id" => current.cert_record.id,
               "issued_certificate_id" => renewed.cert_record.id,
               "request_id" => request.request_id,
               "result_code" => "renewed"
             }
           }

    assert replayed.event_data ==
             put_in(
               allowed.event_data,
               ["app_certificate_renewal", "result_code"],
               "replayed"
             )

    lifecycle_audits =
      Repo.all(
        from(a in AuditLog,
          where:
            a.event_type in [
              "auth.app_certificate_renewal_allowed",
              "auth.app_certificate_revoked"
            ]
        )
      )

    refute inspect(lifecycle_audits) =~ replacement_csr
    refute inspect(lifecycle_audits) =~ Base.encode64(replacement_csr)
    refute inspect(lifecycle_audits) =~ Base.encode64(request.proof)
  end

  test "returns an idempotency conflict when a replay changes the signed payload", %{
    app: app,
    token: token
  } do
    current_key = X509.PrivateKey.new_rsa(2048)
    current_csr = current_key |> X509.CSR.new("/CN=current") |> X509.CSR.to_pem()

    assert {:ok, current} =
             AppCertificates.issue_from_bootstrap(token, current_csr, Ecto.UUID.generate())

    first_csr =
      X509.PrivateKey.new_rsa(2048) |> X509.CSR.new("/CN=first") |> X509.CSR.to_pem()

    request =
      renewal_request(
        app.id,
        current.cert_record.canonical_fingerprint,
        first_csr,
        current_key,
        "rsa-pss-sha256"
      )

    assert {:ok, first} = AppCertificates.renew(request)

    changed_csr =
      X509.PrivateKey.new_rsa(2048) |> X509.CSR.new("/CN=changed") |> X509.CSR.to_pem()

    changed_request =
      renewal_request(
        app.id,
        current.cert_record.canonical_fingerprint,
        changed_csr,
        current_key,
        "rsa-pss-sha256",
        request.request_id
      )

    assert {:error, :idempotency_conflict} = AppCertificates.renew(changed_request)
    assert Repo.aggregate(AppCertificateRenewal, :count) == 1
    assert Repo.aggregate(AppCertificate, :count) == 2
    assert Repo.get!(Certificate, first.cert_record.id).revoked == false
  end

  test "rejects renewal with an expired current certificate", %{app: app, token: token} do
    current_key = X509.PrivateKey.new_rsa(2048)
    current_csr = current_key |> X509.CSR.new("/CN=current") |> X509.CSR.to_pem()

    assert {:ok, current} =
             AppCertificates.issue_from_bootstrap(token, current_csr, Ecto.UUID.generate())

    expired_at = DateTime.utc_now() |> DateTime.add(-60, :second) |> DateTime.truncate(:second)

    current.cert_record
    |> Ecto.Changeset.change(valid_until: expired_at)
    |> Repo.update!()

    replacement_csr =
      X509.PrivateKey.new_rsa(2048)
      |> X509.CSR.new("/CN=replacement")
      |> X509.CSR.to_pem()

    request =
      renewal_request(
        app.id,
        current.cert_record.canonical_fingerprint,
        replacement_csr,
        current_key,
        "rsa-pss-sha256"
      )

    assert {:error, :invalid_current_certificate} = AppCertificates.renew(request)
    assert Repo.aggregate(AppCertificateRenewal, :count) == 0
    assert Repo.aggregate(AppCertificate, :count) == 1
  end

  test "rejects renewal with a revoked current certificate", %{app: app, token: token} do
    current_key = X509.PrivateKey.new_rsa(2048)
    current_csr = current_key |> X509.CSR.new("/CN=current") |> X509.CSR.to_pem()

    assert {:ok, current} =
             AppCertificates.issue_from_bootstrap(token, current_csr, Ecto.UUID.generate())

    current.cert_record
    |> Certificate.revoke_changeset("compromised")
    |> Repo.update!()

    replacement_csr =
      X509.PrivateKey.new_rsa(2048)
      |> X509.CSR.new("/CN=replacement")
      |> X509.CSR.to_pem()

    request =
      renewal_request(
        app.id,
        current.cert_record.canonical_fingerprint,
        replacement_csr,
        current_key,
        "rsa-pss-sha256"
      )

    assert {:error, :invalid_current_certificate} = AppCertificates.renew(request)
    assert Repo.aggregate(AppCertificateRenewal, :count) == 0
    assert Repo.aggregate(AppCertificate, :count) == 1
  end

  test "revokes the association and underlying certificate for every canonical reason", %{
    app: app,
    token: first_token
  } do
    reasons = ~w(superseded compromised operator_revoked app_suspended)

    Enum.with_index(reasons)
    |> Enum.each(fn {reason, index} ->
      token =
        if index == 0 do
          first_token
        else
          {:ok, token, _record} = Apps.generate_bootstrap_token(app.id)
          token
        end

      csr =
        X509.PrivateKey.new_rsa(2048)
        |> X509.CSR.new("/CN=revoke-#{reason}")
        |> X509.CSR.to_pem()

      assert {:ok, issued} =
               AppCertificates.issue_from_bootstrap(token, csr, Ecto.UUID.generate())

      assert {:ok,
              %AppCertificate{
                revoked_at: %DateTime{},
                revocation_reason: ^reason
              }} = AppCertificates.revoke(app.id, issued.cert_record.id, reason)

      assert %AppCertificate{revoked_at: %DateTime{}, revocation_reason: ^reason} =
               Repo.get!(AppCertificate, issued.app_certificate.id)

      assert %Certificate{
               revoked: true,
               revoked_at: %DateTime{},
               revocation_reason: ^reason
             } = Repo.get!(Certificate, issued.cert_record.id)

      assert {:error, :not_found} =
               AppCertificates.revoke(app.id, issued.cert_record.id, reason)
    end)
  end

  test "Apps delegates single-certificate revocation with the canonical default", %{
    app: app,
    token: token
  } do
    csr =
      X509.PrivateKey.new_rsa(2048)
      |> X509.CSR.new("/CN=apps-revoke")
      |> X509.CSR.to_pem()

    assert {:ok, issued} =
             AppCertificates.issue_from_bootstrap(token, csr, Ecto.UUID.generate())

    assert {:ok, %AppCertificate{revocation_reason: "operator_revoked"}} =
             Apps.revoke_app_certificate(app.id, issued.cert_record.id)

    assert %Certificate{revoked: true, revocation_reason: "operator_revoked"} =
             Repo.get!(Certificate, issued.cert_record.id)
  end

  test "Apps delegates all-certificate revocation atomically and preserves the count", %{
    app: app,
    token: first_token
  } do
    {:ok, second_token, _record} = Apps.generate_bootstrap_token(app.id)

    issued =
      Enum.map([first_token, second_token], fn token ->
        csr =
          X509.PrivateKey.new_rsa(2048)
          |> X509.CSR.new("/CN=apps-revoke-all")
          |> X509.CSR.to_pem()

        {:ok, result} =
          AppCertificates.issue_from_bootstrap(token, csr, Ecto.UUID.generate())

        result
      end)

    assert {:ok, 2} = Apps.revoke_all_app_certificates(app.id)

    Enum.each(issued, fn result ->
      assert %AppCertificate{revocation_reason: "operator_revoked"} =
               Repo.get!(AppCertificate, result.app_certificate.id)

      assert %Certificate{revoked: true, revocation_reason: "operator_revoked"} =
               Repo.get!(Certificate, result.cert_record.id)
    end)

    assert {:ok, 0} = Apps.revoke_all_app_certificates(app.id)
  end

  test "rolls back every renewal mutation and records a sanitized failure", %{
    app: app,
    token: token
  } do
    current_key = X509.PrivateKey.new_rsa(2048)
    current_csr = current_key |> X509.CSR.new("/CN=current-fault") |> X509.CSR.to_pem()

    assert {:ok, current} =
             AppCertificates.issue_from_bootstrap(token, current_csr, Ecto.UUID.generate())

    replacement_csr =
      X509.PrivateKey.new_rsa(2048)
      |> X509.CSR.new("/CN=replacement-fault")
      |> X509.CSR.to_pem()

    request =
      renewal_request(
        app.id,
        current.cert_record.canonical_fingerprint,
        replacement_csr,
        current_key,
        "rsa-pss-sha256"
      )

    Process.put(
      :secrethub_app_certificate_renewal_fault,
      :before_original_revocation
    )

    assert {:error, :renewal_failed} = AppCertificates.renew(request)
    assert Repo.aggregate(AppCertificateRenewal, :count) == 0
    assert Repo.aggregate(AppCertificate, :count) == 1

    assert %AppCertificate{revoked_at: nil, revocation_reason: nil} =
             Repo.get!(AppCertificate, current.app_certificate.id)

    assert %Certificate{revoked: false, revoked_at: nil, revocation_reason: nil} =
             Repo.get!(Certificate, current.cert_record.id)

    assert %AuditLog{
             event_type: "auth.app_certificate_renewal_failed",
             access_granted: false,
             denial_reason: "renewal_failed",
             correlation_id: request_id,
             event_data: %{
               "app_certificate_renewal" => %{
                 "request_id" => request_id,
                 "result_code" => "renewal_failed"
               }
             }
           } =
             failed =
             Repo.one!(
               from(a in AuditLog,
                 where: a.event_type == "auth.app_certificate_renewal_failed"
               )
             )

    assert request_id == request.request_id
    refute inspect(failed) =~ replacement_csr
    refute inspect(failed) =~ Base.encode64(request.proof)
  end

  test "rolls back renewal when its transactional success audit fails", %{
    app: app,
    token: token
  } do
    current_key = X509.PrivateKey.new_rsa(2048)
    current_csr = current_key |> X509.CSR.new("/CN=current-audit-fault") |> X509.CSR.to_pem()

    assert {:ok, current} =
             AppCertificates.issue_from_bootstrap(token, current_csr, Ecto.UUID.generate())

    replacement_csr =
      X509.PrivateKey.new_rsa(2048)
      |> X509.CSR.new("/CN=replacement-audit-fault")
      |> X509.CSR.to_pem()

    request =
      renewal_request(
        app.id,
        current.cert_record.canonical_fingerprint,
        replacement_csr,
        current_key,
        "rsa-pss-sha256"
      )

    Process.put(:secrethub_app_certificate_renewal_fault, :success_audit)

    assert {:error, :renewal_failed} = AppCertificates.renew(request)
    assert Repo.aggregate(AppCertificateRenewal, :count) == 0
    assert Repo.aggregate(AppCertificate, :count) == 1

    assert %Certificate{revoked: false, revoked_at: nil, revocation_reason: nil} =
             Repo.get!(Certificate, current.cert_record.id)

    assert Repo.aggregate(
             from(a in AuditLog,
               where:
                 a.event_type in [
                   "auth.app_certificate_renewal_allowed",
                   "auth.app_certificate_revoked"
                 ]
             ),
             :count
           ) == 0

    assert Repo.aggregate(
             from(a in AuditLog,
               where: a.event_type == "auth.app_certificate_renewal_failed"
             ),
             :count
           ) == 1
  end

  test "rolls back both revocation records when the transactional audit fails", %{
    app: app,
    token: token
  } do
    csr =
      X509.PrivateKey.new_rsa(2048)
      |> X509.CSR.new("/CN=revocation-audit-fault")
      |> X509.CSR.to_pem()

    assert {:ok, issued} =
             AppCertificates.issue_from_bootstrap(token, csr, Ecto.UUID.generate())

    Process.put(:secrethub_app_certificate_revocation_fault, :success_audit)

    assert {:error, :revocation_failed} =
             AppCertificates.revoke(app.id, issued.cert_record.id, "compromised")

    assert %AppCertificate{revoked_at: nil, revocation_reason: nil} =
             Repo.get!(AppCertificate, issued.app_certificate.id)

    assert %Certificate{revoked: false, revoked_at: nil, revocation_reason: nil} =
             Repo.get!(Certificate, issued.cert_record.id)

    assert Repo.aggregate(
             from(a in AuditLog,
               where: a.event_type == "auth.app_certificate_revoked"
             ),
             :count
           ) == 0
  end

  test "keeps a renewal denial stable when post-rollback audit raises", %{app: app} do
    private_csr = "private-renewal-csr-material"
    private_proof = "private-renewal-proof-material"
    private_fingerprint = "private-renewal-fingerprint"

    Process.put(:secrethub_app_certificate_renewal_audit_fault, :raise)

    log =
      ExUnit.CaptureLog.capture_log(fn ->
        assert {:error, :invalid_fingerprint} =
                 AppCertificates.renew(%{
                   app_id: app.id,
                   current_fingerprint: private_fingerprint,
                   csr: private_csr,
                   request_id: Ecto.UUID.generate(),
                   signature_algorithm: "rsa-pss-sha256",
                   proof: private_proof
                 })
      end)

    assert log =~ @post_rollback_audit_failure_log
    refute log =~ private_csr
    refute log =~ private_proof
    refute log =~ private_fingerprint
  end

  test "issues and persists a canonical RSA-2048 application certificate", %{
    agent: agent,
    app: app,
    token: token
  } do
    request_id = Ecto.UUID.generate()
    private_key = X509.PrivateKey.new_rsa(2048)
    csr_pem = private_key |> X509.CSR.new("/O=Hostile/CN=hostile") |> X509.CSR.to_pem()

    assert {:ok,
            %{
              certificate: certificate_pem,
              ca_chain: [ca_pem | _],
              cert_record: %Certificate{} = cert_record,
              app_certificate: %AppCertificate{} = app_certificate,
              replayed: false
            }} = AppCertificates.issue_from_bootstrap(token, csr_pem, request_id)

    certificate = X509.Certificate.from_pem!(certificate_pem)

    assert X509.Certificate.subject(certificate, "CN") == [app.id]
    assert X509.Certificate.subject(certificate, "O") == ["SecretHub Applications"]

    assert {:ok, %{app_id: app_id, canonical_fingerprint: canonical_fingerprint}} =
             CertificateIdentity.validate_app_certificate(certificate_pem, app.id)

    assert app_id == app.id
    assert ca_pem =~ "-----BEGIN CERTIFICATE-----"
    assert cert_record.canonical_fingerprint == canonical_fingerprint
    assert cert_record.common_name == app.id
    assert cert_record.organization == "SecretHub Applications"
    assert cert_record.cert_type == :app_client
    assert cert_record.key_usage == ["digitalSignature"]
    assert cert_record.entity_id == app.id
    assert cert_record.entity_type == "app"
    assert cert_record.private_key_encrypted == nil
    assert app_certificate.app_id == app.id
    assert app_certificate.certificate_id == cert_record.id

    assert %AppBootstrapToken{
             used: true,
             issuance_request_id: ^request_id,
             issued_certificate_id: certificate_id
           } = Repo.get_by!(AppBootstrapToken, app_id: app.id)

    assert certificate_id == cert_record.id
    assert agent.id == app.agent_id

    assert %AuditLog{
             actor_type: "app",
             actor_id: app_id,
             app_id: app_id,
             agent_id: agent_id,
             access_granted: true,
             correlation_id: ^request_id,
             event_data: %{
               "app_certificate_issuance" => %{
                 "agent_id" => agent_id,
                 "app_id" => app_id,
                 "certificate_id" => ^certificate_id,
                 "request_id" => ^request_id,
                 "result_code" => "issued"
               }
             }
           } =
             Repo.one!(
               from(a in AuditLog,
                 where: a.event_type == "auth.app_certificate_issuance_allowed"
               )
             )

    assert app_id == app.id
    assert agent_id == agent.id

    issuance_audit =
      Repo.one!(
        from(a in AuditLog,
          where: a.event_type == "auth.app_certificate_issuance_allowed"
        )
      )

    refute inspect(issuance_audit.event_data) =~ token
    refute inspect(issuance_audit.event_data) =~ csr_pem
    refute inspect(issuance_audit.event_data) =~ certificate_pem
  end

  test "rejects an RSA key smaller than 2048 bits without consuming the token", %{
    app: app,
    token: token
  } do
    private_key = X509.PrivateKey.new_rsa(1024)
    csr_pem = private_key |> X509.CSR.new("/CN=small-rsa") |> X509.CSR.to_pem()

    assert {:error, :unsupported_key} =
             AppCertificates.issue_from_bootstrap(token, csr_pem, Ecto.UUID.generate())

    assert Repo.aggregate(
             from(c in Certificate, where: c.cert_type == :app_client),
             :count
           ) == 0

    assert Repo.aggregate(AppCertificate, :count) == 0
    assert %AppBootstrapToken{used: false} = Repo.get_by!(AppBootstrapToken, app_id: app.id)
  end

  test "rejects a signature-valid RSA key with public exponent one", %{
    app: app,
    token: token
  } do
    key = X509.PrivateKey.new_rsa(2048)

    weak_key =
      key
      |> put_elem(3, 1)
      |> put_elem(4, 1)
      |> put_elem(7, 1)
      |> put_elem(8, 1)

    csr = X509.CSR.new(weak_key, "/CN=weak-rsa")

    assert X509.CSR.valid?(csr)
    assert {:RSAPublicKey, _modulus, 1} = X509.CSR.public_key(csr)

    assert {:error, :unsupported_key} =
             AppCertificates.issue_from_bootstrap(
               token,
               X509.CSR.to_pem(csr),
               Ecto.UUID.generate()
             )

    assert Repo.aggregate(
             from(c in Certificate, where: c.cert_type == :app_client),
             :count
           ) == 0

    assert %AppBootstrapToken{used: false} = Repo.get_by!(AppBootstrapToken, app_id: app.id)
  end

  test "rejects a signature-valid RSA key with an even public exponent", %{
    app: app,
    token: token
  } do
    csr = forged_even_exponent_csr()

    assert X509.CSR.valid?(csr)
    assert {:RSAPublicKey, _modulus, 4} = X509.CSR.public_key(csr)

    assert {:error, :unsupported_key} =
             AppCertificates.issue_from_bootstrap(
               token,
               X509.CSR.to_pem(csr),
               Ecto.UUID.generate()
             )

    assert Repo.aggregate(
             from(c in Certificate, where: c.cert_type == :app_client),
             :count
           ) == 0

    assert %AppBootstrapToken{used: false} = Repo.get_by!(AppBootstrapToken, app_id: app.id)
  end

  for curve <- [:secp256r1, :secp384r1] do
    @curve curve

    test "issues an application certificate for #{@curve}", %{app: app, token: token} do
      private_key = X509.PrivateKey.new_ec(@curve)
      csr_pem = private_key |> X509.CSR.new("/CN=ec-client") |> X509.CSR.to_pem()

      assert {:ok, %{certificate: certificate_pem, replayed: false}} =
               AppCertificates.issue_from_bootstrap(token, csr_pem, Ecto.UUID.generate())

      assert {:ok, %{app_id: app_id, public_key: public_key}} =
               CertificateIdentity.validate_app_certificate(certificate_pem, app.id)

      assert app_id == app.id
      assert public_key == X509.PublicKey.derive(private_key)
    end
  end

  test "rejects unsupported EC curves including P-521", %{app: app, token: token} do
    private_key = X509.PrivateKey.new_ec(:secp521r1)
    csr_pem = private_key |> X509.CSR.new("/CN=p521-client") |> X509.CSR.to_pem()

    assert {:error, :unsupported_key} =
             AppCertificates.issue_from_bootstrap(token, csr_pem, Ecto.UUID.generate())

    assert Repo.aggregate(
             from(c in Certificate, where: c.cert_type == :app_client),
             :count
           ) == 0

    assert %AppBootstrapToken{used: false} = Repo.get_by!(AppBootstrapToken, app_id: app.id)
  end

  test "rejects a CSR whose signature does not match its embedded public key", %{
    app: app,
    token: token
  } do
    signing_key = X509.PrivateKey.new_rsa(2048)
    embedded_key = X509.PrivateKey.new_rsa(2048) |> X509.PublicKey.derive()

    csr_pem =
      signing_key
      |> X509.CSR.new("/CN=invalid-signature", public_key: embedded_key)
      |> X509.CSR.to_pem()

    assert {:error, :invalid_csr} =
             AppCertificates.issue_from_bootstrap(token, csr_pem, Ecto.UUID.generate())

    assert Repo.aggregate(
             from(c in Certificate, where: c.cert_type == :app_client),
             :count
           ) == 0

    assert %AppBootstrapToken{used: false} = Repo.get_by!(AppBootstrapToken, app_id: app.id)
  end

  test "ignores hostile CSR identity and requested extensions", %{app: app, token: token} do
    private_key = X509.PrivateKey.new_rsa(2048)

    csr_pem =
      private_key
      |> X509.CSR.new("/O=Attacker/CN=admin",
        extension_request: [
          Extension.subject_alt_name([
            "attacker.example",
            {:uniformResourceIdentifier, ~c"urn:secrethub:app:attacker"}
          ]),
          Extension.key_usage([:keyEncipherment]),
          Extension.ext_key_usage([:serverAuth])
        ]
      )
      |> X509.CSR.to_pem()

    assert {:ok, %{certificate: certificate_pem}} =
             AppCertificates.issue_from_bootstrap(token, csr_pem, Ecto.UUID.generate())

    certificate = X509.Certificate.from_pem!(certificate_pem)
    canonical_uri = ~c"urn:secrethub:app:" ++ to_charlist(app.id)

    assert X509.Certificate.subject(certificate, "CN") == [app.id]
    assert X509.Certificate.subject(certificate, "O") == ["SecretHub Applications"]
    assert X509.Certificate.public_key(certificate) == X509.PublicKey.derive(private_key)

    assert {:Extension, _, _, [{:uniformResourceIdentifier, ^canonical_uri}]} =
             X509.Certificate.extension(certificate, :subject_alt_name)

    assert {:Extension, _, _, [:digitalSignature]} =
             X509.Certificate.extension(certificate, :key_usage)

    assert {:Extension, _, _, [{1, 3, 6, 1, 5, 5, 7, 3, 2}]} =
             X509.Certificate.extension(certificate, :ext_key_usage)
  end

  test "replays the persisted result for the same request and rejects a different request", %{
    agent: agent,
    app: app,
    token: token
  } do
    request_id = Ecto.UUID.generate()
    private_key = X509.PrivateKey.new_rsa(2048)
    csr_pem = private_key |> X509.CSR.new("/CN=replay") |> X509.CSR.to_pem()

    assert {:ok, first} =
             AppCertificates.issue_from_bootstrap(token, csr_pem, request_id)

    first.cert_record.issuer_id
    |> then(&Repo.get!(Certificate, &1))
    |> Certificate.revoke_changeset("revoked_after_issuance")
    |> Repo.update!()

    {:ok, _newer_ca} =
      CA.generate_root_ca(
        "Later Replay Root #{System.unique_integer([:positive])}",
        "SecretHub Test",
        key_size: 2048
      )

    assert {:ok, replay} =
             AppCertificates.issue_from_bootstrap(token, "not a CSR", request_id)

    assert replay.replayed
    assert replay.certificate == first.certificate
    assert replay.ca_chain == first.ca_chain
    assert replay.cert_record.id == first.cert_record.id
    assert replay.app_certificate.id == first.app_certificate.id

    assert [
             %AuditLog{
               actor_type: "app",
               actor_id: app_id,
               app_id: app_id,
               agent_id: agent_id,
               access_granted: true,
               correlation_id: ^request_id,
               event_data: %{
                 "app_certificate_issuance" => %{
                   "agent_id" => agent_id,
                   "app_id" => app_id,
                   "certificate_id" => certificate_id,
                   "request_id" => ^request_id,
                   "result_code" => "issued"
                 }
               }
             },
             %AuditLog{
               actor_type: "app",
               actor_id: app_id,
               app_id: app_id,
               agent_id: agent_id,
               access_granted: true,
               correlation_id: ^request_id,
               event_data: %{
                 "app_certificate_issuance" => %{
                   "agent_id" => agent_id,
                   "app_id" => app_id,
                   "certificate_id" => certificate_id,
                   "request_id" => ^request_id,
                   "result_code" => "replayed"
                 }
               }
             }
           ] =
             Repo.all(
               from(a in AuditLog,
                 where: a.event_type == "auth.app_certificate_issuance_allowed",
                 order_by: [asc: a.sequence_number]
               )
             )

    assert app_id == app.id
    assert agent_id == agent.id
    assert certificate_id == first.cert_record.id

    assert {:error, :idempotency_conflict} =
             AppCertificates.issue_from_bootstrap(token, csr_pem, Ecto.UUID.generate())

    assert Repo.aggregate(
             from(c in Certificate, where: c.cert_type == :app_client),
             :count
           ) == 1

    assert Repo.aggregate(AppCertificate, :count) == 1
  end

  test "replays the matching certificate when two app tokens share a request ID", %{
    agent: agent,
    app: app,
    token: first_token
  } do
    assert {:ok, second_token, %AppBootstrapToken{app_id: app_id}} =
             Apps.generate_bootstrap_token(app.id)

    assert app_id == app.id
    refute second_token == first_token

    request_id = Ecto.UUID.generate()

    first_csr =
      X509.PrivateKey.new_rsa(2048)
      |> X509.CSR.new("/CN=first-token")
      |> X509.CSR.to_pem()

    second_csr =
      X509.PrivateKey.new_rsa(2048)
      |> X509.CSR.new("/CN=second-token")
      |> X509.CSR.to_pem()

    assert {:ok, first} =
             AppCertificates.issue_from_bootstrap(first_token, first_csr, request_id)

    assert {:ok, second} =
             AppCertificates.issue_from_bootstrap(second_token, second_csr, request_id)

    refute first.cert_record.id == second.cert_record.id

    assert {:ok, replay} =
             AppCertificates.issue_from_bootstrap(second_token, "not a CSR", request_id)

    assert replay.replayed
    assert replay.certificate == second.certificate
    assert replay.ca_chain == second.ca_chain
    assert replay.cert_record.id == second.cert_record.id
    assert replay.app_certificate.id == second.app_certificate.id

    assert [
             %{
               "certificate_id" => first_certificate_id,
               "result_code" => "issued"
             },
             %{
               "certificate_id" => second_certificate_id,
               "result_code" => "issued"
             },
             %{
               "certificate_id" => replayed_certificate_id,
               "result_code" => "replayed"
             }
           ] =
             Repo.all(
               from(a in AuditLog,
                 where: a.event_type == "auth.app_certificate_issuance_allowed",
                 where: a.app_id == ^app.id,
                 where: a.agent_id == ^agent.id,
                 where: a.correlation_id == ^request_id,
                 order_by: [asc: a.sequence_number],
                 select: fragment("?->'app_certificate_issuance'", a.event_data)
               )
             )

    assert first_certificate_id == first.cert_record.id
    assert second_certificate_id == second.cert_record.id
    assert replayed_certificate_id == second.cert_record.id
  end

  test "rejects every database-storable malformed bootstrap token state", %{
    app: app,
    token: token
  } do
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    stored_request_id = Ecto.UUID.generate()

    csr_pem =
      X509.PrivateKey.new_rsa(2048) |> X509.CSR.new("/CN=token-state") |> X509.CSR.to_pem()

    assert {:ok, %{cert_record: %Certificate{id: issued_certificate_id}}} =
             AppCertificates.issue_from_bootstrap(token, csr_pem, stored_request_id)

    malformed_states = [
      [used: false, used_at: now, issuance_request_id: nil, issued_certificate_id: nil],
      [
        used: false,
        used_at: nil,
        issuance_request_id: stored_request_id,
        issued_certificate_id: issued_certificate_id
      ],
      [
        used: false,
        used_at: now,
        issuance_request_id: stored_request_id,
        issued_certificate_id: issued_certificate_id
      ],
      [used: true, used_at: nil, issuance_request_id: nil, issued_certificate_id: nil],
      [
        used: true,
        used_at: nil,
        issuance_request_id: stored_request_id,
        issued_certificate_id: issued_certificate_id
      ],
      [used: true, used_at: now, issuance_request_id: nil, issued_certificate_id: nil]
    ]

    Enum.each(malformed_states, fn state ->
      Repo.update_all(
        from(t in AppBootstrapToken, where: t.app_id == ^app.id),
        set: state
      )

      assert {:error, :issuance_failed} =
               AppCertificates.issue_from_bootstrap(token, csr_pem, stored_request_id)
    end)
  end

  test "accepts an assignment to a trusted-connected Agent", %{
    agent: agent,
    token: token
  } do
    agent |> Ecto.Changeset.change(status: :trusted_connected) |> Repo.update!()
    private_key = X509.PrivateKey.new_rsa(2048)
    csr_pem = private_key |> X509.CSR.new("/CN=trusted-agent") |> X509.CSR.to_pem()

    assert {:ok, %{replayed: false}} =
             AppCertificates.issue_from_bootstrap(token, csr_pem, Ecto.UUID.generate())
  end

  test "locks application, assigned Agent, and token rows in fixed order", %{token: token} do
    handler_id = {__MODULE__, make_ref()}

    :ok =
      :telemetry.attach(
        handler_id,
        [:secret_hub, :core, :repo, :query],
        fn _event, _measurements, metadata, test_pid ->
          send(test_pid, {:issuance_sql, metadata.query})
        end,
        self()
      )

    on_exit(fn -> :telemetry.detach(handler_id) end)

    csr_pem =
      X509.PrivateKey.new_rsa(2048)
      |> X509.CSR.new("/CN=locked-assignment")
      |> X509.CSR.to_pem()

    assert {:ok, %{replayed: false}} =
             AppCertificates.issue_from_bootstrap(token, csr_pem, Ecto.UUID.generate())

    lock_queries =
      []
      |> collect_issuance_sql()
      |> Enum.filter(&String.contains?(&1, "FOR UPDATE"))

    assert [app_query, agent_query, token_query | _rest] = lock_queries
    assert app_query =~ ~s(FROM "applications")
    assert agent_query =~ ~s(FROM "agents")
    assert token_query =~ ~s(FROM "app_bootstrap_tokens")
  end

  test "rejects a suspended Agent assignment and keeps the token unused", %{
    agent: agent,
    app: app,
    token: token
  } do
    agent |> Ecto.Changeset.change(status: :suspended) |> Repo.update!()
    private_key = X509.PrivateKey.new_rsa(2048)
    csr_pem = private_key |> X509.CSR.new("/CN=suspended-agent") |> X509.CSR.to_pem()

    assert {:error, :invalid_agent_assignment} =
             AppCertificates.issue_from_bootstrap(token, csr_pem, Ecto.UUID.generate())

    assert %AppBootstrapToken{used: false} = Repo.get_by!(AppBootstrapToken, app_id: app.id)
    assert Repo.aggregate(AppCertificate, :count) == 0
  end

  test "rejects a suspended application and keeps the token unused", %{
    app: app,
    token: token
  } do
    {:ok, _suspended_app} = Apps.suspend_app(app.id)
    private_key = X509.PrivateKey.new_rsa(2048)
    csr_pem = private_key |> X509.CSR.new("/CN=suspended-app") |> X509.CSR.to_pem()

    assert {:error, :invalid_agent_assignment} =
             AppCertificates.issue_from_bootstrap(token, csr_pem, Ecto.UUID.generate())

    assert %AppBootstrapToken{used: false} = Repo.get_by!(AppBootstrapToken, app_id: app.id)
    assert Repo.aggregate(AppCertificate, :count) == 0
  end

  test "records an invalid-token denial after rollback using only stable evidence", %{
    app: app
  } do
    invalid_token = "hvs.invalid-secret-material"
    request_id = Ecto.UUID.generate()
    private_key = X509.PrivateKey.new_rsa(2048)
    csr_pem = private_key |> X509.CSR.new("/CN=invalid-token") |> X509.CSR.to_pem()

    assert {:error, :invalid_token} =
             AppCertificates.issue_from_bootstrap(invalid_token, csr_pem, request_id)

    assert %AppBootstrapToken{
             used: false,
             used_at: nil,
             issuance_request_id: nil,
             issued_certificate_id: nil
           } = Repo.get_by!(AppBootstrapToken, app_id: app.id)

    assert Repo.aggregate(AppCertificate, :count) == 0

    assert %AuditLog{
             actor_type: "app_bootstrap",
             access_granted: false,
             denial_reason: "invalid_token",
             correlation_id: ^request_id,
             event_data: %{
               "app_certificate_issuance" => %{
                 "request_id" => ^request_id,
                 "result_code" => "invalid_token"
               }
             }
           } =
             denied =
             Repo.one!(
               from(a in AuditLog,
                 where: a.event_type == "auth.app_certificate_issuance_denied"
               )
             )

    refute inspect(denied.event_data) =~ invalid_token
    refute inspect(denied.event_data) =~ csr_pem
  end

  test "keeps the normalized denial stable when post-rollback audit raises" do
    Process.put(:secrethub_app_certificate_issuance_audit_fault, :raise)

    log =
      ExUnit.CaptureLog.capture_log(fn ->
        assert {:error, :invalid_token} =
                 AppCertificates.issue_from_bootstrap(
                   "hvs.invalid-secret-material",
                   "not inspected for an invalid token",
                   Ecto.UUID.generate()
                 )
      end)

    assert log =~ @post_rollback_audit_failure_log
    refute log =~ "hvs.invalid-secret-material"
    refute log =~ "not inspected for an invalid token"
  end

  test "keeps the normalized invalid-request denial stable when post-rollback audit exits" do
    Process.put(:secrethub_app_certificate_issuance_audit_fault, :exit)

    log =
      ExUnit.CaptureLog.capture_log(fn ->
        assert {:error, :invalid_request_id} =
                 AppCertificates.issue_from_bootstrap(
                   "not inspected for an invalid request",
                   "not inspected for an invalid request",
                   "not-a-request-uuid"
                 )
      end)

    assert log =~ @post_rollback_audit_failure_log
    refute log =~ "not inspected for an invalid request"
    refute log =~ "not-a-request-uuid"
  end

  test "keeps the normalized issuance failure stable when post-rollback audit exits", %{
    ca: ca,
    token: token
  } do
    ca |> Certificate.revoke_changeset("test_unavailable") |> Repo.update!()
    Process.put(:secrethub_app_certificate_issuance_audit_fault, :exit)

    csr_pem =
      X509.PrivateKey.new_rsa(2048)
      |> X509.CSR.new("/CN=audit-failure")
      |> X509.CSR.to_pem()

    log =
      ExUnit.CaptureLog.capture_log(fn ->
        assert {:error, :ca_unavailable} =
                 AppCertificates.issue_from_bootstrap(token, csr_pem, Ecto.UUID.generate())
      end)

    assert log =~ @post_rollback_audit_failure_log
    refute log =~ token
    refute log =~ csr_pem
  end

  test "rejects an invalid request UUID before mutation and records a sanitized denial", %{
    app: app,
    token: token
  } do
    invalid_request_id = "not-a-request-uuid"
    private_key = X509.PrivateKey.new_rsa(2048)
    csr_pem = private_key |> X509.CSR.new("/CN=invalid-request") |> X509.CSR.to_pem()

    assert {:error, :invalid_request_id} =
             AppCertificates.issue_from_bootstrap(token, csr_pem, invalid_request_id)

    assert %AppBootstrapToken{
             used: false,
             used_at: nil,
             issuance_request_id: nil,
             issued_certificate_id: nil
           } = Repo.get_by!(AppBootstrapToken, app_id: app.id)

    assert Repo.aggregate(AppCertificate, :count) == 0

    assert %AuditLog{
             actor_type: "app_bootstrap",
             access_granted: false,
             denial_reason: "invalid_request_id",
             event_data: %{
               "app_certificate_issuance" => %{
                 "result_code" => "invalid_request_id"
               }
             }
           } =
             denied =
             Repo.one!(
               from(a in AuditLog,
                 where: a.event_type == "auth.app_certificate_issuance_denied"
               )
             )

    refute inspect(denied.event_data) =~ invalid_request_id
    refute inspect(denied.event_data) =~ token
    refute inspect(denied.event_data) =~ csr_pem
  end

  test "returns ca_unavailable without mutation and records a sanitized failure", %{
    app: app,
    token: token,
    ca: ca
  } do
    ca |> Certificate.revoke_changeset("test_unavailable") |> Repo.update!()
    request_id = Ecto.UUID.generate()
    private_key = X509.PrivateKey.new_rsa(2048)
    csr_pem = private_key |> X509.CSR.new("/CN=no-ca") |> X509.CSR.to_pem()

    assert {:error, :ca_unavailable} =
             AppCertificates.issue_from_bootstrap(token, csr_pem, request_id)

    assert %AppBootstrapToken{
             used: false,
             used_at: nil,
             issuance_request_id: nil,
             issued_certificate_id: nil
           } = Repo.get_by!(AppBootstrapToken, app_id: app.id)

    assert Repo.aggregate(AppCertificate, :count) == 0

    assert %AuditLog{
             event_type: "auth.app_certificate_issuance_failed",
             access_granted: false,
             denial_reason: "ca_unavailable",
             correlation_id: ^request_id,
             event_data: %{
               "app_certificate_issuance" => %{
                 "request_id" => ^request_id,
                 "result_code" => "ca_unavailable"
               }
             }
           } =
             failed =
             Repo.one!(
               from(a in AuditLog,
                 where: a.event_type == "auth.app_certificate_issuance_failed"
               )
             )

    refute inspect(failed.event_data) =~ token
    refute inspect(failed.event_data) =~ csr_pem
  end

  test "rejects new issuance when an active intermediate has a revoked ancestor", %{
    app: app,
    token: token,
    ca: root
  } do
    {:ok, _intermediate} =
      CA.generate_intermediate_ca(
        "Revoked Ancestor Intermediate #{System.unique_integer([:positive])}",
        "SecretHub Test",
        root.id,
        key_size: 2048
      )

    root |> Certificate.revoke_changeset("revoked_ancestor") |> Repo.update!()

    csr_pem =
      X509.PrivateKey.new_rsa(2048)
      |> X509.CSR.new("/CN=revoked-ancestor")
      |> X509.CSR.to_pem()

    assert {:error, :ca_unavailable} =
             AppCertificates.issue_from_bootstrap(token, csr_pem, Ecto.UUID.generate())

    assert %AppBootstrapToken{
             used: false,
             used_at: nil,
             issuance_request_id: nil,
             issued_certificate_id: nil
           } = Repo.get_by!(AppBootstrapToken, app_id: app.id)

    assert Repo.aggregate(AppCertificate, :count) == 0
  end

  test "rejects new issuance when an active intermediate has an expired ancestor", %{
    app: app,
    token: token,
    ca: root
  } do
    {:ok, _intermediate} =
      CA.generate_intermediate_ca(
        "Expired Ancestor Intermediate #{System.unique_integer([:positive])}",
        "SecretHub Test",
        root.id,
        key_size: 2048
      )

    root
    |> Ecto.Changeset.change(
      valid_until:
        DateTime.utc_now()
        |> DateTime.add(-60, :second)
        |> DateTime.truncate(:second)
    )
    |> Repo.update!()

    csr_pem =
      X509.PrivateKey.new_rsa(2048)
      |> X509.CSR.new("/CN=expired-ancestor")
      |> X509.CSR.to_pem()

    assert {:error, :ca_unavailable} =
             AppCertificates.issue_from_bootstrap(token, csr_pem, Ecto.UUID.generate())

    assert %AppBootstrapToken{
             used: false,
             used_at: nil,
             issuance_request_id: nil,
             issued_certificate_id: nil
           } = Repo.get_by!(AppBootstrapToken, app_id: app.id)

    assert Repo.aggregate(AppCertificate, :count) == 0
  end

  test "rejects an ordinary intermediate below a root with pathLenConstraint zero", %{
    app: app,
    token: token
  } do
    unique = System.unique_integer([:positive])
    root_name = "Path Length Root #{unique}"

    {:ok, root} =
      CA.generate_root_ca(
        root_name,
        "SecretHub Test",
        key_size: 2048
      )

    root_key = X509.PrivateKey.from_pem!(root.private_key)

    constrained_root =
      X509.Certificate.self_signed(
        root_key,
        "/O=SecretHub Test/CN=#{root_name}",
        template: :root_ca,
        extensions: [
          basic_constraints: Extension.basic_constraints(true, 0)
        ]
      )

    root.cert_record
    |> Ecto.Changeset.change(certificate_pem: X509.Certificate.to_pem(constrained_root))
    |> Repo.update!()

    {:ok, _intermediate} =
      CA.generate_intermediate_ca(
        "Path Length Intermediate #{unique}",
        "SecretHub Test",
        root.cert_record.id,
        key_size: 2048
      )

    csr_pem =
      X509.PrivateKey.new_rsa(2048)
      |> X509.CSR.new("/CN=path-length-client")
      |> X509.CSR.to_pem()

    assert {:error, :ca_unavailable} =
             AppCertificates.issue_from_bootstrap(token, csr_pem, Ecto.UUID.generate())

    assert %AppBootstrapToken{
             used: false,
             used_at: nil,
             issuance_request_id: nil,
             issued_certificate_id: nil
           } = Repo.get_by!(AppBootstrapToken, app_id: app.id)

    assert Repo.aggregate(AppCertificate, :count) == 0
  end

  test "does not count a self-issued rollover intermediate against pathLenConstraint", %{
    app: app,
    token: token
  } do
    unique = System.unique_integer([:positive])
    root_name = "Rollover Path Length Root #{unique}"

    {:ok, root} =
      CA.generate_root_ca(
        root_name,
        "SecretHub Test",
        key_size: 2048
      )

    root_key = X509.PrivateKey.from_pem!(root.private_key)

    constrained_root =
      X509.Certificate.self_signed(
        root_key,
        "/O=SecretHub Test/CN=#{root_name}",
        template: :root_ca,
        extensions: [
          basic_constraints: Extension.basic_constraints(true, 0)
        ]
      )

    root.cert_record
    |> Ecto.Changeset.change(certificate_pem: X509.Certificate.to_pem(constrained_root))
    |> Repo.update!()

    {:ok, intermediate} =
      CA.generate_intermediate_ca(
        "Rollover Intermediate Key #{unique}",
        "SecretHub Test",
        root.cert_record.id,
        key_size: 2048
      )

    intermediate_key = X509.PrivateKey.from_pem!(intermediate.private_key)

    self_issued_rollover =
      X509.Certificate.new(
        X509.PublicKey.derive(intermediate_key),
        X509.Certificate.subject(constrained_root),
        constrained_root,
        root_key,
        template: :ca,
        extensions: [
          basic_constraints: Extension.basic_constraints(true, 0)
        ]
      )

    intermediate.cert_record
    |> Ecto.Changeset.change(certificate_pem: X509.Certificate.to_pem(self_issued_rollover))
    |> Repo.update!()

    csr_pem =
      X509.PrivateKey.new_rsa(2048)
      |> X509.CSR.new("/CN=self-issued-rollover-client")
      |> X509.CSR.to_pem()

    assert {:ok, %{replayed: false}} =
             AppCertificates.issue_from_bootstrap(token, csr_pem, Ecto.UUID.generate())

    assert %AppBootstrapToken{used: true} =
             Repo.get_by!(AppBootstrapToken, app_id: app.id)

    assert Repo.aggregate(AppCertificate, :count) == 1
  end

  test "rejects new issuance when persisted issuer linkage does not verify", %{
    app: app,
    token: token,
    ca: signing_root
  } do
    {:ok, intermediate} =
      CA.generate_intermediate_ca(
        "Mismatched Issuer Intermediate #{System.unique_integer([:positive])}",
        "SecretHub Test",
        signing_root.id,
        key_size: 2048
      )

    {:ok, unrelated_root} =
      CA.generate_root_ca(
        "Unrelated Issuer Root #{System.unique_integer([:positive])}",
        "SecretHub Test",
        key_size: 2048
      )

    intermediate.cert_record
    |> Ecto.Changeset.change(issuer_id: unrelated_root.cert_record.id)
    |> Repo.update!()

    csr_pem =
      X509.PrivateKey.new_rsa(2048)
      |> X509.CSR.new("/CN=mismatched-issuer")
      |> X509.CSR.to_pem()

    assert {:error, :ca_unavailable} =
             AppCertificates.issue_from_bootstrap(token, csr_pem, Ecto.UUID.generate())

    assert %AppBootstrapToken{
             used: false,
             used_at: nil,
             issuance_request_id: nil,
             issued_certificate_id: nil
           } = Repo.get_by!(AppBootstrapToken, app_id: app.id)

    assert Repo.aggregate(AppCertificate, :count) == 0
  end

  test "rejects new issuance when the terminal root signature does not verify", %{
    app: app,
    token: token,
    ca: root
  } do
    root
    |> Ecto.Changeset.change(certificate_pem: corrupt_certificate_signature(root.certificate_pem))
    |> Repo.update!()

    csr_pem =
      X509.PrivateKey.new_rsa(2048)
      |> X509.CSR.new("/CN=bad-root-signature")
      |> X509.CSR.to_pem()

    assert {:error, :ca_unavailable} =
             AppCertificates.issue_from_bootstrap(token, csr_pem, Ecto.UUID.generate())

    assert %AppBootstrapToken{
             used: false,
             used_at: nil,
             issuance_request_id: nil,
             issued_certificate_id: nil
           } = Repo.get_by!(AppBootstrapToken, app_id: app.id)

    assert Repo.aggregate(AppCertificate, :count) == 0
  end

  test "rolls back a fault before Certificate insert and records only sanitized failure", %{
    app: app,
    token: token
  } do
    Process.put(:secrethub_app_certificate_issuance_fault, :before_certificate_insert)
    request_id = Ecto.UUID.generate()
    private_key = X509.PrivateKey.new_rsa(2048)
    csr_pem = private_key |> X509.CSR.new("/CN=fault-before-certificate") |> X509.CSR.to_pem()

    assert {:error, :issuance_failed} =
             AppCertificates.issue_from_bootstrap(token, csr_pem, request_id)

    assert_issuance_rolled_back(app, token, csr_pem, request_id)
  end

  test "rolls back a fault before AppCertificate association insert", %{
    app: app,
    token: token
  } do
    Process.put(
      :secrethub_app_certificate_issuance_fault,
      :before_app_certificate_insert
    )

    request_id = Ecto.UUID.generate()
    private_key = X509.PrivateKey.new_rsa(2048)
    csr_pem = private_key |> X509.CSR.new("/CN=fault-before-association") |> X509.CSR.to_pem()

    assert {:error, :issuance_failed} =
             AppCertificates.issue_from_bootstrap(token, csr_pem, request_id)

    assert_issuance_rolled_back(app, token, csr_pem, request_id)
  end

  test "rolls back Certificate, association, and success audit before token consumption", %{
    app: app,
    token: token
  } do
    Process.put(
      :secrethub_app_certificate_issuance_fault,
      :before_token_consumption
    )

    request_id = Ecto.UUID.generate()
    private_key = X509.PrivateKey.new_rsa(2048)
    csr_pem = private_key |> X509.CSR.new("/CN=fault-before-token") |> X509.CSR.to_pem()

    assert {:error, :issuance_failed} =
             AppCertificates.issue_from_bootstrap(token, csr_pem, request_id)

    assert_issuance_rolled_back(app, token, csr_pem, request_id)
  end

  defp assert_issuance_rolled_back(app, token, csr_pem, request_id) do
    assert Repo.aggregate(
             from(c in Certificate, where: c.cert_type == :app_client),
             :count
           ) == 0

    assert Repo.aggregate(AppCertificate, :count) == 0

    assert %AppBootstrapToken{
             used: false,
             used_at: nil,
             issuance_request_id: nil,
             issued_certificate_id: nil
           } = Repo.get_by!(AppBootstrapToken, app_id: app.id)

    assert [] =
             Repo.all(
               from(a in AuditLog,
                 where: a.event_type == "auth.app_certificate_issuance_allowed"
               )
             )

    assert [
             %AuditLog{
               event_type: "auth.app_certificate_issuance_failed",
               access_granted: false,
               denial_reason: "issuance_failed",
               event_data: %{
                 "app_certificate_issuance" => %{
                   "request_id" => ^request_id,
                   "result_code" => "issuance_failed"
                 }
               }
             }
           ] =
             Repo.all(
               from(a in AuditLog,
                 where: a.event_type == "auth.app_certificate_issuance_failed"
               )
             )

    refute inspect(Repo.all(AuditLog)) =~ token
    refute inspect(Repo.all(AuditLog)) =~ csr_pem
  end

  defp renewal_request(
         app_id,
         current_fingerprint,
         csr_pem,
         current_private_key,
         signature_algorithm,
         request_id \\ Ecto.UUID.generate()
       ) do
    {:ok, payload} =
      AppCertificates.renewal_signing_payload(
        app_id,
        current_fingerprint,
        csr_pem,
        request_id
      )

    proof = renewal_proof(payload, current_private_key, signature_algorithm)

    %{
      app_id: app_id,
      current_fingerprint: current_fingerprint,
      csr: csr_pem,
      request_id: request_id,
      signature_algorithm: signature_algorithm,
      proof: proof
    }
  end

  defp renewal_proof(payload, private_key, "rsa-pss-sha256") do
    :public_key.sign(payload, :sha256, private_key,
      rsa_padding: :rsa_pkcs1_pss_padding,
      rsa_pss_saltlen: 32,
      rsa_mgf1_md: :sha256
    )
  end

  defp renewal_proof(payload, private_key, "ecdsa-sha256") do
    :public_key.sign(payload, :sha256, private_key)
  end

  defp forged_even_exponent_csr do
    modulus =
      """
      FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1
      29024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B
      302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B
      0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D
      C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD96
      1C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C
      32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9
      DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68
      FFFFFFFFFFFFFFFF
      """
      |> String.replace(~r/\s+/, "")
      |> Base.decode16!()
      |> :binary.decode_unsigned()

    signing_key = X509.PrivateKey.new_rsa(2048)
    forge_even_exponent_csr(signing_key, modulus, 0)
  end

  defp forge_even_exponent_csr(signing_key, modulus, nonce) do
    csr =
      X509.CSR.new(signing_key, "/CN=even-rsa-#{nonce}", public_key: {:RSAPublicKey, modulus, 4})

    encoded_message = csr_encoded_message(csr, modulus)
    message = :binary.decode_unsigned(encoded_message)

    if mod_pow(message, div(modulus - 1, 2), modulus) == 1 do
      square_root = mod_pow(message, div(modulus + 1, 4), modulus)

      quadratic_square_root =
        if mod_pow(square_root, div(modulus - 1, 2), modulus) == 1,
          do: square_root,
          else: modulus - square_root

      signature =
        quadratic_square_root
        |> mod_pow(div(modulus + 1, 4), modulus)
        |> :binary.encode_unsigned()
        |> left_pad(byte_size(:binary.encode_unsigned(modulus)))

      put_elem(csr, 3, signature)
    else
      forge_even_exponent_csr(signing_key, modulus, nonce + 1)
    end
  end

  defp csr_encoded_message(csr, modulus) do
    digest =
      csr
      |> elem(1)
      |> then(&:public_key.der_encode(:CertificationRequestInfo, &1))
      |> then(&:crypto.hash(:sha256, &1))

    digest_info =
      Base.decode16!("3031300D060960864801650304020105000420") <> digest

    encoded_size = byte_size(:binary.encode_unsigned(modulus))
    padding = :binary.copy(<<0xFF>>, encoded_size - byte_size(digest_info) - 3)
    <<0, 1>> <> padding <> <<0>> <> digest_info
  end

  defp mod_pow(_base, 0, _modulus), do: 1

  defp mod_pow(base, exponent, modulus) do
    mod_pow(base, exponent, modulus, 1)
  end

  defp mod_pow(_base, 0, _modulus, result), do: result

  defp mod_pow(base, exponent, modulus, result) do
    next_result = if rem(exponent, 2) == 1, do: rem(result * base, modulus), else: result
    mod_pow(rem(base * base, modulus), div(exponent, 2), modulus, next_result)
  end

  defp left_pad(binary, size) do
    :binary.copy(<<0>>, size - byte_size(binary)) <> binary
  end

  defp corrupt_certificate_signature(certificate_pem) do
    [{:Certificate, certificate_der, :not_encrypted}] =
      :public_key.pem_decode(certificate_pem)

    signature_byte_offset = byte_size(certificate_der) - 1
    <<prefix::binary-size(signature_byte_offset), last_byte>> = certificate_der

    [{:Certificate, prefix <> <<Bitwise.bxor(last_byte, 1)>>, :not_encrypted}]
    |> :public_key.pem_encode()
  end

  defp collect_issuance_sql(queries) do
    receive do
      {:issuance_sql, query} -> collect_issuance_sql([query | queries])
    after
      0 -> Enum.reverse(queries)
    end
  end
end
