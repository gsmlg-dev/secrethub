defmodule SecretHub.Web.PKIControllerTest do
  use SecretHub.Web.ConnCase, async: false

  alias SecretHub.Core.{Apps, Repo}
  alias SecretHub.Core.PKI.{AppCertificates, CA}
  alias SecretHub.Shared.Schemas.{Agent, AppCertificate, Certificate}

  @rate_limiter_table :rate_limiter_table

  setup do
    cleanup_rate_limit_entries(:app_certificate_bootstrap)
    cleanup_rate_limit_entries(:app_certificate_renewal)

    on_exit(fn ->
      cleanup_rate_limit_entries(:app_certificate_bootstrap)
      cleanup_rate_limit_entries(:app_certificate_renewal)
    end)

    :ok
  end

  test "PKI API rejects missing vault token", %{conn: conn} do
    conn =
      post(conn, "/v1/pki/ca/root/generate", %{
        "common_name" => "Missing Token Root CA",
        "organization" => "SecretHub Web Test"
      })

    assert json_response(conn, 401)["error"] == "Missing or empty X-Vault-Token header"
  end

  test "PKI API creates CA hierarchy, signs CSR, lists, fetches, and revokes certificates" do
    token = vault_token!()
    root_cn = unique_name("web-root-ca")
    intermediate_cn = unique_name("web-intermediate-ca")
    service_cn = unique_name("web-service")

    root_response =
      token
      |> authed_conn()
      |> post("/v1/pki/ca/root/generate", %{
        "common_name" => root_cn,
        "organization" => "SecretHub Web Test",
        "key_type" => "rsa",
        "key_size" => 2048,
        "validity_days" => 3650
      })
      |> json_response(201)

    assert root_response["certificate"] =~ "-----BEGIN CERTIFICATE-----"
    assert root_response["private_key"] =~ "-----BEGIN RSA PRIVATE KEY-----"
    assert root_response["cert_id"]

    root_cert = X509.Certificate.from_pem!(root_response["certificate"])
    assert X509.Certificate.subject(root_cert, "CN") == [root_cn]
    assert X509.Certificate.issuer(root_cert, "CN") == [root_cn]

    intermediate_response =
      token
      |> authed_conn()
      |> post("/v1/pki/ca/intermediate/generate", %{
        "common_name" => intermediate_cn,
        "organization" => "SecretHub Web Test",
        "root_ca_id" => root_response["cert_id"],
        "key_type" => "rsa",
        "key_size" => 2048,
        "validity_days" => 1825
      })
      |> json_response(201)

    assert intermediate_response["certificate"] =~ "-----BEGIN CERTIFICATE-----"
    assert intermediate_response["private_key"] =~ "-----BEGIN RSA PRIVATE KEY-----"

    intermediate_cert = X509.Certificate.from_pem!(intermediate_response["certificate"])
    assert X509.Certificate.subject(intermediate_cert, "CN") == [intermediate_cn]
    assert X509.Certificate.issuer(intermediate_cert, "CN") == [root_cn]
    assert :public_key.pkix_is_issuer(intermediate_cert, root_cert)

    {_service_key, service_csr_pem} = new_csr(service_cn)

    signed_response =
      token
      |> authed_conn()
      |> post("/v1/pki/sign-request", %{
        "csr" => service_csr_pem,
        "ca_id" => intermediate_response["cert_id"],
        "cert_type" => "agent_client",
        "validity_days" => 90
      })
      |> json_response(201)

    assert signed_response["certificate"] =~ "-----BEGIN CERTIFICATE-----"

    service_cert = X509.Certificate.from_pem!(signed_response["certificate"])
    assert X509.Certificate.subject(service_cert, "CN") == [service_cn]
    assert X509.Certificate.issuer(service_cert, "CN") == [intermediate_cn]
    assert :public_key.pkix_is_issuer(service_cert, intermediate_cert)

    assert %Certificate{} = service_record = Repo.get(Certificate, signed_response["cert_id"])
    assert service_record.common_name == service_cn
    assert service_record.cert_type == :agent_client
    assert service_record.issuer_id == intermediate_response["cert_id"]
    assert service_record.revoked == false

    list_response =
      token
      |> authed_conn()
      |> get("/v1/pki/certificates", %{"cert_type" => "agent_client", "revoked" => "false"})
      |> json_response(200)

    assert Enum.any?(list_response["certificates"], &(&1["id"] == signed_response["cert_id"]))

    detail_response =
      token
      |> authed_conn()
      |> get("/v1/pki/certificates/#{signed_response["cert_id"]}")
      |> json_response(200)

    assert detail_response["id"] == signed_response["cert_id"]
    assert detail_response["common_name"] == service_cn
    assert detail_response["cert_type"] == "agent_client"
    assert detail_response["certificate"] == signed_response["certificate"]
    assert detail_response["revoked"] == false

    revoke_response =
      token
      |> authed_conn()
      |> post("/v1/pki/certificates/#{signed_response["cert_id"]}/revoke", %{
        "reason" => "keyCompromise"
      })
      |> json_response(200)

    assert revoke_response["revoked"] == true
    assert revoke_response["reason"] == "keyCompromise"

    revoked_detail_response =
      token
      |> authed_conn()
      |> get("/v1/pki/certificates/#{signed_response["cert_id"]}")
      |> json_response(200)

    assert revoked_detail_response["revoked"] == true
    assert revoked_detail_response["revocation_reason"] == "keyCompromise"

    revoked_list_response =
      token
      |> authed_conn()
      |> get("/v1/pki/certificates", %{"revoked" => "true"})
      |> json_response(200)

    assert Enum.any?(
             revoked_list_response["certificates"],
             &(&1["id"] == signed_response["cert_id"])
           )
  end

  test "sign request validates required CSR parameters" do
    conn =
      vault_token!()
      |> authed_conn()
      |> post("/v1/pki/sign-request", %{"ca_id" => Ecto.UUID.generate()})

    assert json_response(conn, 400)["error"] == "csr is required"
  end

  test "an Agent Vault token cannot mint an app certificate through generic signing" do
    fixture = renewal_fixture!()
    {_private_key, csr_pem} = new_csr(fixture.app.id)
    certificate_count = Repo.aggregate(Certificate, :count)
    app_certificate_count = Repo.aggregate(AppCertificate, :count)
    test_pid = self()

    log =
      ExUnit.CaptureLog.capture_log(fn ->
        response =
          vault_token!()
          |> authed_conn()
          |> post("/v1/pki/sign-request", %{
            "csr" => csr_pem,
            "ca_id" => fixture.current.cert_record.issuer_id,
            "cert_type" => "app_client",
            "validity_days" => 90
          })

        send(test_pid, {:generic_app_signing_response, response})
      end)

    assert_receive {:generic_app_signing_response, response}
    assert json_response(response, 403) == %{"error" => "FORBIDDEN"}
    assert Repo.aggregate(Certificate, :count) == certificate_count
    assert Repo.aggregate(AppCertificate, :count) == app_certificate_count

    for private_value <- [csr_pem | pem_log_leak_markers(csr_pem)] do
      refute log =~ private_value
    end
  end

  test "application certificate issuance maps an invalid bootstrap token without Vault auth", %{
    conn: _conn
  } do
    {_private_key, csr_pem} = new_csr("ignored-bootstrap-identity")

    response =
      bootstrap_conn()
      |> post("/v1/pki/app/issue", %{
        "token" => "hvs.invalid-bootstrap-token",
        "csr" => csr_pem,
        "request_id" => Ecto.UUID.generate()
      })

    assert json_response(response, 401) == %{"error" => "INVALID_TOKEN"}
  end

  test "application certificate renewal accepts RSA-PSS current-key proof without Vault auth" do
    fixture = renewal_fixture!()
    request = renewal_wire_request(fixture)

    response =
      renewal_conn()
      |> post("/v1/pki/app/renew", request)
      |> json_response(200)

    assert response["certificate"] =~ "-----BEGIN CERTIFICATE-----"
    assert [_ca | _rest] = response["ca_chain"]
    assert response["serial_number"]
    assert response["expires_at"]
    assert response["issued_at"]
    assert response["replayed"] == false

    assert %AppCertificate{revocation_reason: "superseded"} =
             Repo.get!(AppCertificate, fixture.current.app_certificate.id)

    assert %Certificate{revoked: true, revocation_reason: "superseded"} =
             Repo.get!(Certificate, fixture.current.cert_record.id)
  end

  test "application certificate renewal enforces the exact padded-Base64 wire shape" do
    fixture = renewal_fixture!()
    request = renewal_wire_request(fixture)

    Enum.each(Map.keys(request), fn required_field ->
      response =
        renewal_conn()
        |> post("/v1/pki/app/renew", Map.delete(request, required_field))

      if required_field == "proof" do
        assert json_response(response, 401) == %{"error" => "PROOF_REQUIRED"}
      else
        assert json_response(response, 400) == %{"error" => "INVALID_REQUEST"}
      end
    end)

    blank_proof_response =
      renewal_conn()
      |> post("/v1/pki/app/renew", Map.put(request, "proof", ""))

    assert json_response(blank_proof_response, 401) == %{"error" => "PROOF_REQUIRED"}

    extra_response =
      renewal_conn()
      |> post("/v1/pki/app/renew", Map.put(request, "ttl", 3600))

    assert json_response(extra_response, 400) == %{"error" => "INVALID_REQUEST"}

    unpadded_proof = String.trim_trailing(request["proof"], "=")
    refute unpadded_proof == request["proof"]

    unpadded_response =
      renewal_conn()
      |> post(
        "/v1/pki/app/renew",
        Map.put(request, "proof", unpadded_proof)
      )

    assert json_response(unpadded_response, 400) == %{"error" => "INVALID_REQUEST"}
    assert Repo.get!(Certificate, fixture.current.cert_record.id).revoked == false
  end

  test "a Vault token cannot substitute for application renewal proof" do
    fixture = renewal_fixture!()

    response =
      vault_token!()
      |> authed_conn()
      |> post(
        "/v1/pki/app/renew",
        fixture
        |> renewal_wire_request()
        |> Map.put("proof", Base.encode64("wrong-proof"))
      )

    assert json_response(response, 401) == %{"error" => "PROOF_FAILED"}
    assert Repo.get!(Certificate, fixture.current.cert_record.id).revoked == false
  end

  test "application renewal exposes stable certificate and authorization errors" do
    invalid_certificate_fixture = renewal_fixture!()

    invalid_certificate =
      renewal_conn()
      |> post(
        "/v1/pki/app/renew",
        invalid_certificate_fixture
        |> renewal_wire_request()
        |> Map.put("current_fingerprint", String.duplicate("0", 64))
      )

    assert json_response(invalid_certificate, 401) == %{
             "error" => "INVALID_CERTIFICATE"
           }

    forbidden_fixture = renewal_fixture!()
    forbidden_fixture.agent |> Ecto.Changeset.change(status: :suspended) |> Repo.update!()

    forbidden =
      renewal_conn()
      |> post("/v1/pki/app/renew", renewal_wire_request(forbidden_fixture))

    assert json_response(forbidden, 403) == %{"error" => "FORBIDDEN"}

    revoked_fixture = renewal_fixture!()

    revoked_fixture.current.cert_record
    |> Certificate.revoke_changeset("compromised")
    |> Repo.update!()

    revoked =
      renewal_conn()
      |> post("/v1/pki/app/renew", renewal_wire_request(revoked_fixture))

    assert json_response(revoked, 401) == %{"error" => "INVALID_CERTIFICATE"}
  end

  test "application renewal exposes stable conflict and availability errors" do
    conflict_fixture = renewal_fixture!()
    request = renewal_wire_request(conflict_fixture)

    renewal_conn()
    |> post("/v1/pki/app/renew", request)
    |> json_response(200)

    conflict =
      renewal_conn()
      |> post(
        "/v1/pki/app/renew",
        Map.put(request, "proof", Base.encode64("changed-proof"))
      )

    assert json_response(conflict, 409) == %{"error" => "IDEMPOTENCY_CONFLICT"}

    unavailable_fixture = renewal_fixture!()

    Certificate
    |> Repo.all()
    |> Enum.filter(&(&1.cert_type in [:root_ca, :intermediate_ca]))
    |> Enum.each(fn ca ->
      ca
      |> Certificate.revoke_changeset("test_unavailable")
      |> Repo.update!()
    end)

    unavailable =
      renewal_conn()
      |> post("/v1/pki/app/renew", renewal_wire_request(unavailable_fixture))

    assert json_response(unavailable, 503) == %{"error" => "UNAVAILABLE"}
  end

  test "application renewal hides internal failure and proof details" do
    fixture = renewal_fixture!()
    request = renewal_wire_request(fixture)
    fault_key = :secrethub_app_certificate_renewal_fault

    log =
      ExUnit.CaptureLog.capture_log(fn ->
        Process.put(fault_key, :before_original_revocation)

        try do
          response =
            renewal_conn()
            |> post("/v1/pki/app/renew", request)

          assert json_response(response, 500) == %{"error" => "UNAVAILABLE"}
        after
          Process.delete(fault_key)
        end
      end)

    refute Process.get(fault_key)
    refute log =~ request["csr"]
    refute log =~ request["proof"]
    refute log =~ fixture.replacement_csr
  end

  test "application renewal has a distinct direct-peer rate limit that ignores forwarded IPs" do
    direct_ip = {203, 0, 113, 250}

    request = %{
      "app_id" => Ecto.UUID.generate(),
      "current_fingerprint" => String.duplicate("0", 64),
      "csr" => Base.encode64("not-a-csr"),
      "request_id" => Ecto.UUID.generate(),
      "signature_algorithm" => "rsa-pss-sha256",
      "proof" => Base.encode64("not-a-proof")
    }

    Enum.each(1..5, fn attempt ->
      response =
        direct_ip
        |> renewal_conn()
        |> put_req_header("x-forwarded-for", "198.51.100.#{attempt}")
        |> post(
          "/v1/pki/app/renew",
          Map.put(request, "request_id", Ecto.UUID.generate())
        )

      assert response.status == 403
    end)

    limited =
      direct_ip
      |> renewal_conn()
      |> put_req_header("x-forwarded-for", "192.0.2.99")
      |> post(
        "/v1/pki/app/renew",
        Map.put(request, "request_id", Ecto.UUID.generate())
      )

    assert limited.status == 429
  end

  test "an Agent Vault token cannot access administrative app-certificate revocation" do
    fixture = renewal_fixture!()

    response =
      vault_token!()
      |> authed_conn()
      |> post("/v1/pki/app/revoke", %{
        "app_id" => fixture.app.id,
        "reason" => "operator_revoked"
      })

    assert redirected_to(response, 302) == "/admin/auth/login"
    assert Repo.get!(Certificate, fixture.current.cert_record.id).revoked == false
  end

  test "an Agent Vault token cannot revoke an app certificate through generic PKI" do
    fixture = renewal_fixture!()

    response =
      vault_token!()
      |> authed_conn()
      |> post("/v1/pki/certificates/#{fixture.current.cert_record.id}/revoke", %{
        "reason" => "keyCompromise"
      })

    assert json_response(response, 403) == %{"error" => "FORBIDDEN"}

    assert %Certificate{revoked: false, revoked_at: nil, revocation_reason: nil} =
             Repo.get!(Certificate, fixture.current.cert_record.id)

    assert %AppCertificate{revoked_at: nil, revocation_reason: nil} =
             Repo.get!(AppCertificate, fixture.current.app_certificate.id)
  end

  test "an authenticated admin can revoke application certificates" do
    fixture = renewal_fixture!()

    response =
      Phoenix.ConnTest.build_conn()
      |> init_test_session(%{admin_id: "test-admin"})
      |> post("/v1/pki/app/revoke", %{
        "app_id" => fixture.app.id,
        "reason" => "operator_revoked"
      })
      |> json_response(200)

    assert response == %{
             "message" => "Application certificates revoked",
             "revoked_count" => 1
           }

    assert %Certificate{revoked: true, revocation_reason: "operator_revoked"} =
             Repo.get!(Certificate, fixture.current.cert_record.id)
  end

  test "administrative revocation rejects and never logs a raw reason" do
    fixture = renewal_fixture!()
    private_reason = "private\nrevocation\treason"

    log =
      ExUnit.CaptureLog.capture_log(fn ->
        response =
          Phoenix.ConnTest.build_conn()
          |> init_test_session(%{admin_id: "test-admin"})
          |> post("/v1/pki/app/revoke", %{
            "app_id" => fixture.app.id,
            "reason" => private_reason
          })

        assert json_response(response, 400) == %{
                 "error" => "INVALID_REVOCATION_REASON"
               }
      end)

    refute log =~ private_reason
    assert Repo.get!(Certificate, fixture.current.cert_record.id).revoked == false
  end

  test "application certificate issuance maps an invalid request ID" do
    {_private_key, csr_pem} = new_csr("invalid-request-id")

    response =
      bootstrap_conn()
      |> post("/v1/pki/app/issue", %{
        "token" => "hvs.invalid-bootstrap-token",
        "csr" => csr_pem,
        "request_id" => "not-a-uuid"
      })

    assert json_response(response, 400) == %{"error" => "INVALID_REQUEST_ID"}
  end

  test "application certificate issuance maps an invalid CSR" do
    %{token: token} = bootstrap_issuance_fixture!()

    response =
      bootstrap_conn()
      |> post("/v1/pki/app/issue", %{
        "token" => token,
        "csr" => "private-malformed-csr",
        "request_id" => Ecto.UUID.generate()
      })

    assert json_response(response, 400) == %{"error" => "INVALID_CSR"}
  end

  test "application certificate issuance maps an unsupported key" do
    %{token: token} = bootstrap_issuance_fixture!()
    private_key = X509.PrivateKey.new_rsa(1024)
    csr_pem = private_key |> X509.CSR.new("/CN=small-rsa") |> X509.CSR.to_pem()

    response =
      bootstrap_conn()
      |> post("/v1/pki/app/issue", %{
        "token" => token,
        "csr" => csr_pem,
        "request_id" => Ecto.UUID.generate()
      })

    assert json_response(response, 400) == %{"error" => "UNSUPPORTED_KEY"}
  end

  test "application certificate issuance rejects an invalid Agent assignment" do
    %{token: token, csr: csr_pem} =
      bootstrap_issuance_fixture!(agent_status: :suspended)

    response =
      bootstrap_conn()
      |> post("/v1/pki/app/issue", %{
        "token" => token,
        "csr" => csr_pem,
        "request_id" => Ecto.UUID.generate()
      })

    assert json_response(response, 403) == %{"error" => "INVALID_AGENT_ASSIGNMENT"}
  end

  test "application certificate issuance hides CA details when no CA is available" do
    %{token: token, csr: csr_pem} = bootstrap_issuance_fixture!(with_ca: false)

    response =
      bootstrap_conn()
      |> post("/v1/pki/app/issue", %{
        "token" => token,
        "csr" => csr_pem,
        "request_id" => Ecto.UUID.generate()
      })

    assert json_response(response, 503) == %{"error" => "ISSUANCE_FAILED"}
  end

  test "application certificate issuance maps an internal issuance failure without leaking the token" do
    %{token: token, csr: csr_pem} = bootstrap_issuance_fixture!()
    fault_key = :secrethub_app_certificate_issuance_fault

    log =
      ExUnit.CaptureLog.capture_log(fn ->
        Process.put(fault_key, :before_certificate_insert)

        try do
          response =
            bootstrap_conn()
            |> post("/v1/pki/app/issue", %{
              "token" => token,
              "csr" => csr_pem,
              "request_id" => Ecto.UUID.generate()
            })

          assert json_response(response, 500) == %{"error" => "ISSUANCE_FAILED"}
        after
          Process.delete(fault_key)
        end
      end)

    refute Process.get(fault_key)
    refute log =~ token
  end

  test "application certificate issuance requires exactly the three public fields" do
    {_private_key, csr_pem} = new_csr("request-shape")

    request = %{
      "token" => "hvs.invalid-bootstrap-token",
      "csr" => csr_pem,
      "request_id" => Ecto.UUID.generate()
    }

    for required_field <- Map.keys(request) do
      response =
        bootstrap_conn()
        |> post("/v1/pki/app/issue", Map.delete(request, required_field))

      assert json_response(response, 400) == %{"error" => "INVALID_REQUEST"}

      blank_response =
        bootstrap_conn()
        |> post("/v1/pki/app/issue", Map.put(request, required_field, ""))

      assert json_response(blank_response, 400) == %{"error" => "INVALID_REQUEST"}
    end

    for {unexpected_field, value} <- [
          {"app_id", Ecto.UUID.generate()},
          {"app_token", "legacy-bootstrap-token"},
          {"ttl", 86_400},
          {"metadata", %{"private" => "value"}},
          {"proof", "private-proof"},
          {"signature", "private-signature"}
        ] do
      response =
        bootstrap_conn()
        |> post("/v1/pki/app/issue", Map.put(request, unexpected_field, value))

      assert json_response(response, 400) == %{"error" => "INVALID_REQUEST"}
    end

    legacy_response =
      bootstrap_conn()
      |> post("/v1/pki/app/issue", %{
        "app_id" => Ecto.UUID.generate(),
        "app_token" => "legacy-bootstrap-token",
        "csr" => csr_pem,
        "ttl" => 86_400,
        "metadata" => %{"private" => "value"}
      })

    assert json_response(legacy_response, 400) == %{"error" => "INVALID_REQUEST"}
  end

  test "application certificate issuance returns and replays a Core-owned certificate" do
    %{token: token, csr: csr_pem} = bootstrap_issuance_fixture!()
    request_id = Ecto.UUID.generate()

    request = %{
      "token" => token,
      "csr" => csr_pem,
      "request_id" => request_id
    }

    issued =
      bootstrap_conn()
      |> post("/v1/pki/app/issue", request)
      |> json_response(200)

    assert %{
             "certificate" => certificate,
             "ca_chain" => [ca_certificate | _],
             "serial_number" => serial_number,
             "expires_at" => expires_at,
             "issued_at" => issued_at,
             "replayed" => false
           } = issued

    assert Map.keys(issued) |> Enum.sort() ==
             ~w(ca_chain certificate expires_at issued_at replayed serial_number)

    assert certificate =~ "-----BEGIN CERTIFICATE-----"
    assert ca_certificate =~ "-----BEGIN CERTIFICATE-----"
    assert is_binary(serial_number)
    assert is_binary(expires_at)
    assert is_binary(issued_at)
    refute Map.has_key?(issued, "ttl")

    replayed =
      bootstrap_conn()
      |> put_req_header("x-vault-token", "ignored-vault-token")
      |> post("/v1/pki/app/issue", request)
      |> json_response(200)

    assert replayed == %{issued | "replayed" => true}
  end

  test "application certificate issuance does not log private request or response material" do
    %{token: token, csr: csr_pem} = bootstrap_issuance_fixture!()
    %{token: malformed_token} = bootstrap_issuance_fixture!(with_ca: false)
    request_id = Ecto.UUID.generate()
    malformed_csr = "private-malformed-csr-#{System.unique_integer([:positive])}"
    proof = "private-proof-#{System.unique_integer([:positive])}"
    signature = "private-signature-#{System.unique_integer([:positive])}"
    test_process = self()

    log =
      ExUnit.CaptureLog.capture_log(fn ->
        issued =
          bootstrap_conn()
          |> post("/v1/pki/app/issue", %{
            "token" => token,
            "csr" => csr_pem,
            "request_id" => request_id
          })
          |> json_response(200)

        send(test_process, {:issued_certificate, issued})

        invalid_csr_response =
          bootstrap_conn()
          |> post("/v1/pki/app/issue", %{
            "token" => malformed_token,
            "csr" => malformed_csr,
            "request_id" => Ecto.UUID.generate()
          })

        assert json_response(invalid_csr_response, 400) == %{"error" => "INVALID_CSR"}

        rejected_private_fields =
          bootstrap_conn()
          |> post("/v1/pki/app/issue", %{
            "token" => "private-unexpected-token",
            "csr" => csr_pem,
            "request_id" => Ecto.UUID.generate(),
            "proof" => proof,
            "signature" => signature
          })

        assert json_response(rejected_private_fields, 400) == %{"error" => "INVALID_REQUEST"}
      end)

    assert_receive {:issued_certificate, %{"certificate" => certificate, "ca_chain" => ca_chain}}

    pem_values = [csr_pem, certificate | ca_chain]
    encoded_pem_markers = Enum.flat_map(pem_values, &pem_log_leak_markers/1)

    for private_value <-
          [
            token,
            malformed_token,
            "private-unexpected-token",
            malformed_csr,
            proof,
            signature
          ] ++
            pem_values ++ encoded_pem_markers do
      refute log =~ private_value
    end
  end

  test "application certificate issuance rejects a different request ID after issuance" do
    %{token: token, csr: csr_pem} = bootstrap_issuance_fixture!()

    issued_request = %{
      "token" => token,
      "csr" => csr_pem,
      "request_id" => Ecto.UUID.generate()
    }

    bootstrap_conn()
    |> post("/v1/pki/app/issue", issued_request)
    |> json_response(200)

    conflict_response =
      bootstrap_conn()
      |> post("/v1/pki/app/issue", %{
        issued_request
        | "request_id" => Ecto.UUID.generate()
      })

    assert json_response(conflict_response, 409) == %{"error" => "IDEMPOTENCY_CONFLICT"}
  end

  defp vault_token! do
    unique = System.unique_integer([:positive])

    {:ok, agent} =
      %Agent{}
      |> Agent.changeset(%{
        agent_id: "pki-web-agent-#{unique}",
        name: "PKI Web Agent #{unique}",
        status: :active,
        ip_address: "127.0.0.1",
        metadata: %{}
      })
      |> Repo.insert()

    Phoenix.Token.sign(SecretHub.Web.Endpoint, "agent_auth", %{
      agent_db_id: agent.id,
      agent_id: agent.agent_id
    })
  end

  defp authed_conn(token) do
    Phoenix.ConnTest.build_conn()
    |> Plug.Conn.put_req_header("x-vault-token", token)
  end

  defp bootstrap_conn do
    client = rem(System.unique_integer([:positive]), 250) + 1

    conn = Phoenix.ConnTest.build_conn()
    %{conn | remote_ip: {198, 51, 100, client}}
  end

  defp renewal_conn(remote_ip \\ nil) do
    remote_ip =
      remote_ip ||
        {203, 0, 113, rem(System.unique_integer([:positive]), 250) + 1}

    conn = Phoenix.ConnTest.build_conn()
    %{conn | remote_ip: remote_ip}
  end

  defp new_csr(common_name) do
    private_key = X509.PrivateKey.new_rsa(2048)
    csr = X509.CSR.new(private_key, "/O=SecretHub Web Test/CN=#{common_name}")

    {private_key, X509.CSR.to_pem(csr)}
  end

  defp pem_log_leak_markers(pem) do
    body =
      pem
      |> String.split("\n", trim: true)
      |> Enum.reject(&String.starts_with?(&1, "-----"))
      |> Enum.join()

    [
      String.slice(body, 0, 32),
      String.slice(body, -32, 32),
      String.replace(pem, "\n", "\\n"),
      inspect(pem, printable_limit: :infinity, limit: :infinity),
      Jason.encode!(pem)
    ]
  end

  defp bootstrap_issuance_fixture!(opts \\ []) do
    unique = System.unique_integer([:positive])

    if Keyword.get(opts, :with_ca, true) do
      {:ok, _ca} =
        CA.generate_root_ca(
          "Web App Issuance Root #{unique}",
          "SecretHub Web Test",
          key_size: 2048
        )
    end

    {:ok, agent} =
      %Agent{}
      |> Agent.changeset(%{
        agent_id: "web-app-issuance-agent-#{unique}",
        name: "Web App Issuance Agent #{unique}",
        status: Keyword.get(opts, :agent_status, :active)
      })
      |> Repo.insert()

    {:ok, %{token: token}} =
      Apps.register_app(%{
        name: "web-app-issuance-#{unique}",
        agent_id: agent.id
      })

    {_private_key, csr_pem} = new_csr("hostile-client-controlled-identity")

    %{token: token, csr: csr_pem}
  end

  defp renewal_fixture! do
    unique = System.unique_integer([:positive])

    {:ok, _ca} =
      CA.generate_root_ca(
        "Web App Renewal Root #{unique}",
        "SecretHub Web Test",
        key_size: 2048
      )

    {:ok, agent} =
      %Agent{}
      |> Agent.changeset(%{
        agent_id: "web-app-renewal-agent-#{unique}",
        name: "Web App Renewal Agent #{unique}",
        status: :active
      })
      |> Repo.insert()

    {:ok, %{app: app, token: token}} =
      Apps.register_app(%{
        name: "web-app-renewal-#{unique}",
        agent_id: agent.id
      })

    current_key = X509.PrivateKey.new_rsa(2048)
    current_csr = current_key |> X509.CSR.new("/CN=current") |> X509.CSR.to_pem()

    {:ok, current} =
      AppCertificates.issue_from_bootstrap(token, current_csr, Ecto.UUID.generate())

    {_replacement_key, replacement_csr} = new_csr("replacement")

    %{
      app: app,
      agent: agent,
      current: current,
      current_key: current_key,
      replacement_csr: replacement_csr
    }
  end

  defp renewal_wire_request(fixture, request_id \\ Ecto.UUID.generate()) do
    fingerprint = fixture.current.cert_record.canonical_fingerprint

    {:ok, payload} =
      AppCertificates.renewal_signing_payload(
        fixture.app.id,
        fingerprint,
        fixture.replacement_csr,
        request_id
      )

    proof =
      :public_key.sign(payload, :sha256, fixture.current_key,
        rsa_padding: :rsa_pkcs1_pss_padding,
        rsa_pss_saltlen: 32,
        rsa_mgf1_md: :sha256
      )

    %{
      "app_id" => fixture.app.id,
      "current_fingerprint" => fingerprint,
      "csr" => Base.encode64(fixture.replacement_csr),
      "request_id" => request_id,
      "signature_algorithm" => "rsa-pss-sha256",
      "proof" => Base.encode64(proof)
    }
  end

  defp unique_name(prefix) do
    "#{prefix}-#{System.unique_integer([:positive])}"
  end

  defp cleanup_rate_limit_entries(scope) do
    case :ets.whereis(@rate_limiter_table) do
      :undefined -> :ok
      _table -> :ets.match_delete(@rate_limiter_table, {{scope, :_}, :_, :_})
    end
  end
end
