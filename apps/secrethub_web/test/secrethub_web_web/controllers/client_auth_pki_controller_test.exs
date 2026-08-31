defmodule SecretHub.Web.ClientAuthPKIControllerTest do
  use SecretHub.Web.ConnCase, async: false

  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.Agent

  setup do
    token = vault_token!()
    {:ok, token: token}
  end

  test "public endpoint GET /v1/pki/client-auth/bundle returns 503 before init", %{conn: conn} do
    resp = get(conn, "/v1/pki/client-auth/bundle")
    assert response(resp, 503)
  end

  test "POST /v1/pki/client-auth/authority/init initializes CA authority and enables bundle downloads",
       %{conn: conn, token: token} do
    authed = authed_conn(conn, token)

    # 1. Initialize Authority
    init_params = %{
      "name" => "Client Authentication CA",
      "key_algorithm" => "ecdsa_p384",
      "default_ttl_seconds" => 2_592_000,
      "max_ttl_seconds" => 7_776_000
    }

    init_resp = post(authed, "/v1/pki/client-auth/authority/init", init_params)
    assert json_response(init_resp, 201)["data"]["slug"] == "client-auth"
    assert json_response(init_resp, 201)["data"]["status"] == "active"
    assert json_response(init_resp, 201)["data"]["current_generation"] == 1

    # Conflict on duplicate init
    conflict_resp = post(authed, "/v1/pki/client-auth/authority/init", init_params)
    assert json_response(conflict_resp, 409)["error"] =~ "already initialized"

    # 2. GET /v1/pki/client-auth/authority/status
    status_resp = get(conn, "/v1/pki/client-auth/authority/status")
    status_data = json_response(status_resp, 200)["data"]
    assert status_data["status"] == "active"
    assert status_data["current_generation"] == 1

    # 3. GET /v1/pki/client-auth/bundle (public)
    bundle_resp = get(conn, "/v1/pki/client-auth/bundle")
    bundle_data = json_response(bundle_resp, 200)["data"]
    assert bundle_data["schema_version"] == 1
    assert bundle_data["generation"] == 1
    assert is_binary(bundle_data["ca_bundle_pem"])
    assert is_binary(bundle_data["crl_pem"])
    assert is_binary(bundle_data["bundle_sha256"])

    # 4. Create Identity
    identity_params = %{
      "name" => "backend-service-prod",
      "metadata" => %{"team" => "platform"}
    }

    id_resp = post(authed, "/v1/pki/client-auth/identities", identity_params)
    assert json_response(id_resp, 201)["data"]["name"] == "backend-service-prod"
    identity_id = json_response(id_resp, 201)["data"]["id"]

    # 5. List Identities
    list_id_resp = get(authed, "/v1/pki/client-auth/identities")
    identities = json_response(list_id_resp, 200)["data"]
    assert Enum.any?(identities, &(&1["id"] == identity_id))

    # 6. Issue Certificate with valid CSR
    client_key = X509.PrivateKey.new_ec(:secp384r1)
    csr = X509.CSR.new(client_key, "/O=Custom/CN=custom")
    csr_pem = X509.CSR.to_pem(csr)

    issue_params = %{
      "identity_id" => identity_id,
      "csr_pem" => csr_pem,
      "ttl_seconds" => 86_400
    }

    issue_resp = post(authed, "/v1/pki/client-auth/issue", issue_params)
    cert_data = json_response(issue_resp, 201)["data"]
    assert is_binary(cert_data["certificate_pem"])
    assert is_binary(cert_data["serial_number"])
    cert_id = cert_data["cert_id"]

    # 7. List Certificates
    list_cert_resp = get(authed, "/v1/pki/client-auth/certificates")
    certs = json_response(list_cert_resp, 200)["data"]
    assert Enum.any?(certs, &(&1["id"] == cert_id))

    # 8. Revoke Certificate
    revoke_params = %{"reason" => "keyCompromise"}

    revoke_resp =
      post(authed, "/v1/pki/client-auth/certificates/#{cert_id}/revoke", revoke_params)

    assert json_response(revoke_resp, 200)["data"]["revoked"] == true

    # Bundle generation bumped to 2
    bundle_resp2 = get(conn, "/v1/pki/client-auth/bundle")
    bundle_data2 = json_response(bundle_resp2, 200)["data"]
    assert bundle_data2["generation"] == 2

    # 9. Disable Identity
    disable_resp = post(authed, "/v1/pki/client-auth/identities/#{identity_id}/disable", %{})
    assert json_response(disable_resp, 200)["data"]["status"] == "disabled"

    # 10. Force CRL Refresh
    refresh_resp = post(authed, "/v1/pki/client-auth/crl/refresh", %{})
    assert json_response(refresh_resp, 200)["data"]["generation"] >= 2

    # 11. Agent Receipt logging
    receipt_params = %{
      "agent_id" => "agent-host-1",
      "generation" => 2,
      "crl_number" => 2,
      "bundle_sha256" => bundle_data2["bundle_sha256"],
      "status" => "applied",
      "applied_at" => DateTime.utc_now() |> DateTime.to_iso8601()
    }

    receipt_resp = post(authed, "/v1/pki/client-auth/bundle/receipt", receipt_params)
    assert json_response(receipt_resp, 200)["data"]["agent_id"] == "agent-host-1"

    receipts_list_resp = get(authed, "/v1/pki/client-auth/bundle/receipts")
    assert length(json_response(receipts_list_resp, 200)["data"]) >= 1
  end

  defp vault_token! do
    unique = System.unique_integer([:positive])

    {:ok, agent} =
      %Agent{}
      |> Agent.changeset(%{
        agent_id: "pki-client-auth-test-agent-#{unique}",
        name: "Client Auth Test Agent #{unique}",
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

  defp authed_conn(conn, token) do
    put_req_header(conn, "x-vault-token", token)
  end
end
