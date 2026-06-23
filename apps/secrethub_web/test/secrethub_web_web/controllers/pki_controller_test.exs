defmodule SecretHub.Web.PKIControllerTest do
  use SecretHub.Web.ConnCase, async: true

  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.{Agent, Certificate}

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
        "cert_type" => "app_client",
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
    assert service_record.cert_type == :app_client
    assert service_record.issuer_id == intermediate_response["cert_id"]
    assert service_record.revoked == false

    list_response =
      token
      |> authed_conn()
      |> get("/v1/pki/certificates", %{"cert_type" => "app_client", "revoked" => "false"})
      |> json_response(200)

    assert Enum.any?(list_response["certificates"], &(&1["id"] == signed_response["cert_id"]))

    detail_response =
      token
      |> authed_conn()
      |> get("/v1/pki/certificates/#{signed_response["cert_id"]}")
      |> json_response(200)

    assert detail_response["id"] == signed_response["cert_id"]
    assert detail_response["common_name"] == service_cn
    assert detail_response["cert_type"] == "app_client"
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

  defp new_csr(common_name) do
    private_key = X509.PrivateKey.new_rsa(2048)
    csr = X509.CSR.new(private_key, "/O=SecretHub Web Test/CN=#{common_name}")

    {private_key, X509.CSR.to_pem(csr)}
  end

  defp unique_name(prefix) do
    "#{prefix}-#{System.unique_integer([:positive])}"
  end
end
