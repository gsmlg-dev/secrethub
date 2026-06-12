defmodule SecretHub.Web.AgentEnrollmentControllerTest do
  use SecretHub.Web.ConnCase, async: true

  alias SecretHub.Core.Agents.Enrollment
  alias SecretHub.Core.PKI.{CA, CSR}
  alias SecretHub.Shared.Crypto.AgentCSRProof
  alias X509.Certificate.Extension

  @pending_attrs %{
    hostname: "build-01",
    fqdn: "build-01.internal.example",
    machine_id: "machine-123",
    os: "linux",
    arch: "x86_64",
    agent_version: "1.2.3",
    ssh_host_key_algorithm: "rsa",
    capabilities: %{"templates" => true}
  }

  test "POST /v1/agent/enrollments/:id/csr forwards ssh_proof for certificate issuance", %{
    conn: conn
  } do
    generate_active_ca!()

    ssh_private_key = :public_key.generate_key({:rsa, 2048, 65_537})
    ssh_public_key = :ssh_file.extract_public_key(ssh_private_key)
    tls_private_key = :public_key.generate_key({:rsa, 2048, 65_537})

    {:ok, %{enrollment: enrollment, pending_token: pending_token}} =
      @pending_attrs
      |> Map.put(:machine_id, "controller-csr-#{System.unique_integer([:positive])}")
      |> Map.put(:ssh_host_key_fingerprint, CSR.ssh_fingerprint(ssh_public_key))
      |> Map.put(:ssh_host_public_key, openssh_public_key(ssh_public_key))
      |> Enrollment.create_pending("203.0.113.10")

    {:ok, approved} = Enrollment.approve(enrollment.id, "operator-1")
    csr_pem = csr_pem_for_required_fields(tls_private_key, approved.required_csr_fields)

    proof =
      AgentCSRProof.sign(ssh_private_key, %{
        enrollment_id: approved.id,
        challenge: approved.required_csr_fields["challenge"],
        csr_pem: csr_pem
      })

    conn =
      conn
      |> put_req_header("authorization", "Bearer #{pending_token}")
      |> post("/v1/agent/enrollments/#{approved.id}/csr", %{
        "csr_pem" => csr_pem,
        "ssh_proof" => proof
      })

    response = json_response(conn, 200)

    assert response["agent_id"] == approved.agent_id
    assert response["certificate_pem"] =~ "BEGIN CERTIFICATE"
    assert response["connect_info_url"] == "/v1/agent/enrollments/#{approved.id}/connect-info"
  end

  defp generate_active_ca! do
    {:ok, %{cert_record: cert}} =
      CA.generate_root_ca(
        "Agent Enrollment Controller Test Root CA #{System.unique_integer([:positive])}",
        "SecretHub Test",
        key_size: 2048
      )

    cert
  end

  defp openssh_public_key(public_key) do
    [{public_key, []}]
    |> :ssh_file.encode(:openssh_key)
    |> IO.iodata_to_binary()
    |> String.trim()
  end

  defp csr_pem_for_required_fields(private_key, required_fields) do
    required_fields
    |> csr_for_required_fields(private_key)
    |> X509.CSR.to_pem()
  end

  defp csr_for_required_fields(required_fields, private_key) do
    subject = required_fields["subject"]
    sans = required_fields["san"] || %{}

    uri_sans =
      sans
      |> Map.get("uri", [])
      |> List.wrap()
      |> Enum.map(&{:uniformResourceIdentifier, to_charlist(&1)})

    dns_sans =
      sans
      |> Map.get("dns", [])
      |> List.wrap()
      |> Enum.map(&{:dNSName, to_charlist(&1)})

    X509.CSR.new(private_key, [{"O", subject["O"]}, {"CN", subject["CN"]}],
      extension_request: [
        Extension.subject_alt_name(uri_sans ++ dns_sans),
        Extension.key_usage([:digitalSignature]),
        Extension.ext_key_usage([:clientAuth])
      ]
    )
  end
end
