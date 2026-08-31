defmodule SecretHub.Core.PKI.ClientAuthE2ETest do
  use ExUnit.Case, async: false

  alias SecretHub.Agent.PKI.TrustBundleManager
  alias SecretHub.Core.PKI.ClientAuth
  alias SecretHub.Core.Repo

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)

    tmp_dir = Path.join(System.tmp_dir!(), "secrethub_e2e_#{System.unique_integer([:positive])}")
    File.mkdir_p!(tmp_dir)

    on_exit(fn ->
      File.rm_rf!(tmp_dir)
    end)

    %{tmp_dir: tmp_dir}
  end

  test "end-to-end client auth PKI lifecycle: authority init -> identity -> cert issuance -> agent distribution -> atomic store -> revocation -> CRL update",
       %{tmp_dir: tmp_dir} do
    # 1. Authority Initialization
    init_attrs = %{
      name: "SecretHub Production Client Auth CA",
      key_algorithm: "ecdsa_p384",
      default_ttl_seconds: 2_592_000,
      max_ttl_seconds: 7_776_000
    }

    assert {:ok, init_res} = ClientAuth.init_authority(init_attrs)
    assert init_res.authority.slug == "client-auth"
    assert init_res.authority.status == "active"
    assert init_res.authority.current_generation == 1
    assert init_res.authority.current_crl_number == 1

    # 2. Public Trust Bundle Retrieval
    assert {:ok, bundle_gen1} = ClientAuth.current_bundle()
    assert bundle_gen1["schema_version"] == 1
    assert bundle_gen1["generation"] == 1
    assert bundle_gen1["crl_number"] == 1
    assert is_binary(bundle_gen1["bundle_sha256"])
    assert is_binary(bundle_gen1["ca_bundle_pem"])
    assert is_binary(bundle_gen1["crl_pem"])

    # 3. Create Client Identity
    assert {:ok, identity} =
             ClientAuth.create_identity(%{
               name: "payment-gateway-worker",
               metadata: %{"env" => "prod", "service" => "payments"}
             })

    assert identity.name == "payment-gateway-worker"
    assert identity.status == "active"
    assert is_binary(identity.id)

    # 4. Generate Client Key & CSR, Issue Client Certificate
    client_key = X509.PrivateKey.new_ec(:secp384r1)
    csr = X509.CSR.new(client_key, "/O=Custom/CN=custom")
    csr_pem = X509.CSR.to_pem(csr)
    request_id = Ecto.UUID.generate()

    assert {:ok, issuance_res} =
             ClientAuth.issue_certificate(
               identity.id,
               csr_pem,
               request_id,
               ttl_seconds: 86_400
             )

    _cert_pem = issuance_res.certificate
    cert_record = issuance_res.cert_record
    assert cert_record.common_name == identity.id
    assert cert_record.subject == "O=SecretHub Client Authentication, CN=#{identity.id}"
    assert cert_record.metadata["san_uri"] == ["urn:secrethub:client:#{identity.id}"]
    assert cert_record.metadata["extended_key_usage"] == ["clientAuth"]
    refute issuance_res.replayed

    # 5. Idempotent Reissue with same request_id
    assert {:ok, replay_res} =
             ClientAuth.issue_certificate(
               identity.id,
               csr_pem,
               request_id,
               ttl_seconds: 86_400
             )

    assert replay_res.replayed
    assert replay_res.cert_record.id == cert_record.id

    # 6. Agent receives bundle, validates, and stores atomically
    {:ok, agent_bundle_mgr} =
      TrustBundleManager.start_link(
        state_dir: tmp_dir,
        agent_id: "agent-node-prod-01",
        name: :e2e_agent_bundle_manager
      )

    assert {:ok, receipt1} = TrustBundleManager.process_bundle(agent_bundle_mgr, bundle_gen1)
    assert receipt1["status"] == "applied"
    assert receipt1["generation"] == 1

    # Verify atomic disk structure
    base_dir = Path.join(tmp_dir, "pki/client-auth")
    current_symlink = Path.join(base_dir, "current")
    assert {:ok, "generations/1"} = File.read_link(current_symlink)
    assert File.exists?(Path.join([base_dir, "generations", "1", "ca.crt"]))
    assert File.exists?(Path.join([base_dir, "generations", "1", "crl.pem"]))
    assert File.exists?(Path.join([base_dir, "generations", "1", "manifest.json"]))

    # 7. Agent reports receipt back to Core
    assert {:ok, db_receipt} = ClientAuth.record_bundle_receipt(receipt1)
    assert db_receipt.agent_id == "agent-node-prod-01"
    assert db_receipt.generation == 1
    assert db_receipt.status == "applied"

    # 8. Certificate Revocation
    assert {:ok, revocation_res} =
             ClientAuth.revoke_certificate(
               cert_record.id,
               "keyCompromise"
             )

    assert revocation_res.generation == 2
    assert revocation_res.crl_number == 2
    assert revocation_res.certificate.revoked == true
    assert revocation_res.certificate.revocation_reason == "keyCompromise"

    # 9. Updated Trust Bundle Generation 2
    assert {:ok, bundle_gen2} = ClientAuth.current_bundle()
    assert bundle_gen2["generation"] == 2
    assert bundle_gen2["crl_number"] == 2

    # 10. Agent processes Generation 2 bundle
    assert {:ok, receipt2} = TrustBundleManager.process_bundle(agent_bundle_mgr, bundle_gen2)
    assert receipt2["status"] == "applied"
    assert receipt2["generation"] == 2

    assert {:ok, "generations/2"} = File.read_link(current_symlink)
    assert File.exists?(Path.join([base_dir, "generations", "2", "ca.crt"]))
    assert File.exists?(Path.join([base_dir, "generations", "2", "crl.pem"]))

    # 11. Core records updated agent receipt
    assert {:ok, db_receipt2} = ClientAuth.record_bundle_receipt(receipt2)
    assert db_receipt2.generation == 2
    assert db_receipt2.status == "applied"
  end
end
