defmodule SecretHub.Agent.PKIBundleTest do
  use ExUnit.Case, async: true

  alias SecretHub.Agent.PKI.{AtomicStore, BundleValidator, TrustBundleManager}

  setup do
    tmp_dir =
      Path.join(System.tmp_dir!(), "secrethub_pki_test_#{System.unique_integer([:positive])}")

    File.mkdir_p!(tmp_dir)

    on_exit(fn ->
      File.rm_rf!(tmp_dir)
    end)

    # Generate a valid test CA and signed CRL
    ca_key = X509.PrivateKey.new_ec(:secp384r1)
    ca_cert = X509.Certificate.self_signed(ca_key, "/O=SecretHub/CN=Test CA", template: :root_ca)
    ca_pem = X509.Certificate.to_pem(ca_cert)
    ca_der = X509.Certificate.to_der(ca_cert)
    ca_fingerprint = :crypto.hash(:sha256, ca_der) |> Base.encode16(case: :lower)

    now = DateTime.utc_now() |> DateTime.truncate(:second)
    this_update = DateTime.add(now, -300, :second)
    next_update = DateTime.add(now, 48 * 3600, :second)

    crl =
      X509.CRL.new(
        [],
        ca_cert,
        ca_key,
        this_update: this_update,
        next_update: next_update,
        extensions: [crl_number: X509.CRL.Extension.crl_number(1)]
      )

    crl_pem = X509.CRL.to_pem(crl)
    crl_der = X509.CRL.to_der(crl)
    crl_der_sha256 = :crypto.hash(:sha256, crl_der) |> Base.encode16(case: :lower)

    valid_bundle = %{
      "schema_version" => 1,
      "authority" => "client-auth",
      "generation" => 1,
      "crl_number" => 1,
      "ca_fingerprint" => ca_fingerprint,
      "crl_der_sha256" => crl_der_sha256,
      "this_update" => DateTime.to_iso8601(this_update),
      "next_update" => DateTime.to_iso8601(next_update),
      "ca_bundle_pem" => ca_pem,
      "crl_pem" => crl_pem
    }

    transcript =
      [
        valid_bundle["schema_version"],
        valid_bundle["authority"],
        valid_bundle["generation"],
        valid_bundle["ca_fingerprint"],
        valid_bundle["crl_number"],
        valid_bundle["crl_der_sha256"],
        valid_bundle["this_update"],
        valid_bundle["next_update"],
        valid_bundle["ca_bundle_pem"],
        valid_bundle["crl_pem"]
      ]
      |> Enum.map(&to_string/1)
      |> Enum.join("|")

    bundle_sha256 = :crypto.hash(:sha256, transcript) |> Base.encode16(case: :lower)
    valid_bundle = Map.put(valid_bundle, "bundle_sha256", bundle_sha256)

    %{
      tmp_dir: tmp_dir,
      bundle: valid_bundle,
      ca_key: ca_key,
      ca_cert: ca_cert,
      now: now
    }
  end

  describe "BundleValidator" do
    test "validates a correct trust bundle", %{bundle: bundle, now: now} do
      assert {:ok, validated} = BundleValidator.validate(bundle, now: now)
      assert validated.generation == 1
      assert validated.crl_number == 1
      assert validated.bundle_sha256 == bundle["bundle_sha256"]
    end

    test "rejects invalid schema version", %{bundle: bundle, now: now} do
      invalid = Map.put(bundle, "schema_version", 2)
      assert {:error, :invalid_schema_version, _} = BundleValidator.validate(invalid, now: now)
    end

    test "rejects tampered bundle transcript", %{bundle: bundle, now: now} do
      invalid = Map.put(bundle, "crl_number", 999)
      assert {:error, :transcript_hash_mismatch, _} = BundleValidator.validate(invalid, now: now)
    end

    test "rejects mismatched CA fingerprint", %{bundle: bundle, now: now} do
      invalid =
        Map.put(
          bundle,
          "ca_fingerprint",
          "0000000000000000000000000000000000000000000000000000000000000000"
        )

      assert {:error, :transcript_hash_mismatch, _} = BundleValidator.validate(invalid, now: now)
    end

    test "rejects CRL signed by foreign CA", %{bundle: bundle, ca_cert: ca_cert, now: now} do
      foreign_key = X509.PrivateKey.new_ec(:secp384r1)
      foreign_crl = X509.CRL.new([], ca_cert, foreign_key)
      foreign_crl_pem = X509.CRL.to_pem(foreign_crl)
      foreign_crl_der = X509.CRL.to_der(foreign_crl)
      foreign_crl_hash = :crypto.hash(:sha256, foreign_crl_der) |> Base.encode16(case: :lower)

      tampered =
        bundle
        |> Map.put("crl_pem", foreign_crl_pem)
        |> Map.put("crl_der_sha256", foreign_crl_hash)

      # Recompute bundle hash
      transcript =
        [
          tampered["schema_version"],
          tampered["authority"],
          tampered["generation"],
          tampered["ca_fingerprint"],
          tampered["crl_number"],
          tampered["crl_der_sha256"],
          tampered["this_update"],
          tampered["next_update"],
          tampered["ca_bundle_pem"],
          tampered["crl_pem"]
        ]
        |> Enum.map(&to_string/1)
        |> Enum.join("|")

      tampered_hash = :crypto.hash(:sha256, transcript) |> Base.encode16(case: :lower)
      tampered = Map.put(tampered, "bundle_sha256", tampered_hash)

      assert {:error, :crl_signature_invalid, _} = BundleValidator.validate(tampered, now: now)
    end

    test "rejects expired CRL", %{bundle: bundle} do
      # 10 days in the future
      future_now = DateTime.utc_now() |> DateTime.add(10 * 86_400, :second)
      assert {:error, :crl_expired, _} = BundleValidator.validate(bundle, now: future_now)
    end
  end

  describe "AtomicStore" do
    test "writes files and switches current symlink", %{
      tmp_dir: tmp_dir,
      bundle: bundle,
      now: now
    } do
      base_dir = Path.join(tmp_dir, "pki/client-auth")
      assert {:ok, result} = AtomicStore.write_bundle(base_dir, bundle, now: now)

      assert result.generation == 1
      assert File.exists?(Path.join([base_dir, "generations", "1", "ca.crt"]))
      assert File.exists?(Path.join([base_dir, "generations", "1", "crl.pem"]))
      assert File.exists?(Path.join([base_dir, "generations", "1", "manifest.json"]))

      # Verify symlink
      current_link = Path.join(base_dir, "current")
      assert {:ok, target} = File.read_link(current_link)
      assert target == "generations/1"

      # Read manifest
      assert {:ok, manifest} = AtomicStore.read_current_manifest(base_dir)
      assert manifest["generation"] == 1
      assert manifest["bundle_sha256"] == bundle["bundle_sha256"]
    end

    test "prunes old generations retaining top 4", %{tmp_dir: tmp_dir, bundle: bundle, now: now} do
      base_dir = Path.join(tmp_dir, "pki/client-auth")

      for gen <- 1..6 do
        b = Map.put(bundle, "generation", gen)
        assert {:ok, _} = AtomicStore.write_bundle(base_dir, b, now: now)
      end

      # Should keep generations 6, 5, 4, 3 and prune 1 and 2
      generations_dir = Path.join(base_dir, "generations")
      {:ok, remaining} = File.ls(generations_dir)

      assert Enum.sort(remaining) == ["3", "4", "5", "6"]
      refute File.exists?(Path.join(generations_dir, "1"))
      refute File.exists?(Path.join(generations_dir, "2"))
    end
  end

  describe "TrustBundleManager GenServer" do
    test "processes valid bundle and reports applied receipt", %{
      tmp_dir: tmp_dir,
      bundle: bundle,
      now: now
    } do
      {:ok, manager} =
        TrustBundleManager.start_link(
          state_dir: tmp_dir,
          agent_id: "agent-test-1",
          name: :test_trust_bundle_manager
        )

      assert {:ok, receipt} = TrustBundleManager.process_bundle(manager, bundle, now: now)
      assert receipt["status"] == "applied"
      assert receipt["agent_id"] == "agent-test-1"
      assert receipt["generation"] == 1

      status = TrustBundleManager.status(manager)
      assert status.status == "applied"
      assert status.current_generation == 1
    end

    test "skips re-applying older or duplicate generation", %{
      tmp_dir: tmp_dir,
      bundle: bundle,
      now: now
    } do
      {:ok, manager} =
        TrustBundleManager.start_link(
          state_dir: tmp_dir,
          agent_id: "agent-test-2",
          name: :test_trust_bundle_manager_2
        )

      assert {:ok, _} = TrustBundleManager.process_bundle(manager, bundle, now: now)

      # Duplicate call does not error, returns applied receipt
      assert {:ok, receipt} = TrustBundleManager.process_bundle(manager, bundle, now: now)
      assert receipt["status"] == "applied"
    end

    test "handles invalid bundle with failed receipt", %{
      tmp_dir: tmp_dir,
      bundle: bundle,
      now: now
    } do
      {:ok, manager} =
        TrustBundleManager.start_link(
          state_dir: tmp_dir,
          agent_id: "agent-test-3",
          name: :test_trust_bundle_manager_3
        )

      invalid = Map.put(bundle, "schema_version", 99)

      assert {:error, :invalid_schema_version, receipt} =
               TrustBundleManager.process_bundle(manager, invalid, now: now)

      assert receipt["status"] == "failed"
      assert receipt["last_error_code"] == "invalid_schema_version"

      status = TrustBundleManager.status(manager)
      assert status.status == "failed"
      assert status.last_error_code == "invalid_schema_version"
    end
  end
end
