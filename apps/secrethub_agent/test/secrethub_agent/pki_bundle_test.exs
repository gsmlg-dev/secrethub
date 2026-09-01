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

    test "validates on-disk bundle via validate_disk_bundle", %{
      tmp_dir: tmp_dir,
      bundle: bundle,
      now: now
    } do
      base_dir = Path.join(tmp_dir, "pki/client-auth")
      assert {:ok, _} = AtomicStore.write_bundle(base_dir, bundle, now: now)

      assert {:ok, manifest} = BundleValidator.validate_disk_bundle(base_dir, now: now)
      assert manifest.generation == 1
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

    test "rejects symlinked base_dir", %{tmp_dir: tmp_dir, bundle: bundle, now: now} do
      real_dir = Path.join(tmp_dir, "real_pki")
      File.mkdir_p!(real_dir)
      symlink_base = Path.join(tmp_dir, "symlink_pki")
      File.ln_s(real_dir, symlink_base)

      assert {:error, {:symlink_directory_disallowed, ^symlink_base}} =
               AtomicStore.write_bundle(symlink_base, bundle, now: now)
    end

    test "rejects symlinked generation directory", %{tmp_dir: tmp_dir, bundle: bundle, now: now} do
      base_dir = Path.join(tmp_dir, "pki_sym_gen")
      gen_dir = Path.join([base_dir, "generations", "1"])
      File.mkdir_p!(Path.join(base_dir, "generations"))

      fake_target = Path.join(tmp_dir, "fake_target")
      File.mkdir_p!(fake_target)
      File.ln_s(fake_target, gen_dir)

      assert {:error, {:symlink_directory_disallowed, ^gen_dir}} =
               AtomicStore.write_bundle(base_dir, bundle, now: now)
    end
  end

  describe "TrustBundleManager GenServer & Monotonicity" do
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

    test "strictly rejects generation downgrade and equivocation", %{
      tmp_dir: tmp_dir,
      bundle: bundle,
      ca_key: ca_key,
      ca_cert: ca_cert,
      now: now
    } do
      {:ok, manager} =
        TrustBundleManager.start_link(
          state_dir: tmp_dir,
          agent_id: "agent-test-2",
          name: :test_trust_bundle_manager_2
        )

      gen2_bundle = Map.put(bundle, "generation", 2)

      transcript2 =
        [
          gen2_bundle["schema_version"],
          gen2_bundle["authority"],
          gen2_bundle["generation"],
          gen2_bundle["ca_fingerprint"],
          gen2_bundle["crl_number"],
          gen2_bundle["crl_der_sha256"],
          gen2_bundle["this_update"],
          gen2_bundle["next_update"],
          gen2_bundle["ca_bundle_pem"],
          gen2_bundle["crl_pem"]
        ]
        |> Enum.map(&to_string/1)
        |> Enum.join("|")

      gen2_hash = :crypto.hash(:sha256, transcript2) |> Base.encode16(case: :lower)
      gen2_bundle = Map.put(gen2_bundle, "bundle_sha256", gen2_hash)

      # 1. Apply Gen 2
      assert {:ok, receipt} = TrustBundleManager.process_bundle(manager, gen2_bundle, now: now)
      assert receipt["status"] == "applied"
      assert receipt["generation"] == 2

      # 2. Re-applying identical Gen 2 is a no-op return
      assert {:ok, dup_receipt} =
               TrustBundleManager.process_bundle(manager, gen2_bundle, now: now)

      assert dup_receipt["status"] == "applied"

      # 3. Attempting downgrade to Gen 1 is strictly rejected
      assert {:error, :generation_downgrade_rejected, failed_receipt} =
               TrustBundleManager.process_bundle(manager, bundle, now: now)

      assert failed_receipt["status"] == "failed"
      assert failed_receipt["last_error_code"] == "generation_downgrade_rejected"

      # 4. Equivocation: same generation 2 with differing valid CRL and hash is strictly rejected
      crl2 =
        X509.CRL.new(
          [],
          ca_cert,
          ca_key,
          this_update: DateTime.add(now, -100, :second),
          next_update: DateTime.add(now, 48 * 3600, :second),
          extensions: [crl_number: X509.CRL.Extension.crl_number(2)]
        )

      crl2_pem = X509.CRL.to_pem(crl2)
      crl2_der = X509.CRL.to_der(crl2)
      crl2_hash = :crypto.hash(:sha256, crl2_der) |> Base.encode16(case: :lower)

      equivocating_bundle =
        gen2_bundle
        |> Map.put("crl_number", 2)
        |> Map.put("this_update", DateTime.to_iso8601(DateTime.add(now, -100, :second)))
        |> Map.put("crl_pem", crl2_pem)
        |> Map.put("crl_der_sha256", crl2_hash)

      transcript_eq =
        [
          equivocating_bundle["schema_version"],
          equivocating_bundle["authority"],
          equivocating_bundle["generation"],
          equivocating_bundle["ca_fingerprint"],
          equivocating_bundle["crl_number"],
          equivocating_bundle["crl_der_sha256"],
          equivocating_bundle["this_update"],
          equivocating_bundle["next_update"],
          equivocating_bundle["ca_bundle_pem"],
          equivocating_bundle["crl_pem"]
        ]
        |> Enum.map(&to_string/1)
        |> Enum.join("|")

      eq_hash = :crypto.hash(:sha256, transcript_eq) |> Base.encode16(case: :lower)
      equivocating_bundle = Map.put(equivocating_bundle, "bundle_sha256", eq_hash)

      assert {:error, :equivocation_detected, eq_receipt} =
               TrustBundleManager.process_bundle(manager, equivocating_bundle, now: now)

      assert eq_receipt["status"] == "failed"
      assert eq_receipt["last_error_code"] == "equivocation_detected"
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

    test "persistent watermark restart rollback recovery repairs disk bundle and sends ACK", %{
      tmp_dir: tmp_dir,
      bundle: gen1_bundle,
      ca_cert: ca_cert,
      ca_key: ca_key,
      now: now
    } do
      bundle_dir = Path.join(tmp_dir, "pki/client-auth")

      # 1. Install generation 1
      {:ok, manager1} =
        TrustBundleManager.start_link(
          state_dir: tmp_dir,
          bundle_dir: bundle_dir,
          agent_id: "agent-repair-test",
          name: :test_repair_manager_1
        )

      assert {:ok, _} = TrustBundleManager.process_bundle(manager1, gen1_bundle, now: now)

      # 2. Issue generation 2
      this_update = DateTime.add(now, -100, :second)
      next_update = DateTime.add(now, 48 * 3600, :second)

      crl2 =
        X509.CRL.new(
          [],
          ca_cert,
          ca_key,
          this_update: this_update,
          next_update: next_update,
          extensions: [crl_number: X509.CRL.Extension.crl_number(2)]
        )

      crl2_pem = X509.CRL.to_pem(crl2)
      crl2_der = X509.CRL.to_der(crl2)
      crl2_hash = :crypto.hash(:sha256, crl2_der) |> Base.encode16(case: :lower)

      gen2_bundle =
        gen1_bundle
        |> Map.put("generation", 2)
        |> Map.put("crl_number", 2)
        |> Map.put("this_update", DateTime.to_iso8601(this_update))
        |> Map.put("next_update", DateTime.to_iso8601(next_update))
        |> Map.put("crl_pem", crl2_pem)
        |> Map.put("crl_der_sha256", crl2_hash)

      transcript2 =
        [
          gen2_bundle["schema_version"],
          gen2_bundle["authority"],
          gen2_bundle["generation"],
          gen2_bundle["ca_fingerprint"],
          gen2_bundle["crl_number"],
          gen2_bundle["crl_der_sha256"],
          gen2_bundle["this_update"],
          gen2_bundle["next_update"],
          gen2_bundle["ca_bundle_pem"],
          gen2_bundle["crl_pem"]
        ]
        |> Enum.map(&to_string/1)
        |> Enum.join("|")

      bundle2_hash = :crypto.hash(:sha256, transcript2) |> Base.encode16(case: :lower)
      gen2_bundle = Map.put(gen2_bundle, "bundle_sha256", bundle2_hash)

      assert {:ok, _} = TrustBundleManager.process_bundle(manager1, gen2_bundle, now: now)
      GenServer.stop(manager1)

      # 3. Simulate rollback of disk current symlink back to generation 1
      current_symlink = Path.join(bundle_dir, "current")
      File.rm(current_symlink)
      File.ln_s("generations/1", current_symlink)

      # 4. Restart TrustBundleManager
      {:ok, manager2} =
        TrustBundleManager.start_link(
          state_dir: tmp_dir,
          bundle_dir: bundle_dir,
          agent_id: "agent-repair-test",
          name: :test_repair_manager_2
        )

      status_after_restart = TrustBundleManager.status(manager2)
      assert status_after_restart.needs_repair == true
      assert status_after_restart.status == "error"
      assert status_after_restart.lkg_generation == 2
      assert status_after_restart.current_generation == 1

      # 5. Core sends generation 2 bundle again
      assert {:ok, receipt} = TrustBundleManager.process_bundle(manager2, gen2_bundle, now: now)
      assert receipt["status"] == "applied"
      assert receipt["generation"] == 2

      # 6. Verify disk current symlink has been repaired and points to generation 2
      assert {:ok, target} = File.read_link(current_symlink)
      assert String.ends_with?(target, "2")

      status_repaired = TrustBundleManager.status(manager2)
      assert status_repaired.needs_repair == false
      assert status_repaired.status == "applied"
      assert status_repaired.current_generation == 2
    end

    test "live disk rollback while manager is running detects mismatch and re-applies", %{
      tmp_dir: tmp_dir,
      bundle: gen1_bundle,
      ca_cert: ca_cert,
      ca_key: ca_key,
      now: now
    } do
      bundle_dir = Path.join(tmp_dir, "pki/client-auth-live")

      {:ok, manager} =
        TrustBundleManager.start_link(
          state_dir: tmp_dir,
          bundle_dir: bundle_dir,
          agent_id: "agent-live-repair-test",
          name: :test_live_repair_manager
        )

      # 1. Install generation 1
      assert {:ok, _} = TrustBundleManager.process_bundle(manager, gen1_bundle, now: now)

      # 2. Install generation 2
      this_update = DateTime.add(now, -100, :second)
      next_update = DateTime.add(now, 48 * 3600, :second)

      crl2 =
        X509.CRL.new(
          [],
          ca_cert,
          ca_key,
          this_update: this_update,
          next_update: next_update,
          extensions: [crl_number: X509.CRL.Extension.crl_number(2)]
        )

      crl2_pem = X509.CRL.to_pem(crl2)
      crl2_der = X509.CRL.to_der(crl2)
      crl2_hash = :crypto.hash(:sha256, crl2_der) |> Base.encode16(case: :lower)

      gen2_bundle =
        gen1_bundle
        |> Map.put("generation", 2)
        |> Map.put("crl_number", 2)
        |> Map.put("this_update", DateTime.to_iso8601(this_update))
        |> Map.put("next_update", DateTime.to_iso8601(next_update))
        |> Map.put("crl_pem", crl2_pem)
        |> Map.put("crl_der_sha256", crl2_hash)

      transcript2 =
        [
          gen2_bundle["schema_version"],
          gen2_bundle["authority"],
          gen2_bundle["generation"],
          gen2_bundle["ca_fingerprint"],
          gen2_bundle["crl_number"],
          gen2_bundle["crl_der_sha256"],
          gen2_bundle["this_update"],
          gen2_bundle["next_update"],
          gen2_bundle["ca_bundle_pem"],
          gen2_bundle["crl_pem"]
        ]
        |> Enum.map(&to_string/1)
        |> Enum.join("|")

      bundle2_hash = :crypto.hash(:sha256, transcript2) |> Base.encode16(case: :lower)
      gen2_bundle = Map.put(gen2_bundle, "bundle_sha256", bundle2_hash)

      assert {:ok, _} = TrustBundleManager.process_bundle(manager, gen2_bundle, now: now)

      # 3. While manager is still running, manually tamper/rollback current symlink to generation 1
      current_symlink = Path.join(bundle_dir, "current")
      File.rm(current_symlink)
      File.ln_s("generations/1", current_symlink)

      # 4. Push generation 2 bundle again. Manager must detect that disk has gen 1, NOT take the no-op path, and re-apply gen 2!
      assert {:ok, receipt} = TrustBundleManager.process_bundle(manager, gen2_bundle, now: now)
      assert receipt["status"] == "applied"
      assert receipt["generation"] == 2

      # 5. Verify current symlink has been fixed to generation 2
      assert {:ok, target} = File.read_link(current_symlink)
      assert String.ends_with?(target, "2")
    end

    test "watermark is persisted when valid disk bundle exists but watermark is absent on init",
         %{
           tmp_dir: tmp_dir,
           bundle: bundle,
           now: now
         } do
      bundle_dir = Path.join(tmp_dir, "pki/client-auth-no-wm")
      # Write disk bundle directly with AtomicStore
      assert {:ok, _} = AtomicStore.write_bundle(bundle_dir, bundle, now: now)

      # Delete the watermark to simulate missing watermark
      wm_path = Path.join(bundle_dir, "watermark.json")
      File.rm(wm_path)
      refute File.exists?(wm_path)

      # Start TrustBundleManager
      {:ok, manager} =
        TrustBundleManager.start_link(
          state_dir: tmp_dir,
          bundle_dir: bundle_dir,
          agent_id: "agent-no-wm-test",
          name: :test_no_wm_manager
        )

      # Watermark must now exist
      assert File.exists?(wm_path)
      assert {:ok, wm} = AtomicStore.read_persistent_watermark(bundle_dir)
      assert wm["highest_seen_generation"] == 1

      status = TrustBundleManager.status(manager)
      assert status.status == "applied"
      assert status.current_generation == 1
    end
  end
end
