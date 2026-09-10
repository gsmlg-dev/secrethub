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
      expected_path = AtomicStore.normalize_system_path(symlink_base)

      assert {:error, {:symlink_directory_disallowed, ^expected_path}} =
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

    test "read_persistent_watermark rejects incomplete or invalid watermark schemas", %{
      tmp_dir: tmp_dir
    } do
      bundle_dir = Path.join(tmp_dir, "pki/client-auth-invalid-wm")
      File.mkdir_p!(bundle_dir)
      wm_path = Path.join(bundle_dir, "watermark.json")

      # 1. Empty object
      File.write!(wm_path, "{}")

      assert {:error, :invalid_watermark_schema} =
               AtomicStore.read_persistent_watermark(bundle_dir)

      # 2. Missing fields
      File.write!(wm_path, Jason.encode!(%{"highest_seen_generation" => 10}))

      assert {:error, :invalid_watermark_schema} =
               AtomicStore.read_persistent_watermark(bundle_dir)

      # 3. Invalid hex fingerprint
      invalid_wm = %{
        "schema_version" => 1,
        "highest_seen_generation" => 1,
        "highest_seen_crl_number" => 1,
        "pinned_ca_fingerprint" => "not-a-valid-hex",
        "last_bundle_sha256" =>
          "8792bc0fa20e137b26ac4467d91c67926b86edee0352534a5b71f6fd8aa724b5",
        "updated_at" => "2026-09-02T12:00:00Z"
      }

      File.write!(wm_path, Jason.encode!(invalid_wm))

      assert {:error, :invalid_watermark_schema} =
               AtomicStore.read_persistent_watermark(bundle_dir)

      # 4. Valid schema succeeds
      valid_wm = %{
        invalid_wm
        | "pinned_ca_fingerprint" =>
            "8792bc0fa20e137b26ac4467d91c67926b86edee0352534a5b71f6fd8aa724b5"
      }

      File.write!(wm_path, Jason.encode!(valid_wm))

      assert {:ok, %{"highest_seen_generation" => 1}} =
               AtomicStore.read_persistent_watermark(bundle_dir)
    end

    test "ensure_secure_directory does not mutate ancestor permissions", %{tmp_dir: tmp_dir} do
      parent_dir = Path.join(tmp_dir, "preserved_parent")
      File.mkdir_p!(parent_dir)
      # Set explicit 0777 permission on parent
      File.chmod!(parent_dir, 0o777)
      parent_stat_before = File.stat!(parent_dir)

      target_dir = Path.join(parent_dir, "nested_bundle")
      assert :ok = AtomicStore.ensure_secure_directory(target_dir)

      # Target directory must have 0750 permissions
      target_stat = File.stat!(target_dir)
      assert Bitwise.band(target_stat.mode, 0o777) == 0o750

      # Parent directory permissions must remain untouched (0777)
      parent_stat_after = File.stat!(parent_dir)
      assert parent_stat_before.mode == parent_stat_after.mode
    end

    test "maybe_repair_watermark rejects equivocation and downgrades", %{
      tmp_dir: tmp_dir,
      bundle: bundle,
      now: now
    } do
      bundle_dir = Path.join(tmp_dir, "pki/client-auth-equivocation")
      assert {:ok, _} = AtomicStore.write_bundle(bundle_dir, bundle, now: now)

      # Watermark on disk indicates higher generation 5
      equivocal_wm = %{
        "schema_version" => 1,
        "highest_seen_generation" => 5,
        "highest_seen_crl_number" => 5,
        "pinned_ca_fingerprint" => bundle["ca_fingerprint"],
        "last_bundle_sha256" =>
          "0000000000000000000000000000000000000000000000000000000000000000",
        "updated_at" => DateTime.to_iso8601(now)
      }

      wm_path = Path.join(bundle_dir, "watermark.json")
      File.write!(wm_path, Jason.encode!(equivocal_wm))

      # When TrustBundleManager starts on this directory, it must flag the downgrade and fail closed into error state
      {:ok, manager} =
        TrustBundleManager.start_link(
          state_dir: tmp_dir,
          bundle_dir: bundle_dir,
          agent_id: "agent-equivocation-test",
          name: :test_equivocation_manager
        )

      status = TrustBundleManager.status(manager)
      assert status.status == "error"
      assert status.needs_repair == true
      assert status.last_error_code == :generation_rollback
    end

    test "corrupted watermark with valid disk bundle preserves lower bound and rejects downgrades",
         %{
           tmp_dir: tmp_dir,
           bundle: gen1_bundle,
           ca_cert: ca_cert,
           ca_key: ca_key,
           now: now
         } do
      bundle_dir = Path.join(tmp_dir, "pki/client-auth-corrupted-wm")

      # 1. Write Gen 10 bundle to disk
      crl10 =
        X509.CRL.new(
          [],
          ca_cert,
          ca_key,
          this_update: DateTime.add(now, -100, :second),
          next_update: DateTime.add(now, 48 * 3600, :second),
          extensions: [crl_number: X509.CRL.Extension.crl_number(10)]
        )

      crl10_pem = X509.CRL.to_pem(crl10)
      crl10_der = X509.CRL.to_der(crl10)
      crl10_hash = :crypto.hash(:sha256, crl10_der) |> Base.encode16(case: :lower)

      gen10_bundle =
        gen1_bundle
        |> Map.put("generation", 10)
        |> Map.put("crl_number", 10)
        |> Map.put("this_update", DateTime.to_iso8601(DateTime.add(now, -100, :second)))
        |> Map.put("next_update", DateTime.to_iso8601(DateTime.add(now, 48 * 3600, :second)))
        |> Map.put("crl_pem", crl10_pem)
        |> Map.put("crl_der_sha256", crl10_hash)

      transcript10 =
        [
          gen10_bundle["schema_version"],
          gen10_bundle["authority"],
          gen10_bundle["generation"],
          gen10_bundle["ca_fingerprint"],
          gen10_bundle["crl_number"],
          gen10_bundle["crl_der_sha256"],
          gen10_bundle["this_update"],
          gen10_bundle["next_update"],
          gen10_bundle["ca_bundle_pem"],
          gen10_bundle["crl_pem"]
        ]
        |> Enum.map(&to_string/1)
        |> Enum.join("|")

      bundle10_hash = :crypto.hash(:sha256, transcript10) |> Base.encode16(case: :lower)
      gen10_bundle = Map.put(gen10_bundle, "bundle_sha256", bundle10_hash)

      assert {:ok, _} = AtomicStore.write_bundle(bundle_dir, gen10_bundle, now: now)

      # 2. Corrupt watermark.json
      wm_path = Path.join(bundle_dir, "watermark.json")
      File.write!(wm_path, "{ corrupted json ! }")

      # 3. Start TrustBundleManager
      {:ok, manager} =
        TrustBundleManager.start_link(
          state_dir: tmp_dir,
          bundle_dir: bundle_dir,
          agent_id: "agent-corrupt-wm-test",
          name: :test_corrupt_wm_manager
        )

      status = TrustBundleManager.status(manager)
      assert status.status == "error"
      assert status.needs_repair == true
      assert status.last_error_code == :corrupted_watermark
      # lkg_generation and current_generation must reflect disk generation 10
      assert status.lkg_generation == 10
      assert status.current_generation == 10

      # 4. Incoming candidate Gen 9 must be strictly rejected as generation_downgrade_rejected
      gen9_bundle = Map.put(gen1_bundle, "generation", 9)

      transcript9 =
        [
          gen9_bundle["schema_version"],
          gen9_bundle["authority"],
          gen9_bundle["generation"],
          gen9_bundle["ca_fingerprint"],
          gen9_bundle["crl_number"],
          gen9_bundle["crl_der_sha256"],
          gen9_bundle["this_update"],
          gen9_bundle["next_update"],
          gen9_bundle["ca_bundle_pem"],
          gen9_bundle["crl_pem"]
        ]
        |> Enum.map(&to_string/1)
        |> Enum.join("|")

      bundle9_hash = :crypto.hash(:sha256, transcript9) |> Base.encode16(case: :lower)
      gen9_bundle = Map.put(gen9_bundle, "bundle_sha256", bundle9_hash)

      assert {:error, :generation_downgrade_rejected, receipt} =
               TrustBundleManager.process_bundle(manager, gen9_bundle, now: now)

      assert receipt["status"] == "failed"
      assert receipt["last_error_code"] == "generation_downgrade_rejected"

      # 5. Core sends authentic Gen 10 bundle -> manager applies it, repairs watermark, clears error
      assert {:ok, ok_receipt} =
               TrustBundleManager.process_bundle(manager, gen10_bundle, now: now)

      assert ok_receipt["status"] == "applied"
      assert ok_receipt["generation"] == 10

      status_after = TrustBundleManager.status(manager)
      assert status_after.status == "applied"
      assert status_after.needs_repair == false
      assert status_after.last_error_code == nil
      assert status_after.lkg_generation == 10

      # Watermark on disk must now be valid
      assert {:ok, fixed_wm} = AtomicStore.read_persistent_watermark(bundle_dir)
      assert fixed_wm["highest_seen_generation"] == 10
    end

    test "publication failure after watermark commit reconciles disk state in TrustBundleManager",
         %{
           tmp_dir: tmp_dir,
           bundle: gen1_bundle,
           ca_key: ca_key,
           ca_cert: ca_cert,
           now: now
         } do
      bundle_dir = Path.join(tmp_dir, "pki_fsync_fail")

      # 1. Start manager and apply Gen 1
      {:ok, manager} =
        TrustBundleManager.start_link(
          state_dir: tmp_dir,
          bundle_dir: bundle_dir,
          agent_id: "agent-fsync-fail-test",
          name: :test_fsync_fail_manager
        )

      assert {:ok, _} = TrustBundleManager.process_bundle(manager, gen1_bundle, now: now)

      # 2. Build Gen 2 bundle
      this_update2 = DateTime.add(now, -60, :second)
      next_update2 = DateTime.add(now, 48 * 3600, :second)

      crl2 =
        X509.CRL.new(
          [],
          ca_cert,
          ca_key,
          this_update: this_update2,
          next_update: next_update2,
          extensions: [crl_number: X509.CRL.Extension.crl_number(2)]
        )

      crl2_pem = X509.CRL.to_pem(crl2)
      crl2_der = X509.CRL.to_der(crl2)
      crl2_der_sha256 = :crypto.hash(:sha256, crl2_der) |> Base.encode16(case: :lower)

      gen2_bundle =
        gen1_bundle
        |> Map.put("generation", 2)
        |> Map.put("crl_number", 2)
        |> Map.put("this_update", DateTime.to_iso8601(this_update2))
        |> Map.put("next_update", DateTime.to_iso8601(next_update2))
        |> Map.put("crl_der_sha256", crl2_der_sha256)
        |> Map.put("crl_pem", crl2_pem)

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

      # 3. Inject base_dir fsync error during Gen 2 write
      assert {:error, :dir_sync_failed_after_switch, receipt} =
               TrustBundleManager.process_bundle(manager, gen2_bundle,
                 now: now,
                 inject_base_dir_fsync_error: :eio
               )

      assert receipt["status"] == "failed"

      # 4. In-memory manager state was reconciled from disk!
      status = TrustBundleManager.status(manager)
      assert status.lkg_generation == 2
      assert status.current_generation == 2

      # 5. Stale Gen 1 candidate must be rejected as downgrade against reconciled baseline
      assert {:error, :generation_downgrade_rejected, _} =
               TrustBundleManager.process_bundle(manager, gen1_bundle, now: now)
    end

    test "damaged-state recovery with expired CRL recovers baseline and rejects downgrade", %{
      tmp_dir: tmp_dir,
      bundle: gen1_bundle,
      ca_key: ca_key,
      ca_cert: ca_cert,
      now: now
    } do
      bundle_dir = Path.join(tmp_dir, "pki_expired_crl_recovery")

      # 1. Create a bundle with CRL that expired in the past
      past_time = DateTime.add(now, -10000, :second)
      expired_time = DateTime.add(now, -5000, :second)

      crl_expired =
        X509.CRL.new(
          [],
          ca_cert,
          ca_key,
          this_update: past_time,
          next_update: expired_time,
          extensions: [crl_number: X509.CRL.Extension.crl_number(10)]
        )

      crl_expired_pem = X509.CRL.to_pem(crl_expired)
      crl_expired_der = X509.CRL.to_der(crl_expired)
      crl_expired_sha256 = :crypto.hash(:sha256, crl_expired_der) |> Base.encode16(case: :lower)

      gen10_bundle =
        gen1_bundle
        |> Map.put("generation", 10)
        |> Map.put("crl_number", 10)
        |> Map.put("this_update", DateTime.to_iso8601(past_time))
        |> Map.put("next_update", DateTime.to_iso8601(expired_time))
        |> Map.put("crl_pem", crl_expired_pem)
        |> Map.put("crl_der_sha256", crl_expired_sha256)

      transcript10 =
        [
          gen10_bundle["schema_version"],
          gen10_bundle["authority"],
          gen10_bundle["generation"],
          gen10_bundle["ca_fingerprint"],
          gen10_bundle["crl_number"],
          gen10_bundle["crl_der_sha256"],
          gen10_bundle["this_update"],
          gen10_bundle["next_update"],
          gen10_bundle["ca_bundle_pem"],
          gen10_bundle["crl_pem"]
        ]
        |> Enum.map(&to_string/1)
        |> Enum.join("|")

      bundle10_hash = :crypto.hash(:sha256, transcript10) |> Base.encode16(case: :lower)
      gen10_bundle = Map.put(gen10_bundle, "bundle_sha256", bundle10_hash)

      # Write to disk as of past_time when CRL was still fresh
      assert {:ok, _} = AtomicStore.write_bundle(bundle_dir, gen10_bundle, now: past_time)

      # 2. Corrupt watermark.json
      File.write!(Path.join(bundle_dir, "watermark.json"), "{ corrupted watermark json }")

      # 3. Start manager at current time (when CRL is expired)
      # Manager must recover baseline from disk historical evidence despite expired CRL
      {:ok, manager} =
        TrustBundleManager.start_link(
          state_dir: tmp_dir,
          bundle_dir: bundle_dir,
          agent_id: "agent-expired-recovery-test",
          name: :test_expired_recovery_manager
        )

      status = TrustBundleManager.status(manager)
      assert status.status == "repair_required"
      assert status.needs_repair == true
      # Baseline generation 10 must have survived as rollback barrier!
      assert status.lkg_generation == 10
      # But current expired bundle must not be published as active installed generation!
      assert status.current_generation == 0

      # 4. Attempting to install Gen 9 must be rejected as downgrade (not accepted as fresh enrollment!)
      assert {:error, :generation_downgrade_rejected, receipt} =
               TrustBundleManager.process_bundle(manager, gen1_bundle, now: now)

      assert receipt["status"] == "failed"
      assert receipt["last_error_code"] == "generation_downgrade_rejected"
    end

    test "damaged state without surviving baseline enters recovery_required and requires force to recover",
         %{
           tmp_dir: tmp_dir,
           bundle: bundle,
           now: now
         } do
      bundle_dir = Path.join(tmp_dir, "pki_damaged_quarantine")
      File.mkdir_p!(bundle_dir)

      # Corrupt watermark and empty/missing generations
      File.write!(Path.join(bundle_dir, "watermark.json"), "[]")

      # Start manager: should enter recovery_required
      {:ok, manager} =
        TrustBundleManager.start_link(
          state_dir: tmp_dir,
          bundle_dir: bundle_dir,
          agent_id: "agent-quarantine-test",
          name: :test_quarantine_manager
        )

      status = TrustBundleManager.status(manager)
      assert status.status == "recovery_required"
      assert status.needs_repair == true
      assert status.last_error_code == :damaged_state_recovery_required

      # Normal process_bundle is rejected because damaged baseline cannot guarantee monotonicity
      assert {:error, :damaged_state_recovery_required, receipt1} =
               TrustBundleManager.process_bundle(manager, bundle, now: now)

      assert receipt1["status"] == "failed"
      assert receipt1["last_error_code"] == "damaged_state_recovery_required"

      # Finding 1 regression: Subsequent attempt without force MUST remain quarantined (not bypassed)
      status_mid = TrustBundleManager.status(manager)
      assert status_mid.status == "recovery_required"
      assert status_mid.recovery_mode == :quarantined

      assert {:error, :damaged_state_recovery_required, receipt2} =
               TrustBundleManager.process_bundle(manager, bundle, now: now)

      assert receipt2["status"] == "failed"
      assert receipt2["last_error_code"] == "damaged_state_recovery_required"

      # With force: true, operator/orchestrator authorizes recovery
      assert {:ok, ok_receipt} =
               TrustBundleManager.process_bundle(manager, bundle, force: true, now: now)

      assert ok_receipt["status"] == "applied"

      status_after = TrustBundleManager.status(manager)
      assert status_after.status == "applied"
      assert status_after.recovery_mode == :none
      assert status_after.needs_repair == false
    end

    test "unified scanner recovers higher generation 10 when current symlink points to generation 9",
         %{
           tmp_dir: tmp_dir,
           bundle: gen1_bundle,
           ca_key: ca_key,
           ca_cert: ca_cert,
           now: now
         } do
      bundle_dir = Path.join(tmp_dir, "pki_unified_scanner_recovery")
      File.mkdir_p!(bundle_dir)

      # Generate signed CRL for gen 9
      crl_9 =
        X509.CRL.new([], ca_cert, ca_key,
          this_update: now,
          next_update: DateTime.add(now, 3600, :second),
          extensions: [crl_number: X509.CRL.Extension.crl_number(9)]
        )

      crl_9_pem = X509.CRL.to_pem(crl_9)
      crl_9_der = X509.CRL.to_der(crl_9)
      crl_9_sha256 = :crypto.hash(:sha256, crl_9_der) |> Base.encode16(case: :lower)

      gen9_bundle =
        gen1_bundle
        |> Map.put("generation", 9)
        |> Map.put("crl_number", 9)
        |> Map.put("this_update", DateTime.to_iso8601(now))
        |> Map.put("next_update", DateTime.to_iso8601(DateTime.add(now, 3600, :second)))
        |> Map.put("crl_pem", crl_9_pem)
        |> Map.put("crl_der_sha256", crl_9_sha256)

      t9 =
        [
          gen9_bundle["schema_version"],
          gen9_bundle["authority"],
          gen9_bundle["generation"],
          gen9_bundle["ca_fingerprint"],
          gen9_bundle["crl_number"],
          gen9_bundle["crl_der_sha256"],
          gen9_bundle["this_update"],
          gen9_bundle["next_update"],
          gen9_bundle["ca_bundle_pem"],
          gen9_bundle["crl_pem"]
        ]
        |> Enum.map(&to_string/1)
        |> Enum.join("|")

      gen9_hash = :crypto.hash(:sha256, t9) |> Base.encode16(case: :lower)
      gen9_bundle = Map.put(gen9_bundle, "bundle_sha256", gen9_hash)

      assert {:ok, _} = AtomicStore.write_bundle(bundle_dir, gen9_bundle, now: now)

      # Generate signed CRL for gen 10
      crl_10 =
        X509.CRL.new([], ca_cert, ca_key,
          this_update: now,
          next_update: DateTime.add(now, 3600, :second),
          extensions: [crl_number: X509.CRL.Extension.crl_number(10)]
        )

      crl_10_pem = X509.CRL.to_pem(crl_10)
      crl_10_der = X509.CRL.to_der(crl_10)
      crl_10_sha256 = :crypto.hash(:sha256, crl_10_der) |> Base.encode16(case: :lower)

      gen10_bundle =
        gen1_bundle
        |> Map.put("generation", 10)
        |> Map.put("crl_number", 10)
        |> Map.put("this_update", DateTime.to_iso8601(now))
        |> Map.put("next_update", DateTime.to_iso8601(DateTime.add(now, 3600, :second)))
        |> Map.put("crl_pem", crl_10_pem)
        |> Map.put("crl_der_sha256", crl_10_sha256)

      t10 =
        [
          gen10_bundle["schema_version"],
          gen10_bundle["authority"],
          gen10_bundle["generation"],
          gen10_bundle["ca_fingerprint"],
          gen10_bundle["crl_number"],
          gen10_bundle["crl_der_sha256"],
          gen10_bundle["this_update"],
          gen10_bundle["next_update"],
          gen10_bundle["ca_bundle_pem"],
          gen10_bundle["crl_pem"]
        ]
        |> Enum.map(&to_string/1)
        |> Enum.join("|")

      gen10_hash = :crypto.hash(:sha256, t10) |> Base.encode16(case: :lower)
      gen10_bundle = Map.put(gen10_bundle, "bundle_sha256", gen10_hash)

      assert {:ok, _} = AtomicStore.write_bundle(bundle_dir, gen10_bundle, now: now)

      # Now point current symlink back to generation 9 to simulate interrupted switch or partial crash
      current_symlink = Path.join(bundle_dir, "current")
      File.rm(current_symlink)
      File.ln_s(Path.join("generations", "9"), current_symlink)

      # Corrupt watermark
      File.write!(Path.join(bundle_dir, "watermark.json"), "{ corrupt }")

      # Unified scanner must find generation 10 across generations/
      assert {:ok, surviving} = BundleValidator.find_surviving_disk_bundle(bundle_dir)
      assert surviving.generation == 10

      # Start manager: should select generation 10 as baseline!
      {:ok, manager} =
        TrustBundleManager.start_link(
          state_dir: tmp_dir,
          bundle_dir: bundle_dir,
          agent_id: "agent-gen10-recovery-test",
          name: :test_gen10_recovery_manager
        )

      status = TrustBundleManager.status(manager)
      assert status.lkg_generation == 10
      # Reject generation 9 as downgrade against baseline 10
      assert {:error, :generation_downgrade_rejected, _} =
               TrustBundleManager.process_bundle(manager, gen9_bundle, now: now)
    end

    test "watermark fsync error injection formats cleanly as watermark_commit_failed without crashing",
         %{
           tmp_dir: tmp_dir,
           bundle: bundle,
           now: now
         } do
      bundle_dir = Path.join(tmp_dir, "pki_watermark_fsync_err")

      {:ok, manager} =
        TrustBundleManager.start_link(
          state_dir: tmp_dir,
          bundle_dir: bundle_dir,
          agent_id: "agent-fsync-err-test",
          name: :test_fsync_err_manager
        )

      # Inject simulated fsync error on watermark write
      assert {:error, :watermark_commit_failed, receipt} =
               TrustBundleManager.process_bundle(
                 manager,
                 bundle,
                 now: now,
                 inject_watermark_fsync_error: :eio
               )

      assert receipt["status"] == "failed"
      assert receipt["last_error_code"] == "watermark_commit_failed"
      assert is_binary(receipt["last_error_detail"])
      assert String.contains?(receipt["last_error_detail"], "eio")

      status = TrustBundleManager.status(manager)
      assert status.status == "failed"
      assert status.last_error_code == "watermark_commit_failed"
    end

    test "total JSON decoding handles non-map shapes across store and validator", %{
      tmp_dir: tmp_dir,
      now: now
    } do
      bundle_dir = Path.join(tmp_dir, "pki_total_json_test")
      File.mkdir_p!(bundle_dir)

      # Test non-map JSON shapes in watermark.json
      non_maps = ["[]", "null", "12345", "\"a string\"", "true", "{ broken json"]

      for shape <- non_maps do
        File.write!(Path.join(bundle_dir, "watermark.json"), shape)
        res = AtomicStore.read_persistent_watermark(bundle_dir)
        assert match?({:error, _}, res)
        assert not match?({:ok, _}, res)
      end

      # Test non-map JSON shapes in manifest.json
      current_dir = Path.join(bundle_dir, "current")
      File.mkdir_p!(current_dir)

      for shape <- non_maps do
        File.write!(Path.join(current_dir, "manifest.json"), shape)
        res = AtomicStore.read_current_manifest(bundle_dir)
        assert match?({:error, _}, res)
        assert not match?({:ok, _}, res)

        # BundleValidator.validate_disk_bundle must handle non-map manifest safely
        val_res = BundleValidator.validate_disk_bundle(bundle_dir, now: now)
        assert match?({:error, :disk_bundle_invalid, _}, val_res)
      end
    end

    test "watermark directory fsync executes strictly after rename", %{
      tmp_dir: tmp_dir
    } do
      bundle_dir = Path.join(tmp_dir, "pki_wm_fsync_order_test")
      File.mkdir_p!(bundle_dir)

      dummy_val = %{
        generation: 1,
        crl_number: 1,
        ca_fingerprint: String.duplicate("a", 64),
        bundle_sha256: String.duplicate("b", 64)
      }

      wm_path = Path.join(bundle_dir, "watermark.json")
      refute File.exists?(wm_path)

      # Inject directory sync error
      assert {:error, {:dir_sync_failed, :eio}} =
               AtomicStore.write_watermark(bundle_dir, dummy_val,
                 inject_watermark_fsync_error: :eio
               )

      # Crucial: watermark.json MUST already exist on disk because rename preceded directory sync!
      assert File.exists?(wm_path)
    end

    test "unified recovery handles missing watermark with older current and newer retained generation",
         %{
           tmp_dir: tmp_dir,
           now: now,
           ca_key: ca_key,
           ca_cert: ca_cert,
           bundle: bundle
         } do
      bundle_dir = Path.join(tmp_dir, "pki_missing_wm_older_current_test")
      File.mkdir_p!(bundle_dir)

      # 1. Publish Gen 9
      crl_9 =
        X509.CRL.new([], ca_cert, ca_key,
          this_update: now,
          next_update: DateTime.add(now, 3600, :second),
          extensions: [crl_number: X509.CRL.Extension.crl_number(9)]
        )

      crl_9_pem = X509.CRL.to_pem(crl_9)
      crl_9_der = X509.CRL.to_der(crl_9)
      crl_9_sha256 = :crypto.hash(:sha256, crl_9_der) |> Base.encode16(case: :lower)

      gen9_bundle =
        bundle
        |> Map.put("generation", 9)
        |> Map.put("crl_number", 9)
        |> Map.put("this_update", DateTime.to_iso8601(now))
        |> Map.put("next_update", DateTime.to_iso8601(DateTime.add(now, 3600, :second)))
        |> Map.put("crl_pem", crl_9_pem)
        |> Map.put("crl_der_sha256", crl_9_sha256)

      t9 =
        [
          gen9_bundle["schema_version"],
          gen9_bundle["authority"],
          gen9_bundle["generation"],
          gen9_bundle["ca_fingerprint"],
          gen9_bundle["crl_number"],
          gen9_bundle["crl_der_sha256"],
          gen9_bundle["this_update"],
          gen9_bundle["next_update"],
          gen9_bundle["ca_bundle_pem"],
          gen9_bundle["crl_pem"]
        ]
        |> Enum.map(&to_string/1)
        |> Enum.join("|")

      gen9_hash = :crypto.hash(:sha256, t9) |> Base.encode16(case: :lower)
      gen9_bundle = Map.put(gen9_bundle, "bundle_sha256", gen9_hash)
      assert {:ok, _} = AtomicStore.write_bundle(bundle_dir, gen9_bundle, now: now)

      # 2. Publish Gen 10
      crl_10 =
        X509.CRL.new([], ca_cert, ca_key,
          this_update: now,
          next_update: DateTime.add(now, 3600, :second),
          extensions: [crl_number: X509.CRL.Extension.crl_number(10)]
        )

      crl_10_pem = X509.CRL.to_pem(crl_10)
      crl_10_der = X509.CRL.to_der(crl_10)
      crl_10_sha256 = :crypto.hash(:sha256, crl_10_der) |> Base.encode16(case: :lower)

      gen10_bundle =
        bundle
        |> Map.put("generation", 10)
        |> Map.put("crl_number", 10)
        |> Map.put("this_update", DateTime.to_iso8601(now))
        |> Map.put("next_update", DateTime.to_iso8601(DateTime.add(now, 3600, :second)))
        |> Map.put("crl_pem", crl_10_pem)
        |> Map.put("crl_der_sha256", crl_10_sha256)

      t10 =
        [
          gen10_bundle["schema_version"],
          gen10_bundle["authority"],
          gen10_bundle["generation"],
          gen10_bundle["ca_fingerprint"],
          gen10_bundle["crl_number"],
          gen10_bundle["crl_der_sha256"],
          gen10_bundle["this_update"],
          gen10_bundle["next_update"],
          gen10_bundle["ca_bundle_pem"],
          gen10_bundle["crl_pem"]
        ]
        |> Enum.map(&to_string/1)
        |> Enum.join("|")

      gen10_hash = :crypto.hash(:sha256, t10) |> Base.encode16(case: :lower)
      gen10_bundle = Map.put(gen10_bundle, "bundle_sha256", gen10_hash)
      assert {:ok, _} = AtomicStore.write_bundle(bundle_dir, gen10_bundle, now: now)

      # Point current symlink back to generation 9
      current_symlink = Path.join(bundle_dir, "current")
      File.rm(current_symlink)
      File.ln_s(Path.join("generations", "9"), current_symlink)

      # Delete watermark.json to simulate missing watermark
      File.rm(Path.join(bundle_dir, "watermark.json"))

      # Unified scanner must find generation 10 across generations/
      assert {:ok, surviving} = BundleValidator.find_surviving_disk_bundle(bundle_dir)
      assert surviving.generation == 10

      # Start manager: must establish generation 10 baseline, NOT generation 9
      {:ok, manager} =
        TrustBundleManager.start_link(
          state_dir: tmp_dir,
          bundle_dir: bundle_dir,
          agent_id: "agent-missing-wm-gen10-test",
          name: :test_missing_wm_gen10_manager
        )

      status = TrustBundleManager.status(manager)
      assert status.lkg_generation == 10
      assert status.needs_repair == true

      # Core now presents generation 9: must be rejected as generation_downgrade_rejected
      assert {:error, :generation_downgrade_rejected, receipt} =
               TrustBundleManager.process_bundle(manager, gen9_bundle, now: now)

      assert receipt["last_error_code"] == "generation_downgrade_rejected"

      # Baseline must remain generation 10
      status_after = TrustBundleManager.status(manager)
      assert status_after.lkg_generation == 10
    end

    test "unified recovery quarantines damaged or conflicting retained evidence when watermark is missing",
         %{
           tmp_dir: tmp_dir
         } do
      bundle_dir = Path.join(tmp_dir, "pki_missing_wm_damaged_evidence_test")
      File.mkdir_p!(bundle_dir)

      # Create generation 1 directory with corrupted manifest.json
      gen1_dir = Path.join([bundle_dir, "generations", "1"])
      File.mkdir_p!(gen1_dir)
      File.write!(Path.join(gen1_dir, "manifest.json"), "{ truncated json")

      # Missing watermark + damaged candidate on disk -> BundleValidator returns corrupted candidate
      assert {:error, {:corrupted_candidate, _, _}} =
               BundleValidator.find_surviving_disk_bundle(bundle_dir)

      # Manager must enter quarantine rather than treating as clean initial enrollment!
      {:ok, manager} =
        TrustBundleManager.start_link(
          state_dir: tmp_dir,
          bundle_dir: bundle_dir,
          agent_id: "agent-missing-wm-corrupt-candidate-test",
          name: :test_missing_wm_corrupt_candidate_manager
        )

      status = TrustBundleManager.status(manager)
      assert status.status == "recovery_required"
      assert status.recovery_mode == :quarantined
    end

    test "observation sequence is durably persisted and incremented across restarts",
         %{
           tmp_dir: tmp_dir,
           now: now,
           bundle: bundle
         } do
      bundle_dir = Path.join(tmp_dir, "pki_durable_sequence_test")
      File.mkdir_p!(bundle_dir)

      {:ok, manager1} =
        TrustBundleManager.start_link(
          state_dir: tmp_dir,
          bundle_dir: bundle_dir,
          agent_id: "agent-seq-test",
          name: :test_seq_manager_1
        )

      assert {:ok, receipt1} = TrustBundleManager.process_bundle(manager1, bundle, now: now)
      assert receipt1["observation_sequence"] == 1

      # Assert observation_sequence.json on disk
      seq_file = Path.join(bundle_dir, "observation_sequence.json")
      assert File.exists?(seq_file)
      assert {:ok, 1} = AtomicStore.read_observation_sequence(bundle_dir)

      # Stop manager 1
      GenServer.stop(manager1)

      # Start new manager instance pointing to the same bundle directory
      {:ok, manager2} =
        TrustBundleManager.start_link(
          state_dir: tmp_dir,
          bundle_dir: bundle_dir,
          agent_id: "agent-seq-test",
          name: :test_seq_manager_2
        )

      status = TrustBundleManager.status(manager2)
      assert status.observation_sequence == 1

      # Next bundle operation advances sequence to 2
      assert {:ok, receipt2} = TrustBundleManager.process_bundle(manager2, bundle, now: now)
      assert receipt2["observation_sequence"] == 2
      assert {:ok, 2} = AtomicStore.read_observation_sequence(bundle_dir)
    end

    test "filesystem operation tracing asserts directory sync occurs strictly after watermark rename",
         %{
           tmp_dir: tmp_dir,
           now: now,
           bundle: bundle
         } do
      bundle_dir = Path.join(tmp_dir, "pki_op_tracing_test")
      File.mkdir_p!(bundle_dir)

      # 1. Standalone write_watermark
      dummy_val = %{
        generation: 1,
        crl_number: 1,
        ca_fingerprint: String.duplicate("a", 64),
        bundle_sha256: String.duplicate("b", 64)
      }

      tracer1 = start_op_tracer()

      assert :ok =
               AtomicStore.write_watermark(bundle_dir, dummy_val, record_operations_to: tracer1)

      wm_path = Path.join(bundle_dir, "watermark.json")
      ops1 = get_traced_ops(tracer1)

      # Strict ordering assertion: rename precedes fsync
      assert ops1 == [
               {:rename_watermark, wm_path},
               {:fsync_watermark_dir, bundle_dir}
             ]

      # 2. Full publication via write_bundle
      bundle_dir_pub = Path.join(tmp_dir, "pki_op_tracing_pub_test")
      File.mkdir_p!(bundle_dir_pub)

      tracer2 = start_op_tracer()

      assert {:ok, _} =
               AtomicStore.write_bundle(bundle_dir_pub, bundle,
                 now: now,
                 record_operations_to: tracer2
               )

      pub_wm_path = Path.join(bundle_dir_pub, "watermark.json")
      pub_gen_dir = Path.join([bundle_dir_pub, "generations", to_string(bundle["generation"])])
      pub_gens_dir = Path.join(bundle_dir_pub, "generations")

      ops2 = get_traced_ops(tracer2)

      assert ops2 == [
               {:rename_generation, pub_gen_dir},
               {:fsync_generations_dir, pub_gens_dir},
               {:rename_watermark, pub_wm_path},
               {:fsync_watermark_dir, bundle_dir_pub},
               {:switch_symlink, bundle["generation"]},
               {:fsync_base_dir, bundle_dir_pub}
             ]
    end

    test "unified recovery quarantines conflicting retained generations with different CA keys",
         %{
           tmp_dir: tmp_dir,
           now: now,
           bundle: bundle
         } do
      bundle_dir = Path.join(tmp_dir, "pki_missing_wm_conflicting_ca_test")
      File.mkdir_p!(bundle_dir)

      # 1. Publish Gen 1 with original CA
      gen1_bundle = Map.put(bundle, "generation", 1) |> Map.put("crl_number", 1)
      assert {:ok, _} = AtomicStore.write_bundle(bundle_dir, gen1_bundle, now: now)

      # 2. Create another CA key and cert
      ca_key_2 = X509.PrivateKey.new_ec(:secp256r1)

      ca_cert_2 =
        X509.Certificate.self_signed(
          ca_key_2,
          "/CN=SecretHub Alternative Root CA",
          template: :root_ca,
          validity: 30
        )

      ca_pem_2 = X509.Certificate.to_pem(ca_cert_2)
      ca_der_2 = X509.Certificate.to_der(ca_cert_2)
      ca_fp_2 = :crypto.hash(:sha256, ca_der_2) |> Base.encode16(case: :lower)

      crl_2 =
        X509.CRL.new([], ca_cert_2, ca_key_2,
          this_update: now,
          next_update: DateTime.add(now, 3600, :second),
          extensions: [crl_number: X509.CRL.Extension.crl_number(2)]
        )

      crl_2_pem = X509.CRL.to_pem(crl_2)
      crl_2_der = X509.CRL.to_der(crl_2)
      crl_2_sha256 = :crypto.hash(:sha256, crl_2_der) |> Base.encode16(case: :lower)

      gen2_bundle =
        bundle
        |> Map.put("generation", 2)
        |> Map.put("crl_number", 2)
        |> Map.put("this_update", DateTime.to_iso8601(now))
        |> Map.put("next_update", DateTime.to_iso8601(DateTime.add(now, 3600, :second)))
        |> Map.put("ca_fingerprint", ca_fp_2)
        |> Map.put("ca_bundle_pem", ca_pem_2)
        |> Map.put("crl_pem", crl_2_pem)
        |> Map.put("crl_der_sha256", crl_2_sha256)

      t2 =
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

      gen2_hash = :crypto.hash(:sha256, t2) |> Base.encode16(case: :lower)
      gen2_bundle = Map.put(gen2_bundle, "bundle_sha256", gen2_hash)

      # Publish Gen 2 directly to generations/2
      gen2_dir = Path.join([bundle_dir, "generations", "2"])
      File.mkdir_p!(gen2_dir)
      File.write!(Path.join(gen2_dir, "ca.crt"), ca_pem_2)
      File.write!(Path.join(gen2_dir, "crl.pem"), crl_2_pem)
      File.write!(Path.join(gen2_dir, "manifest.json"), Jason.encode!(gen2_bundle))

      # Delete watermark.json to trigger recovery
      File.rm(Path.join(bundle_dir, "watermark.json"))

      # Unified validator detects conflicting CA fingerprints
      assert {:error, {:conflicting_recovery_evidence, :ca_fingerprint_conflict}} =
               BundleValidator.find_surviving_disk_bundle(bundle_dir)

      # Manager must enter quarantine
      {:ok, manager} =
        TrustBundleManager.start_link(
          state_dir: tmp_dir,
          bundle_dir: bundle_dir,
          agent_id: "agent-missing-wm-ca-conflict",
          name: :test_missing_wm_ca_conflict_mgr
        )

      status = TrustBundleManager.status(manager)
      assert status.recovery_mode == :quarantined
      assert status.status == "recovery_required"
    end

    test "watermark write failure during startup recovery preserves surviving lower bound in memory",
         %{
           tmp_dir: tmp_dir,
           now: now,
           ca_key: ca_key,
           ca_cert: ca_cert,
           bundle: bundle
         } do
      bundle_dir = Path.join(tmp_dir, "pki_wm_write_failure_recovery_test")
      File.mkdir_p!(bundle_dir)

      crl_10 =
        X509.CRL.new([], ca_cert, ca_key,
          this_update: now,
          next_update: DateTime.add(now, 3600, :second),
          extensions: [crl_number: X509.CRL.Extension.crl_number(10)]
        )

      crl_10_pem = X509.CRL.to_pem(crl_10)
      crl_10_der = X509.CRL.to_der(crl_10)
      crl_10_sha256 = :crypto.hash(:sha256, crl_10_der) |> Base.encode16(case: :lower)

      gen10_bundle =
        bundle
        |> Map.put("generation", 10)
        |> Map.put("crl_number", 10)
        |> Map.put("this_update", DateTime.to_iso8601(now))
        |> Map.put("next_update", DateTime.to_iso8601(DateTime.add(now, 3600, :second)))
        |> Map.put("crl_pem", crl_10_pem)
        |> Map.put("crl_der_sha256", crl_10_sha256)

      t10 =
        [
          gen10_bundle["schema_version"],
          gen10_bundle["authority"],
          gen10_bundle["generation"],
          gen10_bundle["ca_fingerprint"],
          gen10_bundle["crl_number"],
          gen10_bundle["crl_der_sha256"],
          gen10_bundle["this_update"],
          gen10_bundle["next_update"],
          gen10_bundle["ca_bundle_pem"],
          gen10_bundle["crl_pem"]
        ]
        |> Enum.map(&to_string/1)
        |> Enum.join("|")

      gen10_hash = :crypto.hash(:sha256, t10) |> Base.encode16(case: :lower)
      gen10_bundle = Map.put(gen10_bundle, "bundle_sha256", gen10_hash)
      assert {:ok, _} = AtomicStore.write_bundle(bundle_dir, gen10_bundle, now: now)

      # Delete watermark.json so startup recovery attempts to recreate it
      File.rm(Path.join(bundle_dir, "watermark.json"))

      # Start manager with injected directory sync error on watermark recreation
      {:ok, manager} =
        TrustBundleManager.start_link(
          state_dir: tmp_dir,
          bundle_dir: bundle_dir,
          agent_id: "agent-wm-write-failure-test",
          name: :test_wm_write_failure_mgr,
          inject_watermark_fsync_error: :eio
        )

      status = TrustBundleManager.status(manager)

      # Surviving generation 10 MUST be preserved in memory as lower bound (not 0)
      assert status.lkg_generation == 10
      assert status.needs_repair == true
      assert status.status == "repair_required"
      assert status.last_error_code == :watermark_persistence_failed
    end

    test "core sequence bootstrap and crash recovery after allocation before delivery",
         %{
           tmp_dir: tmp_dir,
           now: now,
           bundle: bundle
         } do
      bundle_dir = Path.join(tmp_dir, "pki_seq_bootstrap_and_crash_test")
      File.mkdir_p!(bundle_dir)

      # 1. Start agent with clean state (no sequence file on disk)
      {:ok, manager} =
        TrustBundleManager.start_link(
          state_dir: tmp_dir,
          bundle_dir: bundle_dir,
          agent_id: "agent-bootstrap-crash-test",
          name: :test_seq_bootstrap_manager_1
        )

      assert TrustBundleManager.status(manager).observation_sequence == 0

      # 2. Bundle from Core includes last_accepted_sequence: 100
      bundle_from_core = Map.put(bundle, "last_accepted_sequence", 100)

      # Applying bundle bootstraps from 100 to 101
      assert {:ok, receipt1} =
               TrustBundleManager.process_bundle(manager, bundle_from_core, now: now)

      assert receipt1["observation_sequence"] == 101
      assert {:ok, 101} = AtomicStore.read_observation_sequence(bundle_dir)

      # Check pending observation was persisted
      assert {:ok, pending} = AtomicStore.read_pending_observation(bundle_dir)
      assert is_map(pending)
      assert pending["observation_sequence"] == 101

      GenServer.stop(manager)

      # 3. Simulate crash after allocating sequence 105 and persisting pending receipt before delivery
      crashed_receipt = %{
        "agent_id" => "agent-bootstrap-crash-test",
        "observation_sequence" => 105,
        "status" => "applied",
        "generation" => bundle["generation"]
      }

      assert :ok =
               AtomicStore.persist_observation_sequence(bundle_dir, 105,
                 pending_receipt: crashed_receipt
               )

      # 4. Restart manager pointing to same bundle directory
      # Agent must restore sequence 105 and resubmit the pending observation
      {:ok, manager2} =
        TrustBundleManager.start_link(
          state_dir: tmp_dir,
          bundle_dir: bundle_dir,
          agent_id: "agent-bootstrap-crash-test",
          name: :test_seq_bootstrap_manager_2
        )

      status = TrustBundleManager.status(manager2)
      assert status.observation_sequence == 105

      # 5. Next bundle processed gets sequence 106 (> 105)
      assert {:ok, receipt2} =
               TrustBundleManager.process_bundle(manager2, bundle, now: now)

      assert receipt2["observation_sequence"] == 106
      assert {:ok, 106} = AtomicStore.read_observation_sequence(bundle_dir)
    end

    test "recovery treats damaged non-directory installations as corrupted rather than empty (Finding 1)",
         %{tmp_dir: tmp_dir} do
      bundle_dir = Path.join(tmp_dir, "pki_damaged_entry_recovery_test")
      File.mkdir_p!(bundle_dir)

      # 1. Clean empty installation returns :empty_installation
      assert {:error, :empty_installation} =
               BundleValidator.find_surviving_disk_bundle(bundle_dir)

      # 2. generations/ containing a regular file (not a dir)
      gen_dir = Path.join(bundle_dir, "generations")
      File.mkdir_p!(gen_dir)
      bad_file = Path.join(gen_dir, "stray_file.txt")
      File.write!(bad_file, "not a directory")

      assert {:error, {:corrupted_candidate, ^bad_file, {:unexpected_file_type, :regular}}} =
               BundleValidator.find_surviving_disk_bundle(bundle_dir)

      # Manager must enter quarantine mode
      {:ok, manager1} =
        TrustBundleManager.start_link(
          state_dir: tmp_dir,
          bundle_dir: bundle_dir,
          agent_id: "agent-damaged-entry-test",
          name: :test_damaged_entry_manager_1
        )

      status1 = TrustBundleManager.status(manager1)
      assert status1.status == "recovery_required"
      assert status1.recovery_mode == :quarantined
      GenServer.stop(manager1)

      # 3. generations/ containing a broken symlink
      File.rm!(bad_file)
      broken_symlink = Path.join(gen_dir, "broken_link")
      File.ln_s!("/nonexistent/target/path", broken_symlink)

      assert {:error, {:corrupted_candidate, ^broken_symlink, {:broken_symlink, :enoent}}} =
               BundleValidator.find_surviving_disk_bundle(bundle_dir)

      {:ok, manager2} =
        TrustBundleManager.start_link(
          state_dir: tmp_dir,
          bundle_dir: bundle_dir,
          agent_id: "agent-damaged-entry-test",
          name: :test_damaged_entry_manager_2
        )

      status2 = TrustBundleManager.status(manager2)
      assert status2.status == "recovery_required"
      assert status2.recovery_mode == :quarantined
      GenServer.stop(manager2)
    end

    test "sequence persistence failure prevents receipt transmission and returns error (Finding 2)",
         %{tmp_dir: tmp_dir, bundle: bundle, now: now} do
      bundle_dir = Path.join(tmp_dir, "pki_sequence_failure_gating_test")
      File.mkdir_p!(bundle_dir)

      {:ok, manager} =
        TrustBundleManager.start_link(
          state_dir: tmp_dir,
          bundle_dir: bundle_dir,
          agent_id: "agent-seq-fail-test",
          name: :test_seq_fail_manager
        )

      # Inject sequence persistence error during process_bundle
      assert {:error, :receipt_persistence_failed, nil} =
               TrustBundleManager.process_bundle(manager, bundle,
                 now: now,
                 inject_sequence_persistence_error: :eio
               )

      # Bundle was written to disk, but receipt was NOT emitted/persisted
      assert {:ok, %{highest_sequence: 0, outbox: []}} = AtomicStore.read_outbox(bundle_dir)

      # Now process bundle without failure injection -> succeeds and enqueues receipt
      assert {:ok, receipt} = TrustBundleManager.process_bundle(manager, bundle, now: now)
      assert receipt["observation_sequence"] == 1

      assert {:ok, %{highest_sequence: 1, outbox: [outbox_entry]}} =
               AtomicStore.read_outbox(bundle_dir)

      assert outbox_entry["sequence"] == 1
      assert outbox_entry["receipt"]["observation_sequence"] == 1
    end

    test "durable outbox enqueues and drains receipts sequentially (Finding 3)",
         %{tmp_dir: tmp_dir, bundle: bundle, now: now} do
      bundle_dir = Path.join(tmp_dir, "pki_durable_outbox_test")
      File.mkdir_p!(bundle_dir)

      # Mock connection that records receipts in agent process
      test_pid = self()

      mock_conn =
        spawn(fn ->
          # Simple receive loop
          receive_loop = fn loop ->
            receive do
              {:"$gen_call", from, {:submit_bundle_receipt, receipt}} ->
                send(test_pid, {:submitted_receipt, receipt})
                GenServer.reply(from, {:ok, %{"status" => "recorded"}})
                loop.(loop)

              _other ->
                loop.(loop)
            end
          end

          receive_loop.(receive_loop)
        end)

      Process.register(mock_conn, :test_mock_conn_pki)

      {:ok, manager} =
        TrustBundleManager.start_link(
          state_dir: tmp_dir,
          bundle_dir: bundle_dir,
          agent_id: "agent-outbox-test",
          connection_mod: :test_mock_conn_pki,
          name: :test_outbox_manager
        )

      # Process first bundle
      assert {:ok, receipt1} = TrustBundleManager.process_bundle(manager, bundle, now: now)
      assert receipt1["observation_sequence"] == 1

      # Receipt received by mock conn
      assert_receive {:submitted_receipt, submitted1}, 2000
      assert submitted1["observation_sequence"] == 1

      # Give outbox loop a moment to acknowledge
      Process.sleep(50)
      assert {:ok, %{highest_sequence: 1, outbox: []}} = AtomicStore.read_outbox(bundle_dir)

      GenServer.stop(manager)
    end

    test "existing-generation reuse validates json object shape and handles scalars safely (Finding 4)",
         %{tmp_dir: tmp_dir, bundle: bundle} do
      bundle_dir = Path.join(tmp_dir, "pki_json_shape_test")
      File.mkdir_p!(bundle_dir)

      gen1_dir = Path.join([bundle_dir, "generations", "1"])
      File.mkdir_p!(gen1_dir)

      # Write a scalar JSON (e.g. 123) as manifest.json
      File.write!(Path.join(gen1_dir, "manifest.json"), "123")

      # AtomicStore.write_bundle should return corrupted error without crashing with BadMapError
      assert {:error, :corrupted_existing_generation} =
               AtomicStore.write_bundle(bundle_dir, bundle)

      # Write JSON array
      File.write!(Path.join(gen1_dir, "manifest.json"), "[\"a\", \"b\"]")

      assert {:error, :corrupted_existing_generation} =
               AtomicStore.write_bundle(bundle_dir, bundle)

      # Write JSON object with missing bundle_sha256
      File.write!(Path.join(gen1_dir, "manifest.json"), "{\"other\": \"value\"}")

      assert {:error, :corrupted_existing_generation} =
               AtomicStore.write_bundle(bundle_dir, bundle)
    end

    test "ACK persistence failure backs off outbox draining, maintains responsiveness, and unblocks on recovery (P1 finding)",
         %{tmp_dir: tmp_dir, bundle: _bundle, now: now} do
      bundle_dir = Path.join(tmp_dir, "pki_ack_fail_backoff_test")
      File.mkdir_p!(bundle_dir)

      test_pid = self()

      # Mock connection that counts submissions
      mock_conn =
        spawn(fn ->
          loop_fn = fn loop, count ->
            receive do
              {:"$gen_call", from, {:submit_bundle_receipt, receipt}} ->
                send(test_pid, {:submitted_receipt, receipt["observation_sequence"], count})
                GenServer.reply(from, {:ok, %{"status" => "recorded"}})
                loop.(loop, count + 1)

              _other ->
                loop.(loop, count)
            end
          end

          loop_fn.(loop_fn, 1)
        end)

      Process.register(mock_conn, :test_mock_ack_fail_conn)

      # 1. Enqueue observation with seq 1
      receipt_data = %{
        "agent_id" => "agent-ack-fail-test",
        "observation_sequence" => 1,
        "status" => "applied",
        "applied_at" => DateTime.to_iso8601(now)
      }

      assert {:ok, 1, _} = AtomicStore.enqueue_observation(bundle_dir, receipt_data)

      # 2. Start manager with ACK persistence error injected before rename and short backoff
      {:ok, manager} =
        TrustBundleManager.start_link(
          state_dir: tmp_dir,
          bundle_dir: bundle_dir,
          agent_id: "agent-ack-fail-test",
          connection_mod: :test_mock_ack_fail_conn,
          inject_sequence_rename_error: :eio,
          outbox_drain_backoff_ms: 100,
          name: :test_ack_fail_manager
        )

      # Wait for first submission
      assert_receive {:submitted_receipt, 1, 1}, 2000

      # GenServer is responsive to status calls during outbox operations and backoff
      status = TrustBundleManager.status(manager)
      assert is_map(status)

      # Verify it does not spin in a tight loop: count should not rapidly increase
      refute_receive {:submitted_receipt, 1, 2}, 50

      # Outbox still contains sequence 1 because ACK persistence failed before rename
      assert {:ok, %{outbox: [entry]}} = AtomicStore.read_outbox(bundle_dir)
      assert entry["sequence"] == 1

      # 3. Clear failure injection (recovery)
      assert :ok = TrustBundleManager.set_store_opts(manager, outbox_drain_backoff_ms: 100)

      # Wait for backoff retry to submit and successfully persist ACK
      assert_receive {:submitted_receipt, 1, 2}, 2000

      # Wait briefly for async ACK write to finish
      Process.sleep(50)
      assert {:ok, %{outbox: []}} = AtomicStore.read_outbox(bundle_dir)

      GenServer.stop(manager)
    end

    test "channel wire-format sequence conflict is permanently rejected and moved to dead-letter (P2 finding)",
         %{tmp_dir: tmp_dir, now: now} do
      bundle_dir = Path.join(tmp_dir, "pki_wire_conflict_dead_letter_test")
      File.mkdir_p!(bundle_dir)

      test_pid = self()

      mock_conn =
        spawn(fn ->
          loop_fn = fn loop ->
            receive do
              {:"$gen_call", from, {:submit_bundle_receipt, %{"observation_sequence" => 1}}} ->
                # Wire format from AgentRuntimeChannel
                send(test_pid, {:submitted_seq, 1})

                GenServer.reply(
                  from,
                  {:error,
                   %{
                     "reason" => "conflicting_observation_sequence",
                     "detail" => "differing payload for sequence 1"
                   }}
                )

                loop.(loop)

              {:"$gen_call", from, {:submit_bundle_receipt, %{"observation_sequence" => 2}}} ->
                send(test_pid, {:submitted_seq, 2})
                GenServer.reply(from, {:ok, %{"status" => "recorded"}})
                loop.(loop)

              _other ->
                loop.(loop)
            end
          end

          loop_fn.(loop_fn)
        end)

      Process.register(mock_conn, :test_mock_conflict_conn)

      # Enqueue seq 1 (conflicting) and seq 2 (valid)
      receipt1 = %{
        "agent_id" => "agent-conflict-test",
        "observation_sequence" => 1,
        "status" => "failed",
        "applied_at" => DateTime.to_iso8601(now)
      }

      receipt2 = %{
        "agent_id" => "agent-conflict-test",
        "observation_sequence" => 2,
        "status" => "applied",
        "applied_at" => DateTime.to_iso8601(now)
      }

      assert {:ok, 1, _} = AtomicStore.enqueue_observation(bundle_dir, receipt1)
      assert {:ok, 2, _} = AtomicStore.enqueue_observation(bundle_dir, receipt2)

      {:ok, manager} =
        TrustBundleManager.start_link(
          state_dir: tmp_dir,
          bundle_dir: bundle_dir,
          agent_id: "agent-conflict-test",
          connection_mod: :test_mock_conflict_conn,
          name: :test_conflict_manager
        )

      # Seq 1 submitted and rejected
      assert_receive {:submitted_seq, 1}, 2000
      # Seq 2 submitted next because seq 1 was moved to dead letter and yielded to next turn
      assert_receive {:submitted_seq, 2}, 2000

      Process.sleep(50)

      # Outbox should now be completely drained
      assert {:ok, %{outbox: []}} = AtomicStore.read_outbox(bundle_dir)

      # Dead-letter observations contains receipt 1 with rejection reason
      assert {:ok, [dead_letter]} = AtomicStore.read_dead_letter_observations(bundle_dir)
      assert dead_letter["sequence"] == 1
      assert dead_letter["rejection_code"] == "conflicting_observation_sequence"

      GenServer.stop(manager)
    end

    test "outbox validation enforces strict invariants and preserves corrupted file without clobbering (P2 finding)",
         %{tmp_dir: tmp_dir, now: now} do
      bundle_dir = Path.join(tmp_dir, "pki_strict_outbox_invariants_test")
      File.mkdir_p!(bundle_dir)
      outbox_path = Path.join(bundle_dir, "observation_sequence.json")

      # Case 1: Sequence ahead of top-level counter
      corrupted_ahead = %{
        "observation_sequence" => 1,
        "outbox" => [
          %{
            "sequence" => 5,
            "receipt" => %{
              "agent_id" => "agent-1",
              "observation_sequence" => 5,
              "status" => "applied",
              "applied_at" => DateTime.to_iso8601(now)
            }
          }
        ]
      }

      File.write!(outbox_path, Jason.encode!(corrupted_ahead))

      assert {:error, {:corrupted_outbox, {:entry_sequence_ahead_of_watermark, 5, 1}}} =
               AtomicStore.read_outbox(bundle_dir)

      # Verify file was NOT modified or clobbered
      assert File.read!(outbox_path) == Jason.encode!(corrupted_ahead)

      # Starting manager with this corrupted outbox enters quarantine
      {:ok, manager} =
        TrustBundleManager.start_link(
          state_dir: tmp_dir,
          bundle_dir: bundle_dir,
          agent_id: "agent-corrupted-outbox-test",
          name: :test_corrupted_outbox_manager
        )

      status = TrustBundleManager.status(manager)
      assert status.status == "recovery_required"
      assert status.recovery_mode == :quarantined
      assert status.last_error_code == :corrupted_outbox

      GenServer.stop(manager)

      # Case 2: Duplicate sequence in outbox
      corrupted_duplicate = %{
        "observation_sequence" => 3,
        "outbox" => [
          %{
            "sequence" => 2,
            "receipt" => %{
              "agent_id" => "agent-1",
              "observation_sequence" => 2,
              "status" => "applied",
              "applied_at" => DateTime.to_iso8601(now)
            }
          },
          %{
            "sequence" => 2,
            "receipt" => %{
              "agent_id" => "agent-1",
              "observation_sequence" => 2,
              "status" => "applied",
              "applied_at" => DateTime.to_iso8601(now)
            }
          }
        ]
      }

      File.write!(outbox_path, Jason.encode!(corrupted_duplicate))

      assert {:error, {:corrupted_outbox, :duplicate_sequence_in_outbox}} =
               AtomicStore.read_outbox(bundle_dir)

      # Case 3: Sequence mismatch between entry and receipt
      corrupted_mismatch = %{
        "observation_sequence" => 3,
        "outbox" => [
          %{
            "sequence" => 2,
            "receipt" => %{
              "agent_id" => "agent-1",
              "observation_sequence" => 1,
              "status" => "applied",
              "applied_at" => DateTime.to_iso8601(now)
            }
          }
        ]
      }

      File.write!(outbox_path, Jason.encode!(corrupted_mismatch))

      assert {:error, {:corrupted_outbox, {:receipt_sequence_mismatch, 1, 2}}} =
               AtomicStore.read_outbox(bundle_dir)

      # Case 4: Missing receipt field
      corrupted_missing_field = %{
        "observation_sequence" => 3,
        "outbox" => [
          %{
            "sequence" => 2,
            "receipt" => %{
              "observation_sequence" => 2,
              "status" => "applied",
              "applied_at" => DateTime.to_iso8601(now)
            }
          }
        ]
      }

      File.write!(outbox_path, Jason.encode!(corrupted_missing_field))

      assert {:error, {:corrupted_outbox, {:missing_receipt_field, "agent_id", 2}}} =
               AtomicStore.read_outbox(bundle_dir)

      # Case 5: Non-list outbox
      corrupted_non_list = %{
        "observation_sequence" => 3,
        "outbox" => "not_a_list"
      }

      File.write!(outbox_path, Jason.encode!(corrupted_non_list))

      assert {:error, {:corrupted_outbox, :invalid_outbox_format}} =
               AtomicStore.read_outbox(bundle_dir)
    end

    test "enqueue_observation validates entry before durable commit and rejects invalid entries",
         %{tmp_dir: tmp_dir, now: now} do
      bundle_dir = Path.join(tmp_dir, "pki_enqueue_validation_test")
      File.mkdir_p!(bundle_dir)

      # Missing agent_id
      invalid_receipt1 = %{
        "status" => "applied",
        "applied_at" => DateTime.to_iso8601(now)
      }

      assert {:error,
              {:sequence_persistence_failed,
               {:invalid_outbox_entry, {:missing_receipt_field, "agent_id", 1}}}} =
               AtomicStore.enqueue_observation(bundle_dir, invalid_receipt1)

      # Empty agent_id
      invalid_receipt2 = %{
        "agent_id" => "",
        "status" => "applied",
        "applied_at" => DateTime.to_iso8601(now)
      }

      assert {:error,
              {:sequence_persistence_failed,
               {:invalid_outbox_entry, {:missing_receipt_field, "agent_id", 1}}}} =
               AtomicStore.enqueue_observation(bundle_dir, invalid_receipt2)

      # Outbox file should not even exist or should be empty
      assert {:ok, %{highest_sequence: 0, outbox: []}} = AtomicStore.read_outbox(bundle_dir)

      # Valid receipt enqueues successfully
      valid_receipt = %{
        "agent_id" => "agent-valid",
        "status" => "applied",
        "applied_at" => DateTime.to_iso8601(now)
      }

      assert {:ok, 1, recorded} = AtomicStore.enqueue_observation(bundle_dir, valid_receipt)
      assert recorded["agent_id"] == "agent-valid"
      assert recorded["observation_sequence"] == 1

      # Invalid enqueue input must leave outbox bytes and sequence unchanged
      outbox_path = Path.join(bundle_dir, "observation_sequence.json")
      bytes_before = File.read!(outbox_path)

      invalid_receipt3 = %{
        "agent_id" => "agent-valid",
        "status" => "",
        "applied_at" => DateTime.to_iso8601(now)
      }

      assert {:error,
              {:sequence_persistence_failed,
               {:invalid_outbox_entry, {:missing_receipt_field, "status", 2}}}} =
               AtomicStore.enqueue_observation(bundle_dir, invalid_receipt3)

      assert File.read!(outbox_path) == bytes_before
      assert {:ok, %{highest_sequence: 1, outbox: [single]}} = AtomicStore.read_outbox(bundle_dir)
      assert single["sequence"] == 1
    end

    test "persist_observation_sequence validates pending receipt before durable commit",
         %{tmp_dir: tmp_dir, now: now} do
      bundle_dir = Path.join(tmp_dir, "pki_persist_validation_test")
      File.mkdir_p!(bundle_dir)

      # Missing agent_id in pending receipt
      invalid_receipt = %{
        "observation_sequence" => 1,
        "status" => "applied",
        "applied_at" => DateTime.to_iso8601(now)
      }

      assert {:error,
              {:sequence_persistence_failed,
               {:invalid_outbox_entry, {:missing_receipt_field, "agent_id", 1}}}} =
               AtomicStore.persist_observation_sequence(bundle_dir, 1,
                 pending_receipt: invalid_receipt
               )

      assert {:ok, %{highest_sequence: 0, outbox: []}} = AtomicStore.read_outbox(bundle_dir)
    end

    test "repair_outbox_metadata backfills missing agent_id and applied_at without touching watermark",
         %{tmp_dir: tmp_dir, now: now} do
      bundle_dir = Path.join(tmp_dir, "pki_repair_metadata_test")
      File.mkdir_p!(bundle_dir)
      outbox_path = Path.join(bundle_dir, "observation_sequence.json")

      raw_data = %{
        "observation_sequence" => 2,
        "outbox" => [
          %{
            "sequence" => 1,
            "receipt" => %{
              "agent_id" => nil,
              "observation_sequence" => 1,
              "status" => "applied",
              "applied_at" => ""
            },
            "enqueued_at" => DateTime.to_iso8601(now)
          },
          %{
            "sequence" => 2,
            "receipt" => %{
              "agent_id" => "",
              "observation_sequence" => 2,
              "status" => "failed",
              "applied_at" => DateTime.to_iso8601(now)
            },
            "enqueued_at" => DateTime.to_iso8601(now)
          }
        ],
        "updated_at" => DateTime.to_iso8601(now)
      }

      File.write!(outbox_path, Jason.encode!(raw_data))

      # Before repair, read_outbox reports corruption
      assert {:error, {:corrupted_outbox, {:missing_receipt_field, "agent_id", 1}}} =
               AtomicStore.read_outbox(bundle_dir)

      # Run repair
      assert :ok = AtomicStore.repair_outbox_metadata(bundle_dir, %{agent_id: "agent-repaired"})

      # Verify original file evidence was preserved in immutable content-addressed backup before modification
      content_sha256 =
        :crypto.hash(:sha256, Jason.encode!(raw_data)) |> Base.encode16(case: :lower)

      bak_path = Path.join(bundle_dir, "observation_sequence.json.bak-" <> content_sha256)
      assert File.exists?(bak_path)
      assert File.read!(bak_path) == Jason.encode!(raw_data)

      # Repair with conflicting non-empty agent_id is strictly rejected and does not overwrite
      assert {:error, {:conflicting_outbox_identity, "agent-repaired", "agent-other"}} =
               AtomicStore.repair_outbox_metadata(bundle_dir, %{agent_id: "agent-other"})

      # After repair, outbox is clean and valid
      assert {:ok, %{highest_sequence: 2, outbox: entries}} = AtomicStore.read_outbox(bundle_dir)
      assert length(entries) == 2
      assert Enum.at(entries, 0)["receipt"]["agent_id"] == "agent-repaired"
      assert Enum.at(entries, 0)["receipt"]["applied_at"] != ""
      assert Enum.at(entries, 1)["receipt"]["agent_id"] == "agent-repaired"
    end

    test "TrustBundleManager binds identity dynamically, repairs outbox, and clears quarantine",
         %{tmp_dir: tmp_dir, now: now} do
      bundle_dir = Path.join(tmp_dir, "pki_bind_identity_test")
      File.mkdir_p!(bundle_dir)
      outbox_path = Path.join(bundle_dir, "observation_sequence.json")

      # Put corrupted outbox with missing agent_id
      raw_data = %{
        "observation_sequence" => 1,
        "outbox" => [
          %{
            "sequence" => 1,
            "receipt" => %{
              "agent_id" => nil,
              "observation_sequence" => 1,
              "status" => "applied",
              "applied_at" => DateTime.to_iso8601(now)
            },
            "enqueued_at" => DateTime.to_iso8601(now)
          }
        ],
        "updated_at" => DateTime.to_iso8601(now)
      }

      File.write!(outbox_path, Jason.encode!(raw_data))

      # Start manager without agent_id
      {:ok, manager} =
        TrustBundleManager.start_link(
          state_dir: tmp_dir,
          bundle_dir: bundle_dir,
          name: :test_bind_identity_manager
        )

      status = TrustBundleManager.status(manager)
      assert status.recovery_mode == :quarantined
      assert status.last_error_code == :corrupted_outbox

      # Dynamically bind identity
      assert :ok = TrustBundleManager.bind_identity(manager, "agent-dynamic-123")

      # Outbox repaired and quarantine lifted
      status_after = TrustBundleManager.status(manager)
      assert status_after.recovery_mode == :none
      assert status_after.last_error_code == nil
      assert status_after.observation_sequence == 1

      GenServer.stop(manager)
    end

    test "apply_bundle returns {:error, :waiting_for_identity, nil, state} when agent identity unbound",
         %{tmp_dir: tmp_dir, bundle: bundle} do
      bundle_dir = Path.join(tmp_dir, "pki_unbound_identity_apply_test")
      File.mkdir_p!(bundle_dir)

      {:ok, manager} =
        TrustBundleManager.start_link(
          state_dir: tmp_dir,
          bundle_dir: bundle_dir,
          agent_id: nil,
          name: :test_unbound_apply_manager
        )

      assert {:error, :waiting_for_identity, nil} =
               TrustBundleManager.process_bundle(manager, bundle)

      # Outbox must remain completely empty
      assert {:ok, %{highest_sequence: 0, outbox: []}} = AtomicStore.read_outbox(bundle_dir)

      # Now bind identity and verify application succeeds
      assert :ok = TrustBundleManager.bind_identity(manager, "agent-bound-456")
      assert {:ok, receipt} = TrustBundleManager.process_bundle(manager, bundle)
      assert receipt["status"] == "applied"
      assert receipt["agent_id"] == "agent-bound-456"

      GenServer.stop(manager)
    end

    test "dead-letter error propagation on read failure and idempotency on duplicate append",
         %{tmp_dir: tmp_dir, now: now} do
      bundle_dir = Path.join(tmp_dir, "pki_dead_letter_robustness_test")
      File.mkdir_p!(bundle_dir)
      dl_path = Path.join(bundle_dir, "dead_letter_observations.json")

      # 1. Test error propagation when dead_letter_observations.json is corrupted
      File.write!(dl_path, "{invalid_json")

      entry = %{
        "sequence" => 1,
        "receipt" => %{
          "agent_id" => "agent-1",
          "observation_sequence" => 1,
          "status" => "failed",
          "applied_at" => DateTime.to_iso8601(now)
        },
        "enqueued_at" => DateTime.to_iso8601(now)
      }

      # Enqueue valid outbox entry
      assert {:ok, 1, _} = AtomicStore.enqueue_observation(bundle_dir, entry["receipt"])

      # record_rejected_observation must fail and preserve corrupted file, not overwrite it
      assert {:error, {:dead_letter_persistence_failed, _reason}} =
               AtomicStore.record_rejected_observation(bundle_dir, entry, :some_error, "reason")

      assert File.read!(dl_path) == "{invalid_json"

      # Outbox entry must be preserved!
      assert {:ok, %{outbox: [preserved]}} = AtomicStore.read_outbox(bundle_dir)
      assert preserved["sequence"] == 1

      # 2. Test unreadable file permissions (e.g. eacces) preserves archive and outbox
      File.write!(dl_path, "{\"rejected_observations\": []}")
      File.chmod!(dl_path, 0o000)

      assert {:error,
              {:dead_letter_persistence_failed,
               {:corrupted_dead_letter_archive, {:read_failed, :eacces}}}} =
               AtomicStore.record_rejected_observation(bundle_dir, entry, :some_error, "reason")

      # Restore permission and verify original content preserved
      File.chmod!(dl_path, 0o600)
      assert File.read!(dl_path) == "{\"rejected_observations\": []}"
      assert {:ok, %{outbox: [preserved2]}} = AtomicStore.read_outbox(bundle_dir)
      assert preserved2["sequence"] == 1

      # 3. Test idempotence when valid dead-letter file already has the entry
      File.rm!(dl_path)

      assert :ok = AtomicStore.record_rejected_observation(bundle_dir, entry, :conflict, "dup")
      assert {:ok, [dl1]} = AtomicStore.read_dead_letter_observations(bundle_dir)
      assert dl1["sequence"] == 1

      # Append same rejected entry again
      assert :ok = AtomicStore.record_rejected_observation(bundle_dir, entry, :conflict, "dup")
      assert {:ok, dl_list} = AtomicStore.read_dead_letter_observations(bundle_dir)
      # Must not duplicate
      assert length(dl_list) == 1

      # 4. Injected archive write failure preserves active outbox entry
      entry2 = %{
        "sequence" => 2,
        "receipt" => %{
          "agent_id" => "agent-1",
          "observation_sequence" => 2,
          "status" => "failed",
          "applied_at" => DateTime.to_iso8601(now)
        },
        "enqueued_at" => DateTime.to_iso8601(now)
      }

      assert {:ok, 2, _} = AtomicStore.enqueue_observation(bundle_dir, entry2["receipt"])

      assert {:error, {:dead_letter_persistence_failed, :eio}} =
               AtomicStore.record_rejected_observation(
                 bundle_dir,
                 entry2,
                 :some_error,
                 "reason",
                 inject_dead_letter_write_error: :eio
               )

      assert {:ok, %{outbox: entries_after_write_fail}} = AtomicStore.read_outbox(bundle_dir)
      assert Enum.any?(entries_after_write_fail, &(&1["sequence"] == 2))

      # 5. Same observation identity with different payload detected as conflict
      entry1_conflict = %{
        "sequence" => 1,
        "receipt" => %{
          "agent_id" => "agent-1",
          "observation_sequence" => 1,
          "status" => "applied",
          "applied_at" => DateTime.to_iso8601(now),
          "generation" => 99
        },
        "enqueued_at" => DateTime.to_iso8601(now)
      }

      assert {:error,
              {:dead_letter_persistence_failed, {:conflicting_observation_payload, 1, "agent-1"}}} =
               AtomicStore.record_rejected_observation(
                 bundle_dir,
                 entry1_conflict,
                 :conflict,
                 "different payload"
               )

      # Archive retains original record, not overwritten
      assert {:ok, dl_list_after_conflict} = AtomicStore.read_dead_letter_observations(bundle_dir)
      original_rec = Enum.find(dl_list_after_conflict, &(&1["sequence"] == 1))
      assert original_rec["receipt"]["status"] == "failed"
    end

    test "interrupted dead-letter transfer replay completes outbox removal without duplicating rejection record (Finding 2)",
         %{tmp_dir: tmp_dir, now: now} do
      bundle_dir = Path.join(tmp_dir, "pki_dead_letter_interrupt_test")
      File.mkdir_p!(bundle_dir)

      entry = %{
        "sequence" => 1,
        "receipt" => %{
          "agent_id" => "agent-interrupt-test",
          "observation_sequence" => 1,
          "status" => "failed",
          "applied_at" => DateTime.to_iso8601(now)
        },
        "enqueued_at" => DateTime.to_iso8601(now)
      }

      # 1. Enqueue valid entry in outbox
      assert {:ok, 1, _} = AtomicStore.enqueue_observation(bundle_dir, entry["receipt"])

      # 2. Simulate failure during outbox removal (after dead-letter commit)
      # using inject_sequence_rename_error
      assert {:error, {:sequence_persistence_failed, :eio}} =
               AtomicStore.record_rejected_observation(
                 bundle_dir,
                 entry,
                 :conflicting_observation_sequence,
                 "conflict",
                 inject_sequence_rename_error: :eio
               )

      # Active outbox still retains entry because ACK/removal failed before rename
      assert {:ok, %{outbox: [retained]}} = AtomicStore.read_outbox(bundle_dir)
      assert retained["sequence"] == 1

      # Dead letter archive already contains sequence 1
      assert {:ok, [dl_entry]} = AtomicStore.read_dead_letter_observations(bundle_dir)
      assert dl_entry["sequence"] == 1

      # 3. Crash replay / retry: record_rejected_observation is called again without error
      assert :ok =
               AtomicStore.record_rejected_observation(
                 bundle_dir,
                 entry,
                 :conflicting_observation_sequence,
                 "conflict"
               )

      # Active outbox is now cleanly drained and empty
      assert {:ok, %{outbox: []}} = AtomicStore.read_outbox(bundle_dir)

      # Dead letter observations must NOT have duplicated the entry
      assert {:ok, dl_list} = AtomicStore.read_dead_letter_observations(bundle_dir)
      assert length(dl_list) == 1
    end

    test "application options and runtime bootstrap handoff binds identity and avoids quarantine during bundle and CRL updates",
         %{tmp_dir: tmp_dir, bundle: bundle, now: now, ca_cert: ca_cert, ca_key: ca_key} do
      bundle_dir = Path.join(tmp_dir, "pki_real_app_startup_test")
      state_dir = Path.join(tmp_dir, "agent_state_dir")
      File.mkdir_p!(bundle_dir)
      File.mkdir_p!(state_dir)

      test_pid = self()

      # Mock connection that records receipts
      mock_conn =
        spawn(fn ->
          loop_fn = fn loop, count ->
            receive do
              {:"$gen_call", from, {:submit_bundle_receipt, receipt}} ->
                send(test_pid, {:submitted_receipt, receipt, count})
                GenServer.reply(from, {:ok, %{"status" => "recorded"}})
                loop.(loop, count + 1)

              _other ->
                loop.(loop, count)
            end
          end

          loop_fn.(loop_fn, 1)
        end)

      Process.register(mock_conn, :test_mock_real_app_conn)

      # 1. Start PKI manager through the real Application configuration:
      # bundle_dir and state_dir only, agent_id is nil (not enrolled yet)
      {:ok, manager} =
        TrustBundleManager.start_link(
          state_dir: state_dir,
          bundle_dir: bundle_dir,
          connection_mod: :test_mock_real_app_conn,
          name: :test_real_app_manager
        )

      # Attempting to process bundle before enrollment completes returns waiting_for_identity
      assert {:error, :waiting_for_identity, nil} =
               TrustBundleManager.process_bundle(manager, bundle)

      # Outbox must remain completely clean (no invalid receipts enqueued)
      assert {:ok, %{highest_sequence: 0, outbox: []}} = AtomicStore.read_outbox(bundle_dir)
      status_before = TrustBundleManager.status(manager)
      assert status_before.recovery_mode == :none

      # 2. Simulate RuntimeBootstrapper completing enrollment
      enrolled_agent_id = "agent-enrolled-real-777"

      material = %{
        agent_id: enrolled_agent_id,
        private_key_pem: "---FAKE KEY---",
        certificate_pem: "---FAKE CERT---",
        ca_chain_pem: "---FAKE CA CHAIN---",
        connect_info: %{"endpoint" => "wss://localhost:4664/socket/agent/runtime"},
        identity: %{"agent_id" => enrolled_agent_id}
      }

      assert :ok = SecretHub.Agent.IdentityStore.write(state_dir, material)

      # RuntimeBootstrapper calls bind_identity
      assert :ok = TrustBundleManager.bind_identity(manager, enrolled_agent_id)

      # Attempting to re-bind with conflicting identity is rejected and does not overwrite
      assert {:error, {:identity_mismatch, ^enrolled_agent_id, "different-agent"}} =
               TrustBundleManager.bind_identity(manager, "different-agent")

      # 3. Process bundle 1 (generation 1)
      assert {:ok, receipt1} = TrustBundleManager.process_bundle(manager, bundle, now: now)
      assert receipt1["agent_id"] == enrolled_agent_id
      assert receipt1["status"] == "applied"
      assert receipt1["observation_sequence"] == 1

      # Receipt is drained and submitted over connection
      assert_receive {:submitted_receipt, sub_receipt1, 1}, 2000
      assert sub_receipt1["agent_id"] == enrolled_agent_id
      assert sub_receipt1["observation_sequence"] == 1

      # Wait for ACK to complete outbox drain
      Process.sleep(50)
      assert {:ok, %{outbox: []}} = AtomicStore.read_outbox(bundle_dir)

      # 4. Now process a newer CRL update bundle (generation 1, higher CRL number)
      crl2 =
        X509.CRL.new(
          [],
          ca_cert,
          ca_key,
          this_update: DateTime.add(now, 60, :second),
          next_update: DateTime.add(now, 48 * 3600, :second),
          extensions: [crl_number: X509.CRL.Extension.crl_number(2)]
        )

      crl2_pem = X509.CRL.to_pem(crl2)
      crl2_der = X509.CRL.to_der(crl2)
      crl2_hash = :crypto.hash(:sha256, crl2_der) |> Base.encode16(case: :lower)

      crl_bundle =
        bundle
        |> Map.put("generation", 2)
        |> Map.put("crl_number", 2)
        |> Map.put("this_update", DateTime.to_iso8601(DateTime.add(now, 60, :second)))
        |> Map.put("crl_pem", crl2_pem)
        |> Map.put("crl_der_sha256", crl2_hash)

      crl_transcript =
        [
          crl_bundle["schema_version"],
          crl_bundle["authority"],
          crl_bundle["generation"],
          crl_bundle["ca_fingerprint"],
          crl_bundle["crl_number"],
          crl_bundle["crl_der_sha256"],
          crl_bundle["this_update"],
          crl_bundle["next_update"],
          crl_bundle["ca_bundle_pem"],
          crl_bundle["crl_pem"]
        ]
        |> Enum.map(&to_string/1)
        |> Enum.join("|")

      crl_hash = :crypto.hash(:sha256, crl_transcript) |> Base.encode16(case: :lower)
      crl_bundle = Map.put(crl_bundle, "bundle_sha256", crl_hash)

      assert {:ok, receipt2} =
               TrustBundleManager.process_bundle(manager, crl_bundle,
                 now: DateTime.add(now, 60, :second)
               )

      assert receipt2["agent_id"] == enrolled_agent_id
      assert receipt2["status"] == "applied"
      assert receipt2["observation_sequence"] == 2

      # Second receipt is submitted
      assert_receive {:submitted_receipt, sub_receipt2, 2}, 2000
      assert sub_receipt2["agent_id"] == enrolled_agent_id
      assert sub_receipt2["observation_sequence"] == 2

      # Verify the manager NEVER entered quarantine
      final_status = TrustBundleManager.status(manager)
      assert final_status.recovery_mode == :none
      assert final_status.status == "applied"
      assert final_status.last_error_code == nil
      assert final_status.current_generation == 2
      assert final_status.current_crl_number == 2

      GenServer.stop(manager)

      # 5. Verify that on subsequent application startup, Application.start_agent
      # pre-loads agent_id from IdentityStore in state_dir automatically
      {:ok, restarted_manager} =
        TrustBundleManager.start_link(
          state_dir: state_dir,
          bundle_dir: bundle_dir,
          connection_mod: :test_mock_real_app_conn,
          name: :test_restarted_manager
        )

      restarted_status = TrustBundleManager.status(restarted_manager)
      assert restarted_status.recovery_mode == :none
      assert restarted_status.status == "applied"
      assert restarted_status.current_generation == 2
      assert restarted_status.current_crl_number == 2

      # Verified identity is already loaded from disk without calling bind_identity
      assert {:ok, receipt3} =
               TrustBundleManager.process_bundle(restarted_manager, crl_bundle,
                 now: DateTime.add(now, 120, :second)
               )

      assert receipt3["agent_id"] == enrolled_agent_id

      GenServer.stop(restarted_manager)
    end

    test "application startup with pre-existing identity loads agent_id immediately",
         %{tmp_dir: tmp_dir, bundle: bundle, now: now} do
      bundle_dir = Path.join(tmp_dir, "pki_existing_identity_test")
      state_dir = Path.join(tmp_dir, "existing_agent_state_dir")
      File.mkdir_p!(bundle_dir)
      File.mkdir_p!(state_dir)

      existing_agent_id = "agent-preexisting-888"

      material = %{
        agent_id: existing_agent_id,
        private_key_pem: "---FAKE KEY---",
        certificate_pem: "---FAKE CERT---",
        ca_chain_pem: "---FAKE CA CHAIN---",
        connect_info: %{"endpoint" => "wss://localhost:4664/socket/agent/runtime"},
        identity: %{"agent_id" => existing_agent_id}
      }

      assert :ok = SecretHub.Agent.IdentityStore.write(state_dir, material)

      # Start PKI manager without agent_id; should discover it in state_dir immediately
      {:ok, manager} =
        TrustBundleManager.start_link(
          state_dir: state_dir,
          bundle_dir: bundle_dir,
          name: :test_preexisting_id_manager
        )

      assert {:ok, receipt} = TrustBundleManager.process_bundle(manager, bundle, now: now)
      assert receipt["agent_id"] == existing_agent_id
      assert receipt["status"] == "applied"

      GenServer.stop(manager)
    end

    test "corrupt watermark with no surviving bundle retains trust quarantine after outbox repair",
         %{tmp_dir: tmp_dir, bundle: bundle, now: now} do
      bundle_dir = Path.join(tmp_dir, "pki_corrupt_wm_and_outbox_test")
      File.mkdir_p!(bundle_dir)
      wm_path = Path.join(bundle_dir, "watermark.json")
      outbox_path = Path.join(bundle_dir, "observation_sequence.json")

      # 1. Corrupt watermark file on disk
      File.write!(wm_path, "{\"highest_seen_generation\": -1}")

      # 2. Repairable nil-ID outbox on disk
      raw_outbox = %{
        "observation_sequence" => 1,
        "outbox" => [
          %{
            "sequence" => 1,
            "receipt" => %{
              "agent_id" => nil,
              "observation_sequence" => 1,
              "status" => "applied",
              "applied_at" => DateTime.to_iso8601(now)
            },
            "enqueued_at" => DateTime.to_iso8601(now)
          }
        ],
        "updated_at" => DateTime.to_iso8601(now)
      }

      File.write!(outbox_path, Jason.encode!(raw_outbox))

      # 3. Start manager without initial agent_id
      {:ok, manager} =
        TrustBundleManager.start_link(
          state_dir: tmp_dir,
          bundle_dir: bundle_dir,
          name: :test_corrupt_wm_outbox_manager
        )

      status_init = TrustBundleManager.status(manager)
      assert status_init.recovery_mode == :quarantined

      # 4. Bind verified identity -> outbox repair succeeds
      assert :ok = TrustBundleManager.bind_identity(manager, "agent-verified-111")

      # 5. Confirm trust quarantine REMAINS!
      status_after_bind = TrustBundleManager.status(manager)
      assert status_after_bind.recovery_mode == :quarantined
      assert status_after_bind.status == "recovery_required"

      assert status_after_bind.last_error_code in [
               :damaged_state_recovery_required,
               "damaged_state_recovery_required"
             ]

      # 6. Submit valid candidate multiple times without explicit trust recovery
      # Every attempt must remain rejected!
      assert {:error, :damaged_state_recovery_required, receipt_err1} =
               TrustBundleManager.process_bundle(manager, bundle, now: now)

      assert receipt_err1["status"] == "failed"

      assert {:error, :damaged_state_recovery_required, receipt_err2} =
               TrustBundleManager.process_bundle(manager, bundle, now: now)

      assert receipt_err2["status"] == "failed"

      # 7. Assert watermark and current symlink are completely unchanged
      assert File.read!(wm_path) == "{\"highest_seen_generation\": -1}"
      refute File.exists?(Path.join(bundle_dir, "current"))

      GenServer.stop(manager)
    end

    test "repair_outbox_metadata fails and preserves active outbox when backup path is occupied by a directory",
         %{tmp_dir: tmp_dir, now: now} do
      bundle_dir = Path.join(tmp_dir, "pki_backup_failure_test")
      File.mkdir_p!(bundle_dir)
      outbox_path = Path.join(bundle_dir, "observation_sequence.json")

      raw_data = %{
        "observation_sequence" => 1,
        "outbox" => [
          %{
            "sequence" => 1,
            "receipt" => %{
              "agent_id" => nil,
              "observation_sequence" => 1,
              "status" => "applied",
              "applied_at" => ""
            },
            "enqueued_at" => DateTime.to_iso8601(now)
          }
        ],
        "updated_at" => DateTime.to_iso8601(now)
      }

      raw_json = Jason.encode!(raw_data)
      File.write!(outbox_path, raw_json)

      # Create directory at backup path
      # Under content-addressed or pre_repair_bak naming:
      # If we specify backup_path as a directory:
      backup_dir_path = Path.join(bundle_dir, "backup_as_directory")
      File.mkdir_p!(backup_dir_path)

      # Calling repair with backup_path occupied by a directory must return error
      assert {:error, {:backup_failed, _}} =
               AtomicStore.repair_outbox_metadata(bundle_dir, %{agent_id: "agent-new"},
                 backup_path: backup_dir_path
               )

      # Active outbox raw bytes and counters must be completely unchanged
      assert File.read!(outbox_path) == raw_json
    end

    test "record_rejected_observation returns structured error on malformed dead-letter entries instead of raising",
         %{tmp_dir: tmp_dir, now: now} do
      bundle_dir = Path.join(tmp_dir, "pki_malformed_dl_test")
      File.mkdir_p!(bundle_dir)
      dl_path = Path.join(bundle_dir, "dead_letter_observations.json")

      # Put malformed archive containing scalar member [123]
      File.write!(dl_path, "{\"rejected_observations\": [123]}")

      entry = %{
        "sequence" => 1,
        "receipt" => %{
          "agent_id" => "agent-test",
          "observation_sequence" => 1,
          "status" => "failed",
          "applied_at" => DateTime.to_iso8601(now)
        }
      }

      # Calling record_rejected_observation must not raise ArgumentError!
      # It must return structured error
      assert {:error,
              {:dead_letter_persistence_failed,
               {:corrupted_dead_letter_archive, {:invalid_entry_shape, 123}}}} =
               AtomicStore.record_rejected_observation(bundle_dir, entry, :some_error, "reason")
    end

    test "conflicting retained trust evidence maintains trust quarantine after outbox repair",
         %{tmp_dir: tmp_dir, bundle: bundle, now: now} do
      bundle_dir = Path.join(tmp_dir, "pki_conflicting_evidence_test")
      File.mkdir_p!(bundle_dir)
      generations_dir = Path.join(bundle_dir, "generations")
      gen1_dir = Path.join(generations_dir, "gen-1")
      File.mkdir_p!(gen1_dir)

      # Put damaged/corrupted candidate evidence in generations/gen-1
      File.write!(Path.join(gen1_dir, "manifest.json"), "{corrupted_manifest")

      outbox_path = Path.join(bundle_dir, "observation_sequence.json")

      raw_outbox = %{
        "observation_sequence" => 1,
        "outbox" => [
          %{
            "sequence" => 1,
            "receipt" => %{
              "agent_id" => nil,
              "observation_sequence" => 1,
              "status" => "applied",
              "applied_at" => DateTime.to_iso8601(now)
            },
            "enqueued_at" => DateTime.to_iso8601(now)
          }
        ],
        "updated_at" => DateTime.to_iso8601(now)
      }

      File.write!(outbox_path, Jason.encode!(raw_outbox))

      # Start manager
      {:ok, manager} =
        TrustBundleManager.start_link(
          state_dir: tmp_dir,
          bundle_dir: bundle_dir,
          name: :test_conflicting_evidence_manager
        )

      status_init = TrustBundleManager.status(manager)
      assert status_init.recovery_mode == :quarantined
      assert status_init.trust_recovery_restriction == :damaged_state_recovery_required

      # Bind verified identity
      assert :ok = TrustBundleManager.bind_identity(manager, "agent-verified-222")

      # Trust quarantine must remain enforced!
      status_after = TrustBundleManager.status(manager)
      assert status_after.recovery_mode == :quarantined
      assert status_after.trust_recovery_restriction == :damaged_state_recovery_required
      assert status_after.outbox_restriction == nil

      # Candidate bundle submissions remain rejected
      assert {:error, :damaged_state_recovery_required, _} =
               TrustBundleManager.process_bundle(manager, bundle, now: now)

      GenServer.stop(manager)
    end

    test "repair_outbox_metadata fails and preserves active outbox on injected backup write and sync errors",
         %{tmp_dir: tmp_dir, now: now} do
      bundle_dir = Path.join(tmp_dir, "pki_backup_injected_error_test")
      File.mkdir_p!(bundle_dir)
      outbox_path = Path.join(bundle_dir, "observation_sequence.json")

      raw_data = %{
        "observation_sequence" => 1,
        "outbox" => [
          %{
            "sequence" => 1,
            "receipt" => %{
              "agent_id" => nil,
              "observation_sequence" => 1,
              "status" => "applied",
              "applied_at" => ""
            },
            "enqueued_at" => DateTime.to_iso8601(now)
          }
        ],
        "updated_at" => DateTime.to_iso8601(now)
      }

      raw_json = Jason.encode!(raw_data)
      File.write!(outbox_path, raw_json)

      # 1. Injected write error
      assert {:error, {:backup_failed, :injected_backup_write_error}} =
               AtomicStore.repair_outbox_metadata(
                 bundle_dir,
                 %{agent_id: "agent-1"},
                 inject_backup_write_error: :injected_backup_write_error
               )

      assert File.read!(outbox_path) == raw_json

      assert {:error, {:corrupted_outbox, {:missing_receipt_field, "agent_id", 1}}} =
               AtomicStore.read_observation_sequence(bundle_dir)

      # 2. Injected sync error
      assert {:error, {:backup_failed, :injected_backup_sync_error}} =
               AtomicStore.repair_outbox_metadata(
                 bundle_dir,
                 %{agent_id: "agent-1"},
                 inject_backup_sync_error: :injected_backup_sync_error
               )

      assert File.read!(outbox_path) == raw_json

      assert {:error, {:corrupted_outbox, {:missing_receipt_field, "agent_id", 1}}} =
               AtomicStore.read_observation_sequence(bundle_dir)
    end

    test "repair_outbox_metadata refuses to overwrite existing backup and leaves active outbox unchanged",
         %{tmp_dir: tmp_dir, now: now} do
      bundle_dir = Path.join(tmp_dir, "pki_backup_overwrite_test")
      File.mkdir_p!(bundle_dir)
      outbox_path = Path.join(bundle_dir, "observation_sequence.json")

      raw_data = %{
        "observation_sequence" => 1,
        "outbox" => [
          %{
            "sequence" => 1,
            "receipt" => %{
              "agent_id" => nil,
              "observation_sequence" => 1,
              "status" => "applied",
              "applied_at" => ""
            },
            "enqueued_at" => DateTime.to_iso8601(now)
          }
        ],
        "updated_at" => DateTime.to_iso8601(now)
      }

      raw_json = Jason.encode!(raw_data)
      File.write!(outbox_path, raw_json)

      content_sha256 = :crypto.hash(:sha256, raw_json) |> Base.encode16(case: :lower)
      bak_path = Path.join(bundle_dir, "observation_sequence.json.bak-" <> content_sha256)

      # Create pre-existing backup file with initial evidence
      File.write!(bak_path, "PRIOR_IMMUTABLE_EVIDENCE")

      # Attempting repair on content with existing backup must fail
      assert {:error, {:backup_failed, {:backup_already_exists, ^bak_path}}} =
               AtomicStore.repair_outbox_metadata(bundle_dir, %{agent_id: "agent-new"})

      # Existing backup was NOT modified
      assert File.read!(bak_path) == "PRIOR_IMMUTABLE_EVIDENCE"
      # Active outbox bytes and sequence counters are completely unchanged
      assert File.read!(outbox_path) == raw_json
    end

    test "repair_outbox_metadata rejects backup symlink without following and preserves active outbox",
         %{tmp_dir: tmp_dir, now: now} do
      bundle_dir = Path.join(tmp_dir, "pki_backup_symlink_test")
      File.mkdir_p!(bundle_dir)
      outbox_path = Path.join(bundle_dir, "observation_sequence.json")
      victim_path = Path.join(bundle_dir, "important_data.txt")
      File.write!(victim_path, "DO_NOT_OVERWRITE")

      raw_data = %{
        "observation_sequence" => 1,
        "outbox" => [
          %{
            "sequence" => 1,
            "receipt" => %{
              "agent_id" => nil,
              "observation_sequence" => 1,
              "status" => "applied",
              "applied_at" => ""
            },
            "enqueued_at" => DateTime.to_iso8601(now)
          }
        ],
        "updated_at" => DateTime.to_iso8601(now)
      }

      raw_json = Jason.encode!(raw_data)
      File.write!(outbox_path, raw_json)

      content_sha256 = :crypto.hash(:sha256, raw_json) |> Base.encode16(case: :lower)
      symlink_path = Path.join(bundle_dir, "observation_sequence.json.bak-" <> content_sha256)
      File.ln_s!(victim_path, symlink_path)

      # Attempting repair must reject the symlink
      assert {:error, {:backup_failed, {:symlink_detected, ^symlink_path}}} =
               AtomicStore.repair_outbox_metadata(bundle_dir, %{agent_id: "agent-new"})

      # Victim file was NOT overwritten
      assert File.read!(victim_path) == "DO_NOT_OVERWRITE"
      # Active outbox is unchanged
      assert File.read!(outbox_path) == raw_json
    end

    test "bind_identity returns meaningful repair error when backup fails, keeping agent_id and quarantine",
         %{tmp_dir: tmp_dir, now: now} do
      bundle_dir = Path.join(tmp_dir, "pki_bind_id_backup_failure_test")
      File.mkdir_p!(bundle_dir)
      outbox_path = Path.join(bundle_dir, "observation_sequence.json")

      raw_data = %{
        "observation_sequence" => 1,
        "outbox" => [
          %{
            "sequence" => 1,
            "receipt" => %{
              "agent_id" => nil,
              "observation_sequence" => 1,
              "status" => "applied",
              "applied_at" => ""
            },
            "enqueued_at" => DateTime.to_iso8601(now)
          }
        ],
        "updated_at" => DateTime.to_iso8601(now)
      }

      raw_json = Jason.encode!(raw_data)
      File.write!(outbox_path, raw_json)

      # Start manager with injected backup write error
      {:ok, manager} =
        TrustBundleManager.start_link(
          state_dir: tmp_dir,
          bundle_dir: bundle_dir,
          name: :test_bind_id_backup_fail_mgr,
          store_opts: [inject_backup_write_error: :disk_full]
        )

      assert {:error, {:repair_failed, {:backup_failed, :disk_full}}} =
               TrustBundleManager.bind_identity(manager, "agent-new-id")

      # Identity was bound, but quarantine remains due to un-repaired outbox
      status = TrustBundleManager.status(manager)
      assert status.agent_id == "agent-new-id"
      assert status.recovery_mode == :quarantined
      assert status.outbox_restriction == :corrupted_outbox

      # Active outbox on disk was NOT modified
      assert File.read!(outbox_path) == raw_json

      GenServer.stop(manager)
    end

    test "interrupted repair or restart does not destroy earliest evidence",
         %{tmp_dir: tmp_dir, now: now} do
      bundle_dir = Path.join(tmp_dir, "pki_earliest_evidence_test")
      File.mkdir_p!(bundle_dir)
      outbox_path = Path.join(bundle_dir, "observation_sequence.json")

      raw_data = %{
        "observation_sequence" => 1,
        "outbox" => [
          %{
            "sequence" => 1,
            "receipt" => %{
              "agent_id" => nil,
              "observation_sequence" => 1,
              "status" => "applied",
              "applied_at" => ""
            },
            "enqueued_at" => DateTime.to_iso8601(now)
          }
        ],
        "updated_at" => DateTime.to_iso8601(now)
      }

      raw_json = Jason.encode!(raw_data)
      File.write!(outbox_path, raw_json)

      content_sha256 = :crypto.hash(:sha256, raw_json) |> Base.encode16(case: :lower)
      bak_path = Path.join(bundle_dir, "observation_sequence.json.bak-" <> content_sha256)

      # First repair creates backup and repairs file
      assert :ok = AtomicStore.repair_outbox_metadata(bundle_dir, %{agent_id: "agent-1"})
      assert File.exists?(bak_path)
      assert File.read!(bak_path) == raw_json

      # Another repair attempt on the already-repaired file (no repair needed)
      assert :ok = AtomicStore.repair_outbox_metadata(bundle_dir, %{agent_id: "agent-1"})

      # Earliest evidence in backup remains intact
      assert File.read!(bak_path) == raw_json
    end

    test "read_dead_letter_observations rejects scalar members: number, string, boolean, null",
         %{tmp_dir: tmp_dir} do
      bundle_dir = Path.join(tmp_dir, "pki_dl_scalars_test")
      File.mkdir_p!(bundle_dir)
      dl_path = Path.join(bundle_dir, "dead_letter_observations.json")

      for scalar <- [42, "string", true, false, nil] do
        payload = Jason.encode!(%{"rejected_observations" => [scalar]})
        File.write!(dl_path, payload)

        assert {:error, {:corrupted_dead_letter_archive, {:invalid_entry_shape, ^scalar}}} =
                 AtomicStore.read_dead_letter_observations(bundle_dir)
      end
    end

    test "read_dead_letter_observations rejects entry with receipt as a scalar or list",
         %{tmp_dir: tmp_dir} do
      bundle_dir = Path.join(tmp_dir, "pki_dl_invalid_receipt_test")
      File.mkdir_p!(bundle_dir)
      dl_path = Path.join(bundle_dir, "dead_letter_observations.json")

      for invalid_rec <- [123, "not_a_map", ["list"], true, nil] do
        entry = %{"sequence" => 1, "receipt" => invalid_rec}
        File.write!(dl_path, Jason.encode!(%{"rejected_observations" => [entry]}))

        assert {:error, {:corrupted_dead_letter_archive, {:invalid_receipt_shape, ^invalid_rec}}} =
                 AtomicStore.read_dead_letter_observations(bundle_dir)
      end
    end

    test "read_dead_letter_observations rejects invalid or inconsistent sequence metadata",
         %{tmp_dir: tmp_dir, now: now} do
      bundle_dir = Path.join(tmp_dir, "pki_dl_inconsistent_seq_test")
      File.mkdir_p!(bundle_dir)
      dl_path = Path.join(bundle_dir, "dead_letter_observations.json")

      # Negative sequence
      entry1 = %{
        "sequence" => -1,
        "receipt" => %{
          "agent_id" => "agent-1",
          "observation_sequence" => -1,
          "status" => "failed",
          "applied_at" => DateTime.to_iso8601(now)
        }
      }

      File.write!(dl_path, Jason.encode!(%{"rejected_observations" => [entry1]}))

      assert {:error, {:corrupted_dead_letter_archive, {:invalid_sequence, -1}}} =
               AtomicStore.read_dead_letter_observations(bundle_dir)

      # Non-integer sequence
      entry2 = %{
        "sequence" => "one",
        "receipt" => %{
          "agent_id" => "agent-1",
          "observation_sequence" => 1,
          "status" => "failed",
          "applied_at" => DateTime.to_iso8601(now)
        }
      }

      File.write!(dl_path, Jason.encode!(%{"rejected_observations" => [entry2]}))

      assert {:error, {:corrupted_dead_letter_archive, {:invalid_sequence, "one"}}} =
               AtomicStore.read_dead_letter_observations(bundle_dir)

      # Inconsistent observation_sequence vs sequence
      entry3 = %{
        "sequence" => 1,
        "receipt" => %{
          "agent_id" => "agent-1",
          "observation_sequence" => 2,
          "status" => "failed",
          "applied_at" => DateTime.to_iso8601(now)
        }
      }

      File.write!(dl_path, Jason.encode!(%{"rejected_observations" => [entry3]}))

      assert {:error, {:corrupted_dead_letter_archive, {:inconsistent_sequence, 1, 2}}} =
               AtomicStore.read_dead_letter_observations(bundle_dir)
    end

    test "read_dead_letter_observations rejects invalid or mismatching stored digest",
         %{tmp_dir: tmp_dir, now: now} do
      bundle_dir = Path.join(tmp_dir, "pki_dl_digest_check_test")
      File.mkdir_p!(bundle_dir)
      dl_path = Path.join(bundle_dir, "dead_letter_observations.json")

      receipt = %{
        "agent_id" => "agent-1",
        "observation_sequence" => 1,
        "status" => "failed",
        "applied_at" => DateTime.to_iso8601(now)
      }

      # 1. Invalid digest format (not 64 hex chars)
      entry1 = %{"sequence" => 1, "receipt" => receipt, "receipt_digest" => "bad_format"}
      File.write!(dl_path, Jason.encode!(%{"rejected_observations" => [entry1]}))

      assert {:error,
              {:corrupted_dead_letter_archive, {:invalid_stored_digest_format, "bad_format"}}} =
               AtomicStore.read_dead_letter_observations(bundle_dir)

      # 2. Mismatched digest (valid 64 hex chars but doesn't match payload)
      fake_digest = String.duplicate("0", 64)
      entry2 = %{"sequence" => 1, "receipt" => receipt, "receipt_digest" => fake_digest}
      File.write!(dl_path, Jason.encode!(%{"rejected_observations" => [entry2]}))

      assert {:error, {:corrupted_dead_letter_archive, {:digest_mismatch, _}}} =
               AtomicStore.read_dead_letter_observations(bundle_dir)
    end

    test "read_dead_letter_observations accepts valid legacy record without digest and supports idempotent replay",
         %{tmp_dir: tmp_dir, now: now} do
      bundle_dir = Path.join(tmp_dir, "pki_dl_legacy_test")
      File.mkdir_p!(bundle_dir)
      dl_path = Path.join(bundle_dir, "dead_letter_observations.json")

      legacy_entry = %{
        "sequence" => 1,
        "receipt" => %{
          "agent_id" => "agent-legacy",
          "observation_sequence" => 1,
          "status" => "applied",
          "applied_at" => DateTime.to_iso8601(now)
        },
        "rejected_at" => DateTime.to_iso8601(now)
      }

      File.write!(dl_path, Jason.encode!(%{"rejected_observations" => [legacy_entry]}))

      assert {:ok, [loaded]} = AtomicStore.read_dead_letter_observations(bundle_dir)
      assert loaded["sequence"] == 1
      assert loaded["receipt"]["agent_id"] == "agent-legacy"
      assert is_binary(loaded["receipt_digest"])

      # Replaying identical rejection through record_rejected_observation recognizes it as :replay
      assert :ok =
               AtomicStore.record_rejected_observation(
                 bundle_dir,
                 legacy_entry,
                 :conflict,
                 "replayed"
               )

      # Archive retains exactly 1 record
      assert {:ok, dl_list} = AtomicStore.read_dead_letter_observations(bundle_dir)
      assert length(dl_list) == 1
    end

    test "record_rejected_observation detects differing payload under same identity as conflict",
         %{tmp_dir: tmp_dir, now: now} do
      bundle_dir = Path.join(tmp_dir, "pki_dl_conflict_test")
      File.mkdir_p!(bundle_dir)

      entry1 = %{
        "sequence" => 1,
        "receipt" => %{
          "agent_id" => "agent-conflict",
          "observation_sequence" => 1,
          "status" => "applied",
          "applied_at" => DateTime.to_iso8601(now)
        }
      }

      assert :ok =
               AtomicStore.record_rejected_observation(bundle_dir, entry1, :some_code, "first")

      # Different receipt payload under same sequence and identity
      entry2 = %{
        "sequence" => 1,
        "receipt" => %{
          "agent_id" => "agent-conflict",
          "observation_sequence" => 1,
          "status" => "failed",
          "applied_at" => DateTime.to_iso8601(now)
        }
      }

      assert {:error,
              {:dead_letter_persistence_failed,
               {:conflicting_observation_payload, 1, "agent-conflict"}}} =
               AtomicStore.record_rejected_observation(bundle_dir, entry2, :some_code, "second")
    end

    test "TrustBundleManager outbox draining stays alive and preserves outbox on corrupted dead-letter archive",
         %{tmp_dir: tmp_dir, now: now} do
      bundle_dir = Path.join(tmp_dir, "pki_mgr_corrupt_dl_drain_test")
      File.mkdir_p!(bundle_dir)
      dl_path = Path.join(bundle_dir, "dead_letter_observations.json")
      outbox_path = Path.join(bundle_dir, "observation_sequence.json")

      # Write corrupted dead-letter archive
      File.write!(dl_path, "{\"rejected_observations\": [123]}")

      # Write active outbox entry
      raw_outbox = %{
        "observation_sequence" => 1,
        "outbox" => [
          %{
            "sequence" => 1,
            "receipt" => %{
              "agent_id" => "agent-drain-test",
              "observation_sequence" => 1,
              "status" => "applied",
              "applied_at" => DateTime.to_iso8601(now)
            },
            "enqueued_at" => DateTime.to_iso8601(now)
          }
        ],
        "updated_at" => DateTime.to_iso8601(now)
      }

      File.write!(outbox_path, Jason.encode!(raw_outbox))

      # Mock connection that rejects receipt submission
      test_pid = self()

      mock_conn =
        spawn(fn ->
          receive do
            {:"$gen_call", from, {:submit_bundle_receipt, receipt}} ->
              send(test_pid, {:submitted_receipt, receipt})

              GenServer.reply(
                from,
                {:error, {:rejected, :invalid_receipt, "permanently rejected"}}
              )
          end
        end)

      Process.register(mock_conn, :test_mock_dl_drain_conn)

      {:ok, manager} =
        TrustBundleManager.start_link(
          state_dir: tmp_dir,
          bundle_dir: bundle_dir,
          connection_mod: :test_mock_dl_drain_conn,
          agent_id: "agent-drain-test",
          name: :test_mgr_corrupt_dl_drain,
          outbox_drain_backoff_ms: 10_000
        )

      # Receipt was submitted
      assert_receive {:submitted_receipt, _receipt}, 2000

      # Give manager a moment to process rejection
      Process.sleep(50)

      # Manager must remain alive and responsive!
      assert Process.alive?(manager)
      status = TrustBundleManager.status(manager)
      assert status.status in ["applied", "initializing", "recovery_required"]

      # Corrupt dead letter archive bytes must NOT have been overwritten
      assert File.read!(dl_path) == "{\"rejected_observations\": [123]}"

      # Outbox entry must be preserved!
      assert {:ok, %{outbox: [entry]}} = AtomicStore.read_outbox(bundle_dir)
      assert entry["sequence"] == 1

      GenServer.stop(manager)
    end

    test "SecretHub.Agent.Application child specs start TrustBundleManager under Supervisor",
         %{tmp_dir: tmp_dir} do
      state_dir = Path.join(tmp_dir, "app_sup_state_dir")
      bundle_dir = Path.join(tmp_dir, "app_sup_bundle_dir")
      File.mkdir_p!(state_dir)
      File.mkdir_p!(bundle_dir)

      material = %{
        agent_id: "agent-supervisor-spec-test",
        private_key_pem: "---FAKE KEY---",
        certificate_pem: "---FAKE CERT---",
        ca_chain_pem: "---FAKE CA CHAIN---",
        connect_info: %{"endpoint" => "wss://localhost:4664/socket/agent/runtime"},
        identity: %{"agent_id" => "agent-supervisor-spec-test"}
      }

      assert :ok = SecretHub.Agent.IdentityStore.write(state_dir, material)

      pki_opts = [
        bundle_dir: bundle_dir,
        state_dir: state_dir,
        name: :test_app_supervisor_manager
      ]

      child_spec = {SecretHub.Agent.PKI.TrustBundleManager, pki_opts}

      {:ok, sup} = Supervisor.start_link([child_spec], strategy: :one_for_one)

      children = Supervisor.which_children(sup)

      assert [
               {SecretHub.Agent.PKI.TrustBundleManager, pid, :worker,
                [SecretHub.Agent.PKI.TrustBundleManager]}
             ] = children

      assert is_pid(pid)
      assert Process.alive?(pid)

      status = TrustBundleManager.status(pid)
      assert status.agent_id == "agent-supervisor-spec-test"
      assert status.recovery_mode == :none

      Supervisor.stop(sup)
    end

    # --- Finding 1: Interrupted Outbox Repair Resumption ---

    test "interrupted outbox metadata repair resumes and preserves durable backup across retries and restarts",
         %{tmp_dir: tmp_dir, now: now} do
      bundle_dir = Path.join(tmp_dir, "pki_interrupted_repair_resumption_test")
      File.mkdir_p!(bundle_dir)
      outbox_path = Path.join(bundle_dir, "observation_sequence.json")

      raw_data = %{
        "observation_sequence" => 1,
        "outbox" => [
          %{
            "sequence" => 1,
            "receipt" => %{
              "agent_id" => nil,
              "observation_sequence" => 1,
              "status" => "applied",
              "applied_at" => ""
            },
            "enqueued_at" => DateTime.to_iso8601(now)
          }
        ],
        "updated_at" => DateTime.to_iso8601(now)
      }

      raw_json = Jason.encode!(raw_data)
      File.write!(outbox_path, raw_json)

      content_sha256 = :crypto.hash(:sha256, raw_json) |> Base.encode16(case: :lower)
      bak_path = Path.join(bundle_dir, "observation_sequence.json.bak-" <> content_sha256)

      # 1. First repair attempt: backup succeeds, but active-outbox replacement fails
      assert {:error, {:repair_persistence_failed, :eio}} =
               AtomicStore.repair_outbox_metadata(
                 bundle_dir,
                 %{agent_id: "agent-interrupted"},
                 inject_sequence_rename_error: :eio
               )

      # Durable backup file was created and is byte-for-byte identical to pre-repair outbox
      assert File.exists?(bak_path)
      assert File.read!(bak_path) == raw_json

      # Active outbox bytes remain completely unmodified
      assert File.read!(outbox_path) == raw_json

      # 2. Simulate process restart between attempts: TrustBundleManager starts against interrupted state
      {:ok, manager} =
        TrustBundleManager.start_link(
          bundle_dir: bundle_dir,
          agent_id: "agent-interrupted",
          name: :test_interrupted_repair_manager
        )

      status = TrustBundleManager.status(manager)
      assert status.recovery_mode == :quarantined
      assert status.outbox_restriction == :corrupted_outbox

      # 3. Retry without injection: reuses validated existing backup and completes repair
      assert :ok = TrustBundleManager.bind_identity(manager, "agent-interrupted")

      status_after = TrustBundleManager.status(manager)
      assert status_after.recovery_mode == :none
      assert status_after.outbox_restriction == nil
      assert status_after.trust_recovery_restriction == nil

      # Original backup bytes remain intact throughout
      assert File.read!(bak_path) == raw_json

      # Active outbox now contains repaired agent_id
      assert {:ok, %{highest_sequence: 1, outbox: [repaired_entry]}} =
               AtomicStore.read_outbox(bundle_dir)

      assert repaired_entry["receipt"]["agent_id"] == "agent-interrupted"
      assert repaired_entry["sequence"] == 1

      GenServer.stop(manager)

      # 4. Restart again after successful repair; manager starts cleanly without quarantine
      {:ok, manager2} =
        TrustBundleManager.start_link(
          bundle_dir: bundle_dir,
          agent_id: "agent-interrupted",
          name: :test_interrupted_repair_manager_restarted
        )

      status_restart = TrustBundleManager.status(manager2)
      assert status_restart.recovery_mode == :none
      assert status_restart.outbox_restriction == nil

      GenServer.stop(manager2)
    end

    test "repair_outbox_metadata rejects truncated or mismatching existing backup file",
         %{tmp_dir: tmp_dir, now: now} do
      bundle_dir = Path.join(tmp_dir, "pki_truncated_backup_test")
      File.mkdir_p!(bundle_dir)
      outbox_path = Path.join(bundle_dir, "observation_sequence.json")

      raw_data = %{
        "observation_sequence" => 1,
        "outbox" => [
          %{
            "sequence" => 1,
            "receipt" => %{
              "agent_id" => nil,
              "observation_sequence" => 1,
              "status" => "applied",
              "applied_at" => ""
            },
            "enqueued_at" => DateTime.to_iso8601(now)
          }
        ],
        "updated_at" => DateTime.to_iso8601(now)
      }

      raw_json = Jason.encode!(raw_data)
      File.write!(outbox_path, raw_json)

      content_sha256 = :crypto.hash(:sha256, raw_json) |> Base.encode16(case: :lower)
      bak_path = Path.join(bundle_dir, "observation_sequence.json.bak-" <> content_sha256)

      # Truncated or incomplete backup file
      File.write!(bak_path, binary_part(raw_json, 0, div(byte_size(raw_json), 2)))

      # Repair must reject incomplete backup and not modify active state
      assert {:error, {:backup_failed, {:backup_already_exists, ^bak_path}}} =
               AtomicStore.repair_outbox_metadata(bundle_dir, %{agent_id: "agent-1"})

      assert File.read!(outbox_path) == raw_json
    end

    # --- Finding 2: Authorized Trust Recovery State Transitions ---

    test "authorized trust recovery clears trust restriction, avoids rebinding re-quarantine, and allows subsequent unforced updates",
         %{tmp_dir: tmp_dir, bundle: bundle, now: now} do
      bundle_dir = Path.join(tmp_dir, "pki_authorized_recovery_lifecycle_test")
      File.mkdir_p!(bundle_dir)

      # 1. Damaged trust watermark with no surviving bundle
      File.write!(
        Path.join(bundle_dir, "watermark.json"),
        "{\"highest_seen_generation\": 10, \"highest_seen_crl_number\": 0}"
      )

      # 2. Supply verified Agent identity
      {:ok, manager} =
        TrustBundleManager.start_link(
          bundle_dir: bundle_dir,
          agent_id: "agent-verified-lifecycle",
          name: :test_authorized_recovery_lifecycle_manager
        )

      status = TrustBundleManager.status(manager)
      assert status.recovery_mode == :quarantined
      assert status.trust_recovery_restriction == :damaged_state_recovery_required
      assert status.status == "recovery_required"
      assert status.recovery_reasons == [:damaged_state_recovery_required]

      # 3. Perform explicitly authorized recovery operation (force: true)
      assert {:ok, receipt} =
               TrustBundleManager.process_bundle(manager, bundle, force: true, now: now)

      assert receipt["status"] == "applied"

      # 4. Assert resolved trust restriction is cleared
      status_after = TrustBundleManager.status(manager)
      assert status_after.trust_recovery_restriction == nil
      assert status_after.outbox_restriction == nil
      assert status_after.recovery_mode == :none
      assert status_after.status == "applied"
      assert status_after.needs_repair == false
      assert status_after.recovery_reasons == []

      # 5. Bind the same identity again; quarantine must not return
      assert :ok = TrustBundleManager.bind_identity(manager, "agent-verified-lifecycle")
      status_rebound = TrustBundleManager.status(manager)
      assert status_rebound.recovery_mode == :none
      assert status_rebound.trust_recovery_restriction == nil
      assert status_rebound.status == "applied"
      assert status_rebound.recovery_reasons == []

      # 6. Process a newer valid bundle (generation 2) without force; it must succeed
      transcript2 =
        [
          bundle["schema_version"],
          bundle["authority"],
          2,
          bundle["ca_fingerprint"],
          bundle["crl_number"],
          bundle["crl_der_sha256"],
          bundle["this_update"],
          bundle["next_update"],
          bundle["ca_bundle_pem"],
          bundle["crl_pem"]
        ]
        |> Enum.map(&to_string/1)
        |> Enum.join("|")

      bundle_gen2 =
        bundle
        |> Map.put("generation", 2)
        |> Map.put(
          "bundle_sha256",
          :crypto.hash(:sha256, transcript2) |> Base.encode16(case: :lower)
        )

      assert {:ok, receipt2} =
               TrustBundleManager.process_bundle(manager, bundle_gen2, now: now)

      assert receipt2["status"] == "applied"
      status_gen2 = TrustBundleManager.status(manager)
      assert status_gen2.current_generation == 2
      assert status_gen2.recovery_mode == :none
      assert status_gen2.status == "applied"

      GenServer.stop(manager)

      # 7. Restart and verify consistent recovered state
      {:ok, restarted_manager} =
        TrustBundleManager.start_link(
          bundle_dir: bundle_dir,
          agent_id: "agent-verified-lifecycle",
          name: :test_authorized_recovery_lifecycle_manager_restarted
        )

      status_restarted = TrustBundleManager.status(restarted_manager)
      assert status_restarted.recovery_mode == :none
      assert status_restarted.status == "applied"
      assert status_restarted.trust_recovery_restriction == nil
      assert status_restarted.outbox_restriction == nil
      assert status_restarted.current_generation == 2

      GenServer.stop(restarted_manager)
    end

    test "failed validation or publication during recovery retains trust restriction",
         %{tmp_dir: tmp_dir, bundle: bundle, now: now} do
      bundle_dir = Path.join(tmp_dir, "pki_failed_recovery_retains_restriction_test")
      File.mkdir_p!(bundle_dir)

      # Damaged watermark with no surviving bundle
      File.write!(
        Path.join(bundle_dir, "watermark.json"),
        "{\"highest_seen_generation\": 10, \"highest_seen_crl_number\": 0}"
      )

      {:ok, manager} =
        TrustBundleManager.start_link(
          bundle_dir: bundle_dir,
          agent_id: "agent-failed-rec-test",
          name: :test_failed_rec_manager
        )

      status = TrustBundleManager.status(manager)
      assert status.recovery_mode == :quarantined
      assert status.trust_recovery_restriction == :damaged_state_recovery_required

      # 1. Validation failure (unsupported schema version)
      invalid_bundle = Map.put(bundle, "schema_version", 99)

      assert {:error, :invalid_schema_version, receipt1} =
               TrustBundleManager.process_bundle(manager, invalid_bundle, force: true, now: now)

      assert receipt1["status"] == "failed"
      status1 = TrustBundleManager.status(manager)
      assert status1.trust_recovery_restriction == :damaged_state_recovery_required
      assert status1.recovery_mode == :quarantined
      assert status1.status == "failed"

      # 2. Publication failure (injected watermark fsync error)
      assert {:error, :watermark_commit_failed, receipt2} =
               TrustBundleManager.process_bundle(
                 manager,
                 bundle,
                 force: true,
                 inject_watermark_fsync_error: :eio,
                 now: now
               )

      assert receipt2["status"] == "failed"
      status2 = TrustBundleManager.status(manager)
      assert status2.trust_recovery_restriction == :damaged_state_recovery_required
      assert status2.recovery_mode == :quarantined

      GenServer.stop(manager)
    end

    test "outbox-only repair preserves independent trust restriction",
         %{tmp_dir: tmp_dir, bundle: bundle, now: now} do
      bundle_dir = Path.join(tmp_dir, "pki_outbox_repair_preserves_trust_test")
      File.mkdir_p!(bundle_dir)

      # 1. Damaged trust watermark with no surviving bundle
      File.write!(
        Path.join(bundle_dir, "watermark.json"),
        "{\"highest_seen_generation\": 10, \"highest_seen_crl_number\": 0}"
      )

      # 2. Corrupted outbox (nil agent_id)
      outbox_path = Path.join(bundle_dir, "observation_sequence.json")

      raw_data = %{
        "observation_sequence" => 1,
        "outbox" => [
          %{
            "sequence" => 1,
            "receipt" => %{
              "agent_id" => nil,
              "observation_sequence" => 1,
              "status" => "applied",
              "applied_at" => ""
            },
            "enqueued_at" => DateTime.to_iso8601(now)
          }
        ],
        "updated_at" => DateTime.to_iso8601(now)
      }

      File.write!(outbox_path, Jason.encode!(raw_data))

      {:ok, manager} =
        TrustBundleManager.start_link(
          bundle_dir: bundle_dir,
          name: :test_outbox_repair_preserves_trust_manager
        )

      status = TrustBundleManager.status(manager)
      assert status.recovery_mode == :quarantined
      assert status.trust_recovery_restriction == :damaged_state_recovery_required
      assert status.outbox_restriction == :corrupted_outbox

      # 3. Repair outbox via bind_identity
      assert :ok = TrustBundleManager.bind_identity(manager, "agent-outbox-only")

      status_after = TrustBundleManager.status(manager)
      # Outbox restriction was cleared
      assert status_after.outbox_restriction == nil
      # Trust restriction remains strictly enforced!
      assert status_after.trust_recovery_restriction == :damaged_state_recovery_required
      assert status_after.recovery_mode == :quarantined
      assert status_after.status == "recovery_required"

      # Candidate bundle submissions without force remain rejected
      assert {:error, :damaged_state_recovery_required, _} =
               TrustBundleManager.process_bundle(manager, bundle, now: now)

      GenServer.stop(manager)
    end

    test "successful trust recovery does not clear independently unresolved outbox restriction",
         %{tmp_dir: tmp_dir, bundle: bundle, now: now} do
      bundle_dir = Path.join(tmp_dir, "pki_trust_recovery_preserves_outbox_test")
      File.mkdir_p!(bundle_dir)

      # 1. Damaged trust watermark with no surviving bundle
      File.write!(
        Path.join(bundle_dir, "watermark.json"),
        "{\"highest_seen_generation\": 10, \"highest_seen_crl_number\": 0}"
      )

      # 2. Corrupted outbox (nil agent_id)
      outbox_path = Path.join(bundle_dir, "observation_sequence.json")

      raw_data = %{
        "observation_sequence" => 1,
        "outbox" => [
          %{
            "sequence" => 1,
            "receipt" => %{
              "agent_id" => nil,
              "observation_sequence" => 1,
              "status" => "applied",
              "applied_at" => ""
            },
            "enqueued_at" => DateTime.to_iso8601(now)
          }
        ],
        "updated_at" => DateTime.to_iso8601(now)
      }

      File.write!(outbox_path, Jason.encode!(raw_data))

      {:ok, manager} =
        TrustBundleManager.start_link(
          bundle_dir: bundle_dir,
          agent_id: "agent-dual-restriction",
          name: :test_trust_recovery_preserves_outbox_manager
        )

      status = TrustBundleManager.status(manager)
      assert status.recovery_mode == :quarantined
      assert status.trust_recovery_restriction == :damaged_state_recovery_required
      assert status.outbox_restriction == :corrupted_outbox

      # 3. Perform authorized trust recovery (force: true)
      # Trust material commits to disk, but receipt persistence fails because outbox is corrupted.
      assert {:error, :receipt_persistence_failed, nil} =
               TrustBundleManager.process_bundle(manager, bundle, force: true, now: now)

      status_after_trust = TrustBundleManager.status(manager)
      # Trust recovery committed to disk and trust restriction resolved/cleared:
      assert status_after_trust.trust_recovery_restriction == nil
      # Outbox restriction was NOT cleared by trust recovery:
      assert status_after_trust.outbox_restriction == :corrupted_outbox
      assert status_after_trust.recovery_mode == :quarantined
      assert status_after_trust.status == "recovery_required"
      assert status_after_trust.recovery_reasons == [:corrupted_outbox]

      # Candidate bundle submissions without force remain rejected because manager is still quarantined
      assert {:error, rejected_code, _} =
               TrustBundleManager.process_bundle(manager, bundle, now: now)

      assert rejected_code in [:damaged_state_recovery_required, :receipt_persistence_failed]
      assert TrustBundleManager.status(manager).recovery_mode == :quarantined

      # 4. Now repair outbox via bind_identity
      assert :ok = TrustBundleManager.bind_identity(manager, "agent-dual-restriction")

      status_final = TrustBundleManager.status(manager)
      assert status_final.outbox_restriction == nil
      assert status_final.trust_recovery_restriction == nil
      assert status_final.recovery_mode == :none
      assert status_final.status == "applied"
      assert status_final.needs_repair == false
      assert status_final.recovery_reasons == []

      GenServer.stop(manager)
    end

    # --- Reproduction Tests for Review Findings ---

    test "identity binding and outbox repair preserves unresolved trust-installation rollback and repair requirement",
         %{tmp_dir: tmp_dir, bundle: bundle, now: now} do
      bundle_dir = Path.join(tmp_dir, "pki_rollback_preservation_test")
      File.mkdir_p!(bundle_dir)

      make_bundle = fn gen ->
        transcript =
          [
            bundle["schema_version"],
            bundle["authority"],
            gen,
            bundle["ca_fingerprint"],
            bundle["crl_number"],
            bundle["crl_der_sha256"],
            bundle["this_update"],
            bundle["next_update"],
            bundle["ca_bundle_pem"],
            bundle["crl_pem"]
          ]
          |> Enum.map(&to_string/1)
          |> Enum.join("|")

        bundle
        |> Map.put("generation", gen)
        |> Map.put(
          "bundle_sha256",
          :crypto.hash(:sha256, transcript) |> Base.encode16(case: :lower)
        )
      end

      # 1. Publish generation 9
      bundle_gen9 = make_bundle.(9)
      assert {:ok, _} = AtomicStore.write_bundle(bundle_dir, bundle_gen9, now: now)

      # 2. Publish generation 10
      bundle_gen10 = make_bundle.(10)
      assert {:ok, _} = AtomicStore.write_bundle(bundle_dir, bundle_gen10, now: now)

      # Both generations 9 and 10 exist on disk.
      # Persistent watermark is at generation 10.
      # Artificially switch current/ symlink back to generation 9 to simulate a rollback!
      current_symlink = Path.join(bundle_dir, "current")
      File.rm!(current_symlink)
      File.ln_s!(Path.join("generations", "9"), current_symlink)

      # Ensure outbox exists and has a missing agent_id so bind_identity performs repair work
      outbox_path = Path.join(bundle_dir, "observation_sequence.json")

      raw_data = %{
        "observation_sequence" => 1,
        "outbox" => [
          %{
            "sequence" => 1,
            "receipt" => %{
              "agent_id" => nil,
              "observation_sequence" => 1,
              "status" => "applied",
              "applied_at" => ""
            },
            "enqueued_at" => DateTime.to_iso8601(now)
          }
        ],
        "updated_at" => DateTime.to_iso8601(now)
      }

      File.write!(outbox_path, Jason.encode!(raw_data))

      # 3. Start manager with Core unavailable so automatic reconciliation cannot hide test condition
      {:ok, manager} =
        TrustBundleManager.start_link(
          bundle_dir: bundle_dir,
          name: :test_rollback_preservation_manager,
          connection_mod: :fake_unavailable_conn
        )

      # 4. Confirm rollback error and needs_repair on startup
      status = TrustBundleManager.status(manager)
      assert status.current_generation == 9
      assert status.lkg_generation == 10
      assert status.needs_repair == true
      assert status.recovery_mode == :quarantined

      # 5. Bind legitimate identity (repairs outbox and clears outbox restriction)
      assert :ok = TrustBundleManager.bind_identity(manager, "agent-legitimate-id")

      # 6. Assert the rollback error/repair requirement survives and disk is unchanged!
      status_rebound = TrustBundleManager.status(manager)
      assert status_rebound.current_generation == 9
      assert status_rebound.lkg_generation == 10
      assert status_rebound.needs_repair == true
      assert status_rebound.status == "error"
      assert status_rebound.last_error_code == :generation_rollback
      assert status_rebound.recovery_mode == :none
      assert status_rebound.outbox_restriction == nil
      assert status_rebound.trust_recovery_restriction == nil
      assert File.read_link!(current_symlink) == "generations/9"

      # 7. Successfully install generation 10; only now may readiness become applied!
      assert {:ok, receipt} =
               TrustBundleManager.process_bundle(manager, bundle_gen10, now: now)

      assert receipt["status"] == "applied"

      status_final = TrustBundleManager.status(manager)
      assert status_final.current_generation == 10
      assert status_final.lkg_generation == 10
      assert status_final.status == "applied"
      assert status_final.needs_repair == false
      assert status_final.last_error_code == nil
      assert status_final.recovery_mode == :none

      GenServer.stop(manager)
    end

    test "injecting failure at reused-backup file synchronization halts repair and preserves active outbox and backup",
         %{tmp_dir: tmp_dir, now: now} do
      bundle_dir = Path.join(tmp_dir, "pki_backup_sync_fail_test")
      File.mkdir_p!(bundle_dir)
      outbox_path = Path.join(bundle_dir, "observation_sequence.json")

      # Create watermark file to verify it stays untouched
      wm_data = %{"highest_seen_generation" => 5, "highest_seen_crl_number" => 1}
      File.write!(Path.join(bundle_dir, "watermark.json"), Jason.encode!(wm_data))

      raw_data = %{
        "observation_sequence" => 1,
        "outbox" => [
          %{
            "sequence" => 1,
            "receipt" => %{
              "agent_id" => nil,
              "observation_sequence" => 1,
              "status" => "applied",
              "applied_at" => ""
            },
            "enqueued_at" => DateTime.to_iso8601(now)
          }
        ],
        "updated_at" => DateTime.to_iso8601(now)
      }

      raw_json = Jason.encode!(raw_data)
      File.write!(outbox_path, raw_json)

      content_sha256 = :crypto.hash(:sha256, raw_json) |> Base.encode16(case: :lower)
      bak_path = Path.join(bundle_dir, "observation_sequence.json.bak-" <> content_sha256)

      # Existing backup left before file sync
      File.write!(bak_path, raw_json)

      # 1. Inject failure at reused-backup file synchronization
      assert {:error, {:backup_failed, :eio}} =
               AtomicStore.repair_outbox_metadata(
                 bundle_dir,
                 %{agent_id: "agent-fail-sync"},
                 inject_backup_sync_error: :eio
               )

      # 2. Assert active outbox bytes, sequences, and trust watermarks are completely unchanged
      assert File.read!(outbox_path) == raw_json
      assert File.read!(bak_path) == raw_json
      assert Jason.decode!(File.read!(Path.join(bundle_dir, "watermark.json"))) == wm_data

      # 3. Retry after failure resolution and verify successful resumable repair
      assert :ok =
               AtomicStore.repair_outbox_metadata(
                 bundle_dir,
                 %{agent_id: "agent-fail-sync"}
               )

      # Repaired outbox contains new agent_id
      assert {:ok, %{highest_sequence: 1, outbox: [repaired]}} =
               AtomicStore.read_outbox(bundle_dir)

      assert repaired["receipt"]["agent_id"] == "agent-fail-sync"
      assert File.read!(bak_path) == raw_json
    end

    test "publication failure after watermark advance but before pointer switch preserves error across identity binding",
         %{tmp_dir: tmp_dir, bundle: bundle, now: now} do
      bundle_dir = Path.join(tmp_dir, "pki_post_wm_failure_preservation_test")
      File.mkdir_p!(bundle_dir)

      make_bundle = fn gen ->
        transcript =
          [
            bundle["schema_version"],
            bundle["authority"],
            gen,
            bundle["ca_fingerprint"],
            bundle["crl_number"],
            bundle["crl_der_sha256"],
            bundle["this_update"],
            bundle["next_update"],
            bundle["ca_bundle_pem"],
            bundle["crl_pem"]
          ]
          |> Enum.map(&to_string/1)
          |> Enum.join("|")

        bundle
        |> Map.put("generation", gen)
        |> Map.put(
          "bundle_sha256",
          :crypto.hash(:sha256, transcript) |> Base.encode16(case: :lower)
        )
      end

      # 1. Install generation 1 first
      bundle_gen1 = make_bundle.(1)
      assert {:ok, _} = AtomicStore.write_bundle(bundle_dir, bundle_gen1, now: now)

      {:ok, manager} =
        TrustBundleManager.start_link(
          bundle_dir: bundle_dir,
          agent_id: "agent-post-wm",
          name: :test_post_wm_failure_manager,
          connection_mod: :fake_unavailable_conn
        )

      status1 = TrustBundleManager.status(manager)
      assert status1.current_generation == 1
      assert status1.status == "applied"
      assert status1.needs_repair == false

      # 2. Attempt to publish generation 2, but inject symlink switch error (after watermark committed)
      bundle_gen2 = make_bundle.(2)

      assert {:error, :pointer_switch_failed, _receipt} =
               TrustBundleManager.process_bundle(
                 manager,
                 bundle_gen2,
                 inject_symlink_switch_error: :eio,
                 now: now
               )

      status2 = TrustBundleManager.status(manager)
      assert status2.status == "failed"
      assert status2.needs_repair == true
      assert status2.last_error_code == "pointer_switch_failed"
      assert status2.lkg_generation == 2
      assert status2.current_generation == 1

      # 3. Call bind_identity; publication failure and repair requirement must survive!
      assert :ok = TrustBundleManager.bind_identity(manager, "agent-post-wm")

      status3 = TrustBundleManager.status(manager)
      assert status3.status == "failed"
      assert status3.needs_repair == true
      assert status3.last_error_code == "pointer_switch_failed"
      assert status3.lkg_generation == 2
      assert status3.current_generation == 1

      GenServer.stop(manager)
    end

    test "reusing existing backup verifies durability and traces validate -> sync backup -> sync parent -> replace outbox",
         %{tmp_dir: tmp_dir, now: now} do
      bundle_dir = Path.join(tmp_dir, "pki_backup_durability_trace_test")
      File.mkdir_p!(bundle_dir)
      outbox_path = Path.join(bundle_dir, "observation_sequence.json")

      raw_data = %{
        "observation_sequence" => 1,
        "outbox" => [
          %{
            "sequence" => 1,
            "receipt" => %{
              "agent_id" => nil,
              "observation_sequence" => 1,
              "status" => "applied",
              "applied_at" => ""
            },
            "enqueued_at" => DateTime.to_iso8601(now)
          }
        ],
        "updated_at" => DateTime.to_iso8601(now)
      }

      raw_json = Jason.encode!(raw_data)
      File.write!(outbox_path, raw_json)

      content_sha256 = :crypto.hash(:sha256, raw_json) |> Base.encode16(case: :lower)
      bak_path = Path.join(bundle_dir, "observation_sequence.json.bak-" <> content_sha256)

      # Write pre-existing backup file (simulating left before sync)
      File.write!(bak_path, raw_json)

      # 1. Trace actual operation order
      tracer = start_op_tracer()

      assert :ok =
               AtomicStore.repair_outbox_metadata(
                 bundle_dir,
                 %{agent_id: "agent-trace-test"},
                 record_operations_to: tracer
               )

      ops = get_traced_ops(tracer)

      # Deterministic, ordered arrival assertions requiring:
      # validate_backup -> sync_backup_file -> sync_parent_dir -> replace_active_outbox
      assert_operation_order(ops, [
        {:validate_backup, bak_path},
        {:sync_backup_file, bak_path},
        {:sync_parent_dir, bundle_dir},
        {:replace_active_outbox, outbox_path}
      ])

      assert ops == [
               {:validate_backup, bak_path},
               {:sync_backup_file, bak_path},
               {:sync_parent_dir, bundle_dir},
               {:replace_active_outbox, outbox_path},
               {:persist_observation_sequence, 1},
               {:repair_outbox_metadata, bak_path}
             ]
    end

    test "order verification predicate rejects deliberately reordered traces (e.g. outbox replacement before backup sync)",
         %{tmp_dir: tmp_dir} do
      bak_path = Path.join(tmp_dir, "observation_sequence.json.bak-dummy")
      outbox_path = Path.join(tmp_dir, "observation_sequence.json")
      bundle_dir = tmp_dir

      expected_order = [
        {:validate_backup, bak_path},
        {:sync_backup_file, bak_path},
        {:sync_parent_dir, bundle_dir},
        {:replace_active_outbox, outbox_path}
      ]

      # 1. Valid trace passes
      valid_trace = [
        {:validate_backup, bak_path},
        {:sync_backup_file, bak_path},
        {:sync_parent_dir, bundle_dir},
        {:replace_active_outbox, outbox_path},
        {:persist_observation_sequence, 1},
        {:repair_outbox_metadata, bak_path}
      ]

      assert :ok = assert_operation_order(valid_trace, expected_order)

      # 2. Negative test: replace_active_outbox happens before sync_backup_file
      reordered_outbox_first = [
        {:validate_backup, bak_path},
        {:replace_active_outbox, outbox_path},
        {:sync_backup_file, bak_path},
        {:sync_parent_dir, bundle_dir}
      ]

      assert_raise ExUnit.AssertionError, fn ->
        assert_operation_order(reordered_outbox_first, expected_order)
      end

      # 3. Negative test: sync_parent_dir happens before sync_backup_file
      reordered_parent_first = [
        {:validate_backup, bak_path},
        {:sync_parent_dir, bundle_dir},
        {:sync_backup_file, bak_path},
        {:replace_active_outbox, outbox_path}
      ]

      assert_raise ExUnit.AssertionError, fn ->
        assert_operation_order(reordered_parent_first, expected_order)
      end

      # 4. Negative test: sync_backup_file omitted completely
      missing_sync_step = [
        {:validate_backup, bak_path},
        {:sync_parent_dir, bundle_dir},
        {:replace_active_outbox, outbox_path}
      ]

      assert_raise ExUnit.AssertionError, fn ->
        assert_operation_order(missing_sync_step, expected_order)
      end
    end
  end

  # --- Tracing and Order Assertion Helpers ---

  defp start_op_tracer do
    parent = self()
    spawn_link(fn -> op_tracer_loop([], parent) end)
  end

  defp op_tracer_loop(acc, parent) do
    receive do
      {:atomic_store_op, op} ->
        op_tracer_loop([op | acc], parent)

      {:get_ops, caller} ->
        send(caller, {:traced_ops, Enum.reverse(acc)})
    end
  end

  defp get_traced_ops(tracer, timeout \\ 1000) do
    send(tracer, {:get_ops, self()})

    receive do
      {:traced_ops, ops} -> ops
    after
      timeout -> flunk("Timed out waiting for traced ops")
    end
  end

  defp assert_operation_order(actual_ops, expected_ops) do
    expected_tags = Enum.map(expected_ops, fn {tag, _} -> tag end)
    filtered_ops = Enum.filter(actual_ops, fn {tag, _} -> tag in expected_tags end)

    if filtered_ops != expected_ops do
      flunk("""
      Operation order assertion failed!
      Expected ordered subsequence:
      #{inspect(expected_ops, pretty: true)}

      Actual filtered operations:
      #{inspect(filtered_ops, pretty: true)}

      All captured operations:
      #{inspect(actual_ops, pretty: true)}
      """)
    end

    :ok
  end
end
