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
  end
end
