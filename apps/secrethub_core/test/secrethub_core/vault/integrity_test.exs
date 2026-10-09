defmodule SecretHub.Core.Vault.IntegrityTest do
  use SecretHub.Core.DataCase, async: false
  alias SecretHub.Core.Vault.SealState
  alias SecretHub.Shared.Crypto.{Encryption, Shamir}
  alias SecretHub.Shared.Schemas.{Secret, VaultConfig}

  defmodule VolatileRepo do
    def all(query, opts \\ []) do
      if Agent.get(__MODULE__, & &1) == :down,
        do: raise(DBConnection.ConnectionError, message: "unavailable")

      SecretHub.Core.Repo.all(query, opts)
    end

    def transaction(fun), do: SecretHub.Core.Repo.transaction(fun)

    def query(sql, params, opts) do
      if Agent.get(__MODULE__, & &1) == :down,
        do: raise(DBConnection.ConnectionError, message: "unavailable")

      SecretHub.Core.Repo.query(sql, params, opts)
    end

    def insert(changeset), do: SecretHub.Core.Repo.insert(changeset)
    def rollback(reason), do: SecretHub.Core.Repo.rollback(reason)
  end

  setup do
    stop_seal_state()
    {:ok, _pid} = SealState.start_link()
    await_loaded()
    on_exit(fn -> stop_seal_state() end)
    :ok
  end

  test "shares wrap a separate data key and survive restart with old ciphertext" do
    assert {:ok, shares} = SealState.initialize(5, 3)
    config = Repo.one!(VaultConfig)
    assert byte_size(config.share_set_id) == 16
    assert Enum.all?(shares, &(&1.share_set_id == config.share_set_id))
    assert {:ok, wrapping_key} = Shamir.combine(Enum.take(shares, 3))
    Enum.each(Enum.take(shares, 3), &SealState.unseal/1)
    assert {:ok, data_key} = SealState.get_master_key()
    refute wrapping_key == data_key
    {:ok, ciphertext} = Encryption.encrypt_to_blob("pre restart secret", data_key)
    GenServer.stop(SealState)
    {:ok, _} = SealState.start_link()
    await_loaded()
    assert SealState.status().sealed
    assert {:error, :sealed} = SealState.get_master_key()
    Enum.each(Enum.take(shares, 3), &SealState.unseal/1)
    assert {:ok, ^data_key} = SealState.get_master_key()
    assert {:ok, "pre restart secret"} = Encryption.decrypt_from_blob(ciphertext, data_key)
    assert :ok = SealState.seal()
    assert {:ok, ^data_key} = SealState.get_master_key()
  end

  test "forged threshold reconstruction stays sealed, clears progress and permits correct retry" do
    {:ok, shares} = SealState.initialize(5, 3)
    [first | _] = shares
    {:ok, forged} = Shamir.split(<<0::256>>, 5, 3, first.share_set_id)
    [a, b, c | _] = forged
    assert {:ok, _} = SealState.unseal(a)
    assert {:ok, _} = SealState.unseal(b)
    assert {:error, _} = SealState.unseal(c)
    assert %{sealed: true, progress: 0} = SealState.status()
    assert {:error, :sealed} = SealState.get_master_key()
    {:ok, fixture_blob} = Encryption.encrypt_to_blob("fixture", <<1::256>>)

    Repo.insert!(
      Secret.changeset(%Secret{}, %{
        name: "sealed fixture",
        secret_path: "test.sealed.fixture",
        encrypted_data: fixture_blob
      })
    )

    assert {:error, :sealed} = SecretHub.Core.Secrets.read_decrypted("test.sealed.fixture")

    assert {:error, :sealed} =
             SecretHub.Core.Secrets.create_secret(%{
               name: "blocked",
               secret_path: "test.blocked.write",
               secret_data: %{value: "blocked"}
             })

    assert {:error, "Vault is sealed"} =
             SecretHub.Core.PKI.CA.generate_root_ca("Blocked CA", "SecretHub", key_size: 2048)

    Enum.each(Enum.take(shares, 3), &SealState.unseal/1)
    refute SealState.status().sealed
  end

  test "rejects mixed, duplicate and malformed shares and resets the attempt" do
    {:ok, [a, b | _]} = SealState.initialize(5, 3)

    for invalid <- [
          a,
          %{b | share_set_id: <<0::128>>},
          %{b | threshold: 2},
          %{b | secret_length: 31},
          nil,
          %{}
        ] do
      assert {:ok, _} = SealState.unseal(a)
      assert {:error, _} = SealState.unseal(invalid)
      assert %{sealed: true, progress: 0} = SealState.status()
    end

    assert Process.alive?(Process.whereis(SealState))
  end

  test "concurrent initialization creates exactly one durable configuration" do
    results =
      1..8
      |> Enum.map(fn _ -> Task.async(fn -> SealState.initialize(5, 3) end) end)
      |> Enum.map(&Task.await/1)

    assert Enum.count(results, &match?({:ok, _}, &1)) == 1
    assert Repo.aggregate(VaultConfig, :count) == 1
    before = Repo.one!(VaultConfig)
    assert {:error, _} = SealState.initialize(5, 3)
    assert Repo.one!(VaultConfig) == before
  end

  test "database singleton prohibits an independent second writer" do
    {:ok, _} = SealState.initialize(5, 3)
    existing = Repo.one!(VaultConfig)

    changeset =
      VaultConfig.changeset(
        %VaultConfig{},
        Map.take(existing, [
          :encrypted_master_key,
          :threshold,
          :total_shares,
          :initialized_at,
          :envelope_version,
          :share_version,
          :share_set_id
        ])
      )

    assert {:error, _} = Repo.insert(changeset)
    assert Repo.aggregate(VaultConfig, :count) == 1
  end

  test "legacy recovery is blocked without trusted ciphertext and never replaces its configuration" do
    GenServer.stop(SealState)
    config = legacy_config()
    {:ok, _} = SealState.start_link()
    await_loaded()
    assert %{sealed: true, recovery_required: true} = SealState.status()
    assert {:error, _} = SealState.initialize(5, 3)
    assert {:error, _} = SealState.recover_legacy(legacy_shares(<<1::256>>), 5, 3)
    assert Repo.one!(VaultConfig) == config
  end

  test "legacy recovery verifies preexisting ciphertext, preserves its key and restarts sealed" do
    GenServer.stop(SealState)
    legacy_config()
    old_key = :binary.copy(<<252>>, 32)
    {:ok, ciphertext} = Encryption.encrypt_to_blob("old secret", old_key)

    Repo.insert!(
      Secret.changeset(%Secret{}, %{
        name: "recovery",
        secret_path: "test.legacy.key",
        encrypted_data: ciphertext
      })
    )

    {:ok, _} = SealState.start_link()
    await_loaded()
    assert {:error, _} = SealState.recover_legacy(legacy_shares(:binary.copy(<<253>>, 32)), 5, 3)
    assert {:ok, shares} = SealState.recover_legacy(legacy_shares(old_key), 5, 3)
    assert SealState.status().sealed
    GenServer.stop(SealState)
    {:ok, _} = SealState.start_link()
    await_loaded()
    Enum.each(Enum.take(shares, 3), &SealState.unseal/1)
    assert {:ok, ^old_key} = SealState.get_master_key()
    assert {:ok, "old secret"} = Encryption.decrypt_from_blob(ciphertext, old_key)
  end

  test "development-encrypted certificates cannot authenticate a legacy Vault key" do
    GenServer.stop(SealState)
    original = legacy_config()
    old_key = :crypto.strong_rand_bytes(32)
    fallback = :crypto.hash(:sha256, "test-encryption-key-for-pki-testing")
    {:ok, secret_blob} = Encryption.encrypt_to_blob("original Vault secret", old_key)

    Repo.insert!(
      Secret.changeset(%Secret{}, %{
        name: "legacy",
        secret_path: "legacy.real",
        encrypted_data: secret_blob
      })
    )

    signing_key = X509.PrivateKey.new_rsa(2048)
    cert = X509.Certificate.self_signed(signing_key, "/CN=Fallback CA")
    pem = X509.Certificate.to_pem(cert)
    {:ok, key_blob} = Encryption.encrypt_to_blob(X509.PrivateKey.to_pem(signing_key), fallback)
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    Repo.insert!(%SecretHub.Shared.Schemas.Certificate{
      serial_number: "fallback-fixture",
      fingerprint: "fallback-fixture",
      certificate_pem: pem,
      private_key_encrypted: key_blob,
      subject: "/CN=Fallback CA",
      issuer: "/CN=Fallback CA",
      common_name: "Fallback CA",
      cert_type: :root_ca,
      valid_from: now,
      valid_until: DateTime.add(now, 3600, :second)
    })

    {:ok, _} = SealState.start_link()
    await_loaded()
    assert match?({:error, _}, SealState.recover_legacy(legacy_shares(fallback), 5, 3))
    assert Repo.one!(VaultConfig) == original
    assert {:ok, _} = SealState.recover_legacy(legacy_shares(old_key), 5, 3)
  end

  test "initialization audit failure rolls back configuration and releases no shares" do
    reject_audit_signing()
    assert match?({:error, _}, SealState.initialize(5, 3))
    assert Repo.aggregate(VaultConfig, :count) == 0
  end

  test "legacy recovery audit failure preserves the old configuration" do
    GenServer.stop(SealState)
    original = legacy_config()
    old_key = :crypto.strong_rand_bytes(32)
    {:ok, blob} = Encryption.encrypt_to_blob("original", old_key)

    Repo.insert!(
      Secret.changeset(%Secret{}, %{
        name: "legacy",
        secret_path: "legacy.audit",
        encrypted_data: blob
      })
    )

    {:ok, _} = SealState.start_link()
    await_loaded()
    reject_audit_signing()
    assert match?({:error, _}, SealState.recover_legacy(legacy_shares(old_key), 5, 3))
    assert Repo.one!(VaultConfig) == original
  end

  test "unseal audit failure keeps the verified key unavailable and resets progress" do
    {:ok, [a, b, c | _]} = SealState.initialize(5, 3)
    reject_audit_signing()
    assert {:ok, _} = SealState.unseal(a)
    assert {:ok, _} = SealState.unseal(b)
    assert match?({:error, _}, SealState.unseal(c))
    assert %{sealed: true, progress: 0} = SealState.status()
    assert {:error, :sealed} = SealState.get_master_key()
  end

  defp reject_audit_signing do
    previous = Application.fetch_env(:secrethub_core, :audit_hmac_key_id)
    Application.put_env(:secrethub_core, :audit_hmac_key_id, "invalid/key/id")

    on_exit(fn ->
      case previous do
        {:ok, value} -> Application.put_env(:secrethub_core, :audit_hmac_key_id, value)
        :error -> Application.delete_env(:secrethub_core, :audit_hmac_key_id)
      end
    end)
  end

  test "insert interruption after row creation rolls back and returns no shares" do
    Ecto.Adapters.SQL.query!(
      Repo,
      "CREATE FUNCTION pg_temp.reject_vault_insert() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'simulated interruption'; END $$",
      []
    )

    Ecto.Adapters.SQL.query!(
      Repo,
      "CREATE TRIGGER reject_vault_insert AFTER INSERT ON vault_config FOR EACH ROW EXECUTE FUNCTION pg_temp.reject_vault_insert()",
      []
    )

    assert {:error, "Vault initialization failed; durable state unavailable"} =
             SealState.initialize(5, 3)

    assert Repo.aggregate(VaultConfig, :count) == 0
    assert %{state: :unavailable, sealed: true, initialized: false} = SealState.status()
  end

  test "malformed durable envelope never becomes an empty Vault" do
    {:ok, _} = SealState.initialize(5, 3)
    Repo.update_all(VaultConfig, set: [encrypted_master_key: <<2, 0::480>>])
    GenServer.stop(SealState)
    {:ok, _} = SealState.start_link()
    await_loaded()
    assert %{state: :unavailable, sealed: true} = SealState.status()
    assert {:error, _} = SealState.initialize(5, 3)
    assert Repo.aggregate(VaultConfig, :count) == 1
  end

  test "status, Inspect and rejected-share logs contain no key material" do
    {:ok, [share | _]} = SealState.initialize(5, 3)
    assert {:ok, _} = SealState.unseal(share)
    printed = inspect(:sys.get_state(SealState))
    refute printed =~ inspect(share.value)
    refute printed =~ Shamir.encode_share(share)
    refute Map.has_key?(SealState.status(), :master_key)
    logs = ExUnit.CaptureLog.capture_log(fn -> assert {:error, _} = SealState.unseal(share) end)
    refute logs =~ inspect(share.value)
    refute inspect(Repo.one!(VaultConfig)) =~ inspect(Repo.one!(VaultConfig).encrypted_master_key)
  end

  test "database loss clears verified key and recovers sealed with the same generation" do
    stop_seal_state()

    start_supervised!(%{
      id: VolatileRepo,
      start: {Agent, :start_link, [fn -> :up end, [name: VolatileRepo]]}
    })

    {:ok, _} = SealState.start_link(repo: VolatileRepo, retry_interval: 5)
    await_loaded()
    {:ok, shares} = SealState.initialize(5, 3)
    Enum.each(Enum.take(shares, 3), &SealState.unseal/1)
    assert {:ok, key} = SealState.get_master_key()
    before = Repo.one!(VaultConfig)
    Agent.update(VolatileRepo, fn _ -> :down end)
    assert {:error, :unavailable} = SealState.get_master_key()
    assert %{state: :unavailable, sealed: true} = SealState.status()
    assert {:error, _} = SealState.initialize(5, 3)
    Agent.update(VolatileRepo, fn _ -> :up end)
    await_state(:sealed)
    assert Repo.one!(VaultConfig) == before
    assert {:error, :sealed} = SealState.get_master_key()
    Enum.each(Enum.take(shares, 3), &SealState.unseal/1)
    assert {:ok, ^key} = SealState.get_master_key()
  end

  test "crash diagnostics redact submitted share and queued key replies" do
    {:ok, [share | _] = shares} = SealState.initialize(5, 3)
    pid = Process.whereis(SealState)
    Process.unlink(pid)
    ref = Process.monitor(pid)
    :sys.log(pid, true)
    Enum.each(Enum.take(shares, 3), &SealState.unseal/1)
    {:ok, key} = SealState.get_master_key()

    :sys.replace_state(pid, fn state ->
      %{state | status: :sealed, master_key: nil, unseal_shares: [nil]}
    end)

    logs =
      ExUnit.CaptureLog.capture_log(fn ->
        assert catch_exit(SealState.unseal(share))
        assert_receive {:DOWN, ^ref, :process, ^pid, _}
      end)

    refute logs =~ inspect(share.value)
    refute logs =~ Shamir.encode_share(share)
    refute logs =~ inspect(key)
    assert logs =~ "redacted"
  end

  test "crash diagnostics redact encoded legacy recovery submissions" do
    stop_seal_state()
    legacy_config()
    {:ok, _} = SealState.start_link()
    await_loaded()
    key = <<1::256>>
    encoded = legacy_shares(key)
    pid = Process.whereis(SealState)
    Process.unlink(pid)
    ref = Process.monitor(pid)

    :sys.replace_state(pid, fn state ->
      %{state | config: Map.delete(Map.from_struct(state.config), :id)}
    end)

    logs =
      ExUnit.CaptureLog.capture_log(fn ->
        assert catch_exit(SealState.recover_legacy(encoded, 5, 3))
        assert_receive {:DOWN, ^ref, :process, ^pid, _}
      end)

    Enum.each(encoded, fn share -> refute logs =~ share end)
    refute logs =~ inspect(key)
    assert logs =~ "redacted"
  end

  defp await_loaded(remaining \\ 100)
  defp await_loaded(0), do: flunk("Vault did not finish loading")

  defp await_loaded(remaining) do
    if SealState.status().state == :loading do
      Process.sleep(5)
      await_loaded(remaining - 1)
    end
  end

  defp await_state(expected, remaining \\ 100)
  defp await_state(_, 0), do: flunk("Vault state did not recover")

  defp await_state(expected, remaining) do
    if SealState.status().state != expected do
      Process.sleep(5)
      await_state(expected, remaining - 1)
    end
  end

  defp stop_seal_state do
    if pid = Process.whereis(SealState) do
      try do
        GenServer.stop(pid)
      catch
        :exit, {:noproc, _} -> :ok
      end
    end
  end

  defp legacy_config do
    Repo.insert!(%VaultConfig{
      encrypted_master_key: <<1, 0::480>>,
      threshold: 3,
      total_shares: 5,
      initialized_at: DateTime.utc_now() |> DateTime.truncate(:second)
    })
  end

  defp legacy_shares(key) do
    mask = for <<byte <- key>>, into: <<>>, do: <<if(byte >= 251, do: 1, else: 0)>>

    for id <- 1..3 do
      values =
        for <<byte <- key>>, into: <<>>, do: <<rem(rem(byte, 251) + 7 * id + 11 * id * id, 251)>>

      "secrethub-share-" <>
        Base.url_encode64(<<3, id, 3, 5, 32, 32, mask::binary, values::binary>>, padding: false)
    end
  end
end
