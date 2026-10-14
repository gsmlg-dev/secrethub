defmodule SecretHub.Web.VaultRecoveryControllerTest do
  use SecretHub.Web.ConnCase, async: false

  import ExUnit.CaptureLog

  alias SecretHub.Core.Repo
  alias SecretHub.Core.Vault.SealState
  alias SecretHub.Shared.Crypto.{Encryption, Shamir}
  alias SecretHub.Shared.Schemas.{AuditLog, Secret, VaultConfig}

  setup do
    key = :binary.copy(<<252>>, 32)

    config =
      Repo.insert!(%VaultConfig{
        encrypted_master_key: <<1, 0::480>>,
        threshold: 3,
        total_shares: 5,
        initialized_at: DateTime.utc_now() |> DateTime.truncate(:second)
      })

    {:ok, ciphertext} = Encryption.encrypt_to_blob("preserved legacy secret", key)

    secret =
      Repo.insert!(
        Secret.changeset(%Secret{}, %{
          name: "legacy recovery",
          secret_path: "test.legacy.recovery",
          encrypted_data: ciphertext
        })
      )

    start_supervised!(SealState)
    await_loaded(200)
    {:ok, key: key, config: config, secret: secret, shares: legacy_shares(key)}
  end

  test "GET offers the sealed legacy recovery form without share material" do
    conn = get(build_conn(), "/vault/recover")
    body = html_response(conn, 200)
    assert body =~ ~s(id="vault-recovery-form")
    assert body =~ "recovery[shares]"
    assert body =~ "recovery[backup_confirmed]"
    assert get_resp_header(conn, "cache-control") == ["no-store"]
    refute body =~ "secrethub-share-"
  end

  test "authenticated recovery preserves the old data and issues usable v4 shares", context do
    conn = submit(context.shares, %{"total_shares" => "1", "threshold" => "1"})
    body = html_response(conn, 200)

    encoded =
      Regex.scan(~r/secrethub-share-[A-Za-z0-9_-]+/, body) |> List.flatten() |> Enum.uniq()

    assert length(encoded) == 5

    decoded =
      Enum.map(encoded, fn share ->
        {:ok, decoded} = Shamir.decode_share(share)
        decoded
      end)

    assert Enum.all?(decoded, &(&1.version == 4))

    recovered = Repo.one!(VaultConfig)
    assert recovered.id == context.config.id
    assert recovered.initialized_at == context.config.initialized_at
    assert recovered.threshold == 3
    assert recovered.total_shares == 5
    assert recovered.envelope_version == 1
    assert recovered.share_version == 4
    assert byte_size(recovered.share_set_id) == 16
    assert Repo.get!(Secret, context.secret.id) == context.secret
    assert %{sealed: true, recovery_required: false} = SealState.status()
    assert Enum.any?(Repo.all(AuditLog), &(&1.event_type == "vault_legacy_recovered"))
    assert get_resp_header(conn, "cache-control") == ["no-store"]
    refute inspect(get_session(conn)) =~ "secrethub-share-"
    Enum.each(context.shares, &refute(body =~ &1))

    Enum.each(Enum.take(decoded, 3), &SealState.unseal/1)
    assert {:ok, key} = SealState.get_master_key()
    assert key == context.key

    assert {:ok, "preserved legacy secret"} =
             Encryption.decrypt_from_blob(context.secret.encrypted_data, key)
  end

  test "wrong shares fail authentication without changing or reflecting old material", context do
    wrong = legacy_shares(:binary.copy(<<253>>, 32))
    original_log_level = Logger.level()

    logs =
      try do
        Logger.configure(level: :debug)

        capture_log([level: :debug], fn ->
          conn = submit(wrong)
          assert_blank_error(conn, 422, wrong)
          refute inspect(get_session(conn)) =~ "secrethub-share-"
        end)
      after
        Logger.configure(level: original_log_level)
      end

    assert Logger.level() == original_log_level
    assert logs =~ "Processing with SecretHub.Web.VaultRecoveryController.recover/2"
    assert logs =~ "Parameters:"
    assert logs =~ ~s("shares" => "[FILTERED]")
    Enum.each(wrong, &refute(logs =~ &1))
    assert_unchanged(context)
  end

  test "missing backup confirmation rejects recovery", context do
    conn = submit(context.shares, %{"backup_confirmed" => "false"})
    assert_blank_error(conn, 400, context.shares)
    assert_unchanged(context)
  end

  test "insufficient, duplicate and excessive shares reject recovery", context do
    for shares <- [
          Enum.take(context.shares, 2),
          [hd(context.shares), hd(context.shares), List.last(context.shares)],
          legacy_shares(context.key, 6)
        ] do
      assert_blank_error(submit(shares), 400, shares)
      assert_unchanged(context)
    end
  end

  test "malformed parameter shapes and oversized inputs reject recovery", context do
    for shares <- [nil, %{"nested" => "secret-input"}, String.duplicate("s", 32_769)] do
      conn =
        post(build_conn(), "/vault/recover", %{
          "recovery" => %{"shares" => shares, "backup_confirmed" => "true"}
        })

      assert conn.status == 400
      refute html_response(conn, 400) =~ "secret-input"
      assert_unchanged(context)
    end

    assert_blank_error(submit(["malformed-one", "malformed-two", "malformed-three"]), 422, [])
    assert_unchanged(context)
  end

  test "whitespace and comma separated shares are accepted", context do
    shares = Enum.join(context.shares, ",\n \t")

    conn =
      post(build_conn(), "/vault/recover", %{
        "recovery" => %{"shares" => shares, "backup_confirmed" => "true"}
      })

    assert conn.status == 200
    assert %{sealed: true, recovery_required: false} = SealState.status()
  end

  test "repeat submission and subsequent GET cannot retrieve returned shares", context do
    assert submit(context.shares).status == 200
    recovered = Repo.one!(VaultConfig)
    assert_blank_error(submit(context.shares), 409, context.shares)
    conn = get(build_conn(), "/vault/recover")
    assert conn.status == 409
    refute html_response(conn, 409) =~ "secrethub-share-"
    assert Repo.one!(VaultConfig) == recovered
  end

  test "uninitialized and unsealed states are ineligible", context do
    stop_supervised(SealState)
    Repo.delete!(context.config)
    start_supervised!(SealState)
    await_loaded(200)
    assert submit(context.shares).status == 409
    {:ok, shares} = SealState.initialize(5, 3)
    Enum.each(Enum.take(shares, 3), &SealState.unseal/1)
    assert submit(context.shares).status == 409
  end

  test "missing state process fails closed without exception details", context do
    stop_supervised(SealState)
    conn = submit(context.shares)
    assert_blank_error(conn, 503, context.shares)
    refute html_response(conn, 503) =~ "noproc"
    assert Repo.one!(VaultConfig) == context.config
  end

  test "stale durable state rejects recovery without replacing the changed config", context do
    changed =
      Repo.update!(Ecto.Changeset.change(context.config, encrypted_master_key: <<1, 1::480>>))

    assert_blank_error(submit(context.shares), 422, context.shares)
    assert Repo.one!(VaultConfig) == changed
    assert Repo.get!(Secret, context.secret.id) == context.secret
    assert SealState.status().sealed
  end

  test "CSRF and public management peers cannot recover", context do
    assert_raise Plug.CSRFProtection.InvalidCSRFTokenError, fn ->
      build_conn()
      |> put_private(:plug_skip_csrf_protection, false)
      |> post("/vault/recover", %{
        "recovery" => %{"shares" => Enum.join(context.shares, "\n"), "backup_confirmed" => "true"}
      })
    end

    conn = build_conn() |> Map.put(:remote_ip, {203, 0, 113, 1}) |> post("/vault/recover", %{})
    assert conn.status == 403
    assert_unchanged(context)
  end

  defp submit(shares, overrides \\ %{}) do
    params =
      Map.merge(%{"shares" => Enum.join(shares, "\n"), "backup_confirmed" => "true"}, overrides)

    post(build_conn(), "/vault/recover", %{"recovery" => params})
  end

  defp assert_blank_error(conn, status, shares) do
    body = html_response(conn, status)
    Enum.each(shares, &refute(body =~ &1))
    assert conn.assigns.form.params["shares"] == ""
    assert is_binary(conn.assigns.error_message)
    assert get_resp_header(conn, "cache-control") == ["no-store"]
  end

  defp assert_unchanged(context) do
    assert Repo.one!(VaultConfig) == context.config
    assert Repo.get!(Secret, context.secret.id) == context.secret
    assert %{sealed: true, recovery_required: true} = SealState.status()
  end

  defp await_loaded(0), do: flunk("Vault state did not finish loading")

  defp await_loaded(attempts) do
    if SealState.status().state == :loading do
      Process.sleep(5)
      await_loaded(attempts - 1)
    end
  end

  defp legacy_shares(key, total \\ 3) do
    mask = for <<byte <- key>>, into: <<>>, do: <<if(byte >= 251, do: 1, else: 0)>>

    for id <- 1..total do
      values =
        for <<byte <- key>>, into: <<>>, do: <<rem(rem(byte, 251) + 7 * id + 11 * id * id, 251)>>

      "secrethub-share-" <>
        Base.url_encode64(<<3, id, 3, 5, 32, 32, mask::binary, values::binary>>, padding: false)
    end
  end
end
