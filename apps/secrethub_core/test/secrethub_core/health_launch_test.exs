defmodule SecretHub.Core.HealthLaunchTest do
  use SecretHub.Core.DataCase, async: false

  alias SecretHub.Core.{Health, Vault.SealState}
  alias SecretHub.Core.Workers.ClientAuthCRLRefresher

  setup do
    previous_profile = Application.get_env(:secrethub_core, :launch_profile)
    Application.put_env(:secrethub_core, :launch_profile, :single_operator)
    previous = Application.get_env(:secrethub_core, :enabled_features)
    Application.put_env(:secrethub_core, :enabled_features, [:static_secrets])

    on_exit(fn ->
      Application.put_env(:secrethub_core, :enabled_features, previous)
      Application.put_env(:secrethub_core, :launch_profile, previous_profile)
    end)

    start_supervised!(SealState)
    await_loaded(200)
    :ok
  end

  test "sealed initialized Vault keeps management available but cannot serve secrets" do
    assert {:ok, _shares} = SealState.initialize(3, 2)
    assert {:ok, %{ready: true, service: "management"}} = Health.management_readiness()
    assert {:error, %{ready: false, service: "secrets"}} = Health.readiness()
    assert {:ok, %{status: "alive"}} = Health.liveness()
  end

  test "empty Vault has management availability without secret readiness" do
    assert {:ok, %{ready: true}} = Health.management_readiness()
    assert {:error, %{ready: false}} = Health.readiness()
  end

  test "verified unsealed key enables secret readiness" do
    unseal!()
    assert {:ok, %{ready: true, service: "secrets"}} = Health.readiness()
  end

  test "state claiming unsealed without a verified data key is not ready" do
    unseal!()
    :sys.replace_state(SealState, &%{&1 | master_key: nil})
    assert {:error, %{ready: false}} = Health.readiness()
  end

  test "enabled PKI requires an actual running CRL worker" do
    unseal!()
    Application.put_env(:secrethub_core, :enabled_features, [:static_secrets, :client_auth_pki])
    assert {:error, %{ready: false}} = Health.readiness()
    assert {:error, %{reason: "crl_worker_unavailable"}} = Health.check_background_jobs()
  end

  test "disabled CRL process is not a healthy required worker" do
    Application.put_env(:secrethub_core, :enabled_features, [:client_auth_pki])
    start_supervised!({ClientAuthCRLRefresher, enabled: false})
    assert {:error, %{reason: "crl_worker_disabled"}} = Health.check_background_jobs()
  end

  test "required CRL worker has a real reconciliation heartbeat and scheduled next check" do
    unseal!()
    Application.put_env(:secrethub_core, :enabled_features, [:static_secrets, :client_auth_pki])
    start_supervised!(ClientAuthCRLRefresher)
    assert {:ok, %{required: true}} = Health.check_background_jobs()
    assert {:ok, %{ready: true}} = Health.readiness()
  end

  test "persisted missing CRL produces an observed worker failure and blocks readiness" do
    unseal!()
    Application.put_env(:secrethub_core, :enabled_features, [:static_secrets, :client_auth_pki])

    Repo.insert!(%SecretHub.Shared.Schemas.ClientAuthAuthority{
      name: "broken-test-authority",
      status: "active"
    })

    start_supervised!(ClientAuthCRLRefresher)
    assert {:error, %{reason: "crl_refresh_failed"}} = Health.check_background_jobs()
    assert {:error, %{ready: false}} = Health.readiness()
  end

  test "successful CRL refresh check followed by failed reread stays unhealthy and retries" do
    unseal!()
    Application.put_env(:secrethub_core, :enabled_features, [:static_secrets, :client_auth_pki])

    {:ok, %{initial_crl: crl, ca_certificate: ca_cert}} =
      SecretHub.Core.PKI.ClientAuth.initialize_authority()

    {:ok, key} = SealState.get_master_key()

    assert match?(
             {:ok, _},
             SecretHub.Shared.Crypto.Encryption.decrypt_from_blob(
               ca_cert.private_key_encrypted,
               key
             )
           )

    crl
    |> Ecto.Changeset.change(
      next_update: DateTime.add(DateTime.utc_now(), 60, :second) |> DateTime.truncate(:second)
    )
    |> Repo.update!()

    repo_pid = Process.whereis(Repo)
    test_pid = self()
    handler = "crl-post-refresh-failure-#{System.unique_integer([:positive])}"

    :ok =
      :telemetry.attach(
        handler,
        [:secret_hub, :core, :repo, :query],
        fn _event, _measurements, metadata, _config ->
          if self() == Process.whereis(ClientAuthCRLRefresher) and
               String.contains?(metadata.query, ~s(FROM "client_auth_authorities")) do
            count = Process.get(:health_test_authority_reads, 0) + 1
            Process.put(:health_test_authority_reads, count)
            # Move the CRL outside the refresh window before the locked preload.
            # The refresh check succeeds with :not_modified, then its reread fails.
            if count == 2 do
              crl
              |> Ecto.Changeset.change(
                next_update:
                  DateTime.add(DateTime.utc_now(), 86_400, :second) |> DateTime.truncate(:second)
              )
              |> Repo.update!()
            end
          end

          if self() == Process.whereis(ClientAuthCRLRefresher) and metadata.query == "commit" do
            :erlang.unregister(Repo)
            send(test_pid, :post_refresh_reread_failed)
          end
        end,
        nil
      )

    try do
      start_supervised!(ClientAuthCRLRefresher)
      assert_receive :post_refresh_reread_failed, 2000
      assert {:error, %{reason: "crl_refresh_failed"}} = Health.check_background_jobs()
      state = :sys.get_state(ClientAuthCRLRefresher)
      assert state.retry_attempt == 1
      assert is_integer(Process.read_timer(state.timer))
    after
      :telemetry.detach(handler)
      unless Process.whereis(Repo), do: :erlang.register(Repo, repo_pid)
    end

    assert Repo.get!(SecretHub.Shared.Schemas.ClientAuthAuthority, crl.authority_id).current_crl_number ==
             1
  end

  test "database failures are bounded and redacted" do
    pid = Process.whereis(Repo)
    :erlang.unregister(Repo)

    try do
      assert {:error, %{reason: "database_unavailable"}} = Health.check_database()
    after
      :erlang.register(Repo, pid)
    end
  end

  test "unresponsive Vault does not crash or indefinitely block health" do
    :sys.suspend(SealState)

    try do
      {elapsed, result} = :timer.tc(&Health.check_vault/0)
      assert {:error, %{reason: "vault_unavailable"}} = result
      assert elapsed < 1_500_000
    after
      :sys.resume(SealState)
    end
  end

  defp unseal! do
    {:ok, shares} = SealState.initialize(3, 2)
    Enum.each(Enum.take(shares, 2), &SealState.unseal/1)
  end

  defp await_loaded(0), do: flunk("Vault load did not complete")

  defp await_loaded(attempts) do
    if SealState.status().state == :loading do
      Process.sleep(5)
      await_loaded(attempts - 1)
    else
      :ok
    end
  end
end
