defmodule SecretHub.Core.PKI.ACME.JobRecoveryTest do
  use ExUnit.Case, async: false
  import Ecto.Query
  import SecretHub.Core.VaultTestHelpers
  alias Ecto.Changeset
  alias SecretHub.Core.PKI.ACME.{Keys, Reconciler, Revocation, Worker}
  alias SecretHub.Core.PKI.ManagedCertificates, as: Managed
  alias SecretHub.Core.{Repo, RuntimeDatabaseFixture}
  alias SecretHub.Core.Vault.SealState

  alias SecretHub.Shared.Schemas.{
    AcmeAccount,
    AcmeOrder,
    DNSProvider,
    ManagedCertificate,
    ManagedCertificateVersion,
    Secret
  }

  setup_all do
    RuntimeDatabaseFixture.prepare_template()
  end

  setup tags do
    if pid = Process.whereis(SealState), do: GenServer.stop(pid, :normal)
    RuntimeDatabaseFixture.setup(tags)

    {:ok, oban} =
      Oban.start_link(
        name: SecretHub.Core.Oban,
        repo: Repo,
        get_dynamic_repo: fn -> :runtime_authorization_fixture end,
        testing: :disabled,
        queues: false,
        plugins: false
      )

    Process.unlink(oban)
    on_exit(fn -> if Process.alive?(oban), do: Supervisor.stop(oban) end)
    start_supervised!({SealState, repo: RuntimeDatabaseFixture.VaultRepo}, restart: :temporary)
    await_vault_state(:not_initialized)
    {:ok, [a, b | _]} = SealState.initialize(3, 2)
    {:ok, _} = SealState.unseal(a)
    {:ok, _} = SealState.unseal(b)
    {:ok, key} = Keys.generate()
    {:ok, encrypted} = Managed.encrypt(key.private_key_pem)

    account =
      Repo.insert!(%AcmeAccount{
        name: "fixture",
        environment: "staging",
        directory_url: "https://acme-staging-v02.api.letsencrypt.org/directory",
        terms_url: "https://ca.test/terms",
        terms_accepted_at: Managed.now(),
        encrypted_key: encrypted,
        status: "valid",
        account_url: "https://ca.test/account"
      })

    secret =
      Repo.insert!(%Secret{
        name: "DNS",
        secret_path: "test.jobs.dns",
        secret_type: :static,
        encrypted_data: <<0>>
      })

    provider =
      Repo.insert!(%DNSProvider{
        name: "fixture",
        provider: "cloudflare",
        credential_secret_id: secret.id,
        zones: [%{"zone_id" => "zone", "zone_name" => "example.com"}]
      })

    previous = Application.get_env(:secrethub_core, :acme_adapter_options)

    on_exit(fn ->
      if previous,
        do: Application.put_env(:secrethub_core, :acme_adapter_options, previous),
        else: Application.delete_env(:secrethub_core, :acme_adapter_options)
    end)

    %{account: account, provider: provider, secret: secret}
  end

  test "future schedules do not starve due resources beyond the first batch", c do
    future = DateTime.add(Managed.now(), 86_400)
    for _ <- 1..100, do: material(c, future, future)
    {renewal, _} = material(c, DateTime.add(Managed.now(), -1), future)
    {_, ari} = material(c, future, DateTime.add(Managed.now(), -1))
    assert :ok = Reconciler.perform(nil)

    assert Repo.exists?(
             from(o in AcmeOrder,
               where:
                 o.managed_certificate_id == ^renewal.id and
                   o.state == "queued"
             )
           )

    assert Repo.exists?(
             from(j in Oban.Job,
               where: fragment("?->>'renewal_info_id'", j.args) == ^ari.id
             )
           )
  end

  test "a stale failed revocation cannot overwrite concurrent confirmation", c do
    {_, version} = material(c, Managed.now(), Managed.now())

    version =
      Repo.update!(
        Changeset.change(version,
          revocation_state: "pending",
          quarantined_at: Managed.now()
        )
      )

    transport = fn _, _, _, _, _ ->
      current = Repo.get!(ManagedCertificateVersion, version.id)

      Repo.update!(
        Changeset.change(current,
          revocation_state: "confirmed",
          revocation_error: %{},
          revocation_next_attempt_at: nil
        )
      )

      {:error, :timeout}
    end

    assert :ok = Revocation.run(version.id, transport: transport)
    current = Repo.get!(ManagedCertificateVersion, version.id)
    assert current.revocation_state == "confirmed"
    assert current.revocation_error == %{}
    assert current.revocation_next_attempt_at == nil
  end

  @tag :eligibility
  test "disabled accounts do not occupy the renewal reconciliation batch", c do
    healthy =
      Repo.insert!(%{
        c.account
        | id: Ecto.UUID.generate(),
          account_url: "https://ca.test/healthy"
      })

    Repo.update!(Changeset.change(c.account, enabled: false))
    future = DateTime.add(Managed.now(), 86_400)
    for _ <- 1..100, do: material(c, future, Managed.now())
    due = for _ <- 1..100, do: material(%{c | account: healthy}, future, Managed.now())

    assert :ok = Reconciler.perform(nil)
    assert Enum.count(due, fn {_, version} -> renewal_info_enqueued?(version.id) end) == 100
  end

  @tag :eligibility
  test "disabled DNS providers do not occupy the renewal reconciliation batch", c do
    healthy = Repo.insert!(%{c.provider | id: Ecto.UUID.generate()})
    Repo.update!(Changeset.change(c.provider, enabled: false))
    future = DateTime.add(Managed.now(), 86_400)
    for _ <- 1..100, do: material(c, future, Managed.now())
    due = for _ <- 1..100, do: material(%{c | provider: healthy}, future, Managed.now())

    assert :ok = Reconciler.perform(nil)
    assert Enum.count(due, fn {_, version} -> renewal_info_enqueued?(version.id) end) == 100
  end

  @tag :eligibility
  test "unavailable ARI does not mask healthy work or prevent due replacement", c do
    future = DateTime.add(Managed.now(), 86_400)
    expired = [not_after: DateTime.add(Managed.now(), -1)]
    quarantined = [quarantined_at: Managed.now()]

    for attrs <- [expired, quarantined], _ <- 1..50, do: material(c, future, Managed.now(), attrs)

    replacements =
      for attrs <- [expired, quarantined] do
        {resource, version} = material(c, Managed.now(), Managed.now(), attrs)
        {resource.id, version.id}
      end

    {_, healthy} = material(c, future, Managed.now())
    assert :ok = Reconciler.perform(nil)
    assert renewal_info_enqueued?(healthy.id)

    for {resource_id, version_id} <- replacements do
      refute renewal_info_enqueued?(version_id)

      assert Repo.exists?(
               from(o in AcmeOrder,
                 where: o.managed_certificate_id == ^resource_id and o.state == "queued"
               )
             )
    end
  end

  test "account worker persists sanitized registration failures", c do
    account = Repo.update!(Changeset.change(c.account, status: "pending", account_url: nil))

    Application.put_env(:secrethub_core, :acme_adapter_options,
      transport: fn _, _, _, _, _ -> directory("https://ca.test/new-terms") end
    )

    assert {:error, %{"code" => "terms_changed"}} =
             Worker.perform(%Oban.Job{args: %{"account_id" => account.id}})

    assert Repo.get!(AcmeAccount, account.id).last_error == %{"code" => "terms_changed"}
  end

  test "account worker exposes an unavailable Vault without remote requests", c do
    account = Repo.update!(Changeset.change(c.account, status: "pending", account_url: nil))
    stop_supervised!(SealState)

    Application.put_env(:secrethub_core, :acme_adapter_options,
      transport: fn _, _, _, _, _ -> flunk("unavailable Vault must prevent registration HTTP") end
    )

    assert {:error, %{"code" => "vault_unavailable"}} =
             Worker.perform(%Oban.Job{args: %{"account_id" => account.id}})

    assert Repo.get!(AcmeAccount, account.id).last_error == %{"code" => "vault_unavailable"}
  end

  test "a failed registration worker preserves concurrent valid remote success", c do
    account = Repo.update!(Changeset.change(c.account, status: "pending", account_url: nil))

    transport = fn _, _, _, _, _ ->
      Repo.update!(
        Changeset.change(account,
          status: "valid",
          account_url: "https://ca.test/recovered",
          last_error: %{}
        )
      )

      {:error, :timeout}
    end

    Application.put_env(:secrethub_core, :acme_adapter_options, transport: transport)
    assert {:error, _} = Worker.perform(%Oban.Job{args: %{"account_id" => account.id}})
    current = Repo.get!(AcmeAccount, account.id)
    assert current.status == "valid"
    assert current.account_url == "https://ca.test/recovered"
    assert current.last_error == %{}
  end

  defp directory(terms) do
    body =
      Map.new(
        ~w(newNonce newAccount newOrder revokeCert),
        &{&1, "https://acme-staging-v02.api.letsencrypt.org/" <> &1}
      )
      |> Map.put("meta", %{"termsOfService" => terms})

    {:ok, %{status: 200, headers: %{}, body: JSON.encode!(body)}}
  end

  defp renewal_info_enqueued?(id) do
    Repo.exists?(from(j in Oban.Job, where: fragment("?->>'renewal_info_id'", j.args) == ^id))
  end

  defp material(c, renewal_due, ari_due, version_attrs \\ []) do
    binding = %{"provider_id" => c.provider.id, "zone_id" => "zone", "zone_name" => "example.com"}

    resource =
      Repo.insert!(%ManagedCertificate{
        slug: "jobs-#{System.unique_integer([:positive])}",
        account_id: c.account.id,
        identifiers: ["example.com"],
        bindings: [binding],
        next_renewal_at: renewal_due
      })

    order =
      Repo.insert!(%AcmeOrder{
        managed_certificate_id: resource.id,
        request_id: Ecto.UUID.generate(),
        request_digest: "fixture",
        configuration_revision: 1,
        state: "published",
        phase: "published",
        identifiers: ["example.com"],
        bindings: [binding],
        account_snapshot: %{"id" => c.account.id, "environment" => "staging"},
        deadline_at: DateTime.add(Managed.now(), 86_400)
      })

    version =
      %ManagedCertificateVersion{
        managed_certificate_id: resource.id,
        order_id: order.id,
        publication_sequence: 1,
        environment: "staging",
        fingerprint: Ecto.UUID.generate(),
        certificate_pem: "fixture",
        fullchain_pem: "fixture",
        identifiers: ["example.com"],
        not_before: DateTime.add(Managed.now(), -86_400),
        not_after: DateTime.add(Managed.now(), 172_800),
        key_policy: "ec_p256",
        output_secret_id: c.secret.id,
        secret_version_number: System.unique_integer([:positive]),
        ari_refresh_at: ari_due,
        renewal_due_at: renewal_due
      }
      |> struct(version_attrs)
      |> Repo.insert!()

    resource = Repo.update!(Changeset.change(resource, current_version_id: version.id))
    {resource, version}
  end
end
