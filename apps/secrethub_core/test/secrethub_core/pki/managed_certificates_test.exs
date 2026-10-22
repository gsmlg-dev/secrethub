defmodule SecretHub.Core.PKI.ManagedCertificatesTest do
  use ExUnit.Case, async: false
  alias SecretHub.Core.PKI.ACME.Keys
  alias SecretHub.Core.PKI.ACME.Publication
  alias SecretHub.Core.PKI.ManagedCertificates, as: Managed
  alias SecretHub.Core.Repo
  alias SecretHub.Core.RuntimeDatabaseFixture
  alias SecretHub.Core.Secrets
  alias SecretHub.Core.Vault.SealState
  alias SecretHub.Shared.Schemas.AcmeAccount
  alias SecretHub.Shared.Schemas.AcmeOrder
  alias SecretHub.Shared.Schemas.ManagedCertificate
  alias X509.Certificate.Extension
  import SecretHub.Core.VaultTestHelpers

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
    :ok
  end

  test "account keys are encrypted and environments have fixed directory identities" do
    assert {:ok, account} = Managed.create_account(account_attrs())
    assert account.environment == "staging"
    assert account.directory_url == "https://acme-staging-v02.api.letsencrypt.org/directory"
    refute inspect(account) =~ "BEGIN PRIVATE"
    refute account.encrypted_key =~ "BEGIN"
    assert Repo.get!(AcmeAccount, account.id).encrypted_key == account.encrypted_key
    assert {:error, _} = Managed.create_account(Map.put(account_attrs(), "terms_accepted", false))
  end

  test "requests are normalized, durable, idempotent and conflict on changed intent" do
    {:ok, resource} = resource()
    assert resource.identifiers == ["*.example.com", "example.com"]
    assert {:ok, order} = Managed.request_issue(resource.id, "operator-request-1")
    assert {:ok, same} = Managed.request_issue(resource.id, "operator-request-1")
    assert same.id == order.id
    assert order.configuration_revision == 1
    assert order.expected_prior_version_id == nil
    assert Repo.get!(AcmeOrder, order.id).state == "queued"
    assert {:error, :active_order} = Managed.request_issue(resource.id, "different-request")
    assert {:ok, _} = Managed.update_managed(resource.id, %{"enabled" => false})

    assert {:error, :idempotency_conflict} =
             Managed.request_issue(resource.id, "operator-request-1")

    assert Repo.get!(ManagedCertificate, resource.id).configuration_revision == 2
  end

  test "provider credentials remain references, and outstanding work prevents destructive edits" do
    {:ok, resource} = resource()
    [binding | _] = resource.bindings
    {:ok, _} = Managed.request_issue(resource.id, "pending")

    assert {:error, :outstanding_obligations} =
             Managed.update_provider(binding["provider_id"], %{
               "credential_secret_id" => Ecto.UUID.generate()
             })

    assert {:ok, provider} =
             Managed.update_provider(binding["provider_id"], %{"enabled" => false})

    refute provider.enabled
    refute inspect(provider) =~ "scoped-test-token"
  end

  test "cancellation leaves a durable terminal order for independent DNS cleanup" do
    {:ok, resource} = resource()
    {:ok, order} = Managed.request_issue(resource.id, "cancel")
    assert {:ok, cancelled} = Managed.cancel_order(order.id)
    assert cancelled.state == "cancelled"
    assert Repo.get!(ManagedCertificate, resource.id).current_version_id == nil
  end

  test "configuration rejects nested credentials and ambiguous bindings" do
    {:ok, resource} = resource()
    [binding] = resource.bindings

    assert {:error, :invalid_bindings} =
             Managed.update_managed(resource.id, %{"bindings" => [binding, binding]})

    assert {:error, :invalid_bindings} =
             Managed.update_managed(
               resource.id,
               %{"bindings" => [Map.put(binding, "api_token", "must-not-persist")]}
             )

    assert {:error, :invalid_zone} =
             Managed.update_provider(
               binding["provider_id"],
               %{
                 "zones" => [
                   %{
                     "zone_id" => "zone-1",
                     "zone_name" => "example.com",
                     "token" => "must-not-persist"
                   }
                 ]
               }
             )
  end

  test "publication is atomic, idempotent and protects its owned output" do
    {:ok, resource} = resource()
    {order, key, opts} = ready_order(resource, "first")
    assert {:ok, first} = Publication.publish(order.id, order.claim_token, opts)
    assert first.publication_sequence == 1
    assert {:ok, material} = Managed.export_version(first.id)
    assert material["private_key"] == key
    assert material["certificate_version_id"] == first.id
    assert {:ok, same} = Publication.publish(order.id, order.claim_token, opts)
    assert same.id == first.id
    assert Repo.get!(AcmeOrder, order.id).encrypted_pending_key == nil
    assert {:ok, secret} = Secrets.get_secret(first.output_secret_id)
    assert secret.version == 1
    assert secret.engine_type == "static"

    assert {:error, :managed_certificate_output} =
             Secrets.update_secret(secret.id, %{"value" => "wrong"})

    assert {:error, :managed_certificate_output} = Secrets.delete_secret(secret.id)
    assert {:error, _} = Secrets.get_secret_for_entity("untrusted", secret.secret_path)
  end

  test "every publication boundary rolls back material, pointer and audit together" do
    {:ok, resource} = resource()
    {initial, _, opts} = ready_order(resource, "initial")
    {:ok, first} = Publication.publish(initial.id, initial.claim_token, opts)
    {:ok, resource} = Managed.get_managed(resource.id)
    {order, _, opts} = ready_order(resource, "replacement")

    for step <- [:secret_written, :version_written, :pointer_switched, :audit_appended] do
      failing =
        Keyword.put(opts, :publication_checkpoint, fn at ->
          if at == step, do: Repo.rollback({:injected, at})
        end)

      assert {:error, {:injected, ^step}} =
               Publication.publish(order.id, order.claim_token, failing)

      assert Repo.get!(ManagedCertificate, resource.id).current_version_id == first.id
      assert {:ok, %{version: 1}} = Secrets.get_secret(first.output_secret_id)
      assert [_] = Managed.list_versions(resource.id)
    end

    assert {:ok, second} = Publication.publish(order.id, order.claim_token, opts)
    assert second.publication_sequence == 2
  end

  test "two renewals without configuration edits retain matching exact-version keys and history" do
    {:ok, resource} = resource()

    versions =
      Enum.map(1..3, fn sequence ->
        {:ok, current} = Managed.get_managed(resource.id)
        {order, key, opts} = ready_order(current, "generation-#{sequence}")
        {:ok, version} = Publication.publish(order.id, order.claim_token, opts)
        assert version.publication_sequence == sequence
        {version, key}
      end)

    assert Repo.get!(ManagedCertificate, resource.id).configuration_revision == 1

    for {version, key} <- versions do
      assert {:ok, %{"private_key" => ^key, "certificate_version_id" => id}} =
               Managed.export_version(version.id)

      assert id == version.id

      assert {:ok, %{"private_key" => ^key, "certificate_version_id" => ^id}} =
               Secrets.read_exact_material(
                 version.output_secret_id,
                 version.secret_version_number
               )
    end

    [{first, _} | _] = versions
    Secrets.prune_old_versions(first.output_secret_id, keep_versions: 0, keep_days: 0)
    assert {:ok, _} = Managed.export_version(first.id)
  end

  test "stale claims and desired configuration edits cannot publish over the serving version" do
    {:ok, resource} = resource()
    {order, _, opts} = ready_order(resource, "stale")

    assert {:error, :stale_publication} =
             Publication.publish(order.id, Ecto.UUID.generate(), opts)

    assert {:ok, _} = Managed.update_managed(resource.id, %{"key_policy" => "rsa_2048"})
    assert {:error, :stale_publication} = Publication.publish(order.id, order.claim_token, opts)
    assert Repo.get!(ManagedCertificate, resource.id).current_version_id == nil
  end

  test "quarantine gates the resolved generation and advances the normal cache revision" do
    {:ok, resource} = resource()
    {o1, _, opts} = ready_order(resource, "one")
    {:ok, first} = Publication.publish(o1.id, o1.claim_token, opts)
    {:ok, resource} = Managed.get_managed(resource.id)
    {o2, _, opts} = ready_order(resource, "two")
    {:ok, second} = Publication.publish(o2.id, o2.claim_token, opts)
    {:ok, _} = Managed.request_revocation(first.id)
    assert {:error, :certificate_quarantined} = Managed.export_version(first.id)

    assert {:error, :certificate_quarantined} =
             Secrets.read_exact_material(first.output_secret_id, first.secret_version_number)

    assert {:ok, _} = Managed.export_version(second.id)
    assert :ok = Managed.check_delivery(second.output_secret_id)
    {:ok, secret} = Secrets.get_secret(second.output_secret_id)
    before = Repo.get!(SecretHub.Shared.Schemas.SecretPathRevision, secret.secret_path).revision
    {:ok, _} = Managed.request_revocation(second.id)
    assert {:error, :certificate_quarantined} = Managed.check_delivery(secret.id)
    assert {:error, :certificate_quarantined} = Secrets.read_decrypted(secret.secret_path)

    assert Repo.get!(SecretHub.Shared.Schemas.SecretPathRevision, secret.secret_path).revision >
             before
  end

  test "a quarantined current generation does not hide healthy historical material" do
    {:ok, resource} = resource()
    {o1, first_key, opts} = ready_order(resource, "healthy-history")
    {:ok, first} = Publication.publish(o1.id, o1.claim_token, opts)
    {:ok, resource} = Managed.get_managed(resource.id)
    {o2, _, opts} = ready_order(resource, "quarantined-current")
    {:ok, second} = Publication.publish(o2.id, o2.claim_token, opts)
    {:ok, _} = Managed.request_revocation(second.id)

    assert {:ok, %{"private_key" => ^first_key}} =
             Secrets.read_exact_material(first.output_secret_id, first.secret_version_number)

    assert {:error, :certificate_quarantined} =
             Secrets.read_exact_material(second.output_secret_id, second.secret_version_number)
  end

  test "a healthy replacement cannot authorize a quarantined snapshot fetched before publication" do
    {:ok, resource} = resource()
    {o1, _, opts} = ready_order(resource, "quarantined-snapshot")
    {:ok, first} = Publication.publish(o1.id, o1.claim_token, opts)
    {:ok, resource} = Managed.get_managed(resource.id)
    {o2, _, opts} = ready_order(resource, "healthy-replacement")
    {:ok, _} = Managed.request_revocation(first.id)
    {:ok, secret} = Secrets.get_secret(first.output_secret_id)
    reader = self()
    handler = "managed-read-race-#{Ecto.UUID.generate()}"
    marker = {__MODULE__, handler}

    :ok =
      :telemetry.attach(
        handler,
        Repo.config()[:telemetry_prefix] ++ [:query],
        fn _, _, metadata, _ ->
          if self() == reader and metadata[:source] == "secrets" and
               not Process.get(marker, false) do
            Process.put(marker, true)

            send(
              reader,
              {:replacement_published, Publication.publish(o2.id, o2.claim_token, opts)}
            )
          end
        end,
        nil
      )

    result =
      try do
        Secrets.read_decrypted(secret.secret_path)
      after
        :telemetry.detach(handler)
        Process.delete(marker)
      end

    assert_receive {:replacement_published, {:ok, _}}
    assert match?({:error, :certificate_quarantined}, result)
  end

  defp ready_order(resource, request_id) do
    {:ok, order} = Managed.request_issue(resource.id, request_id)
    {:ok, key} = Keys.generate()
    {:ok, encrypted} = Managed.encrypt(key.private_key_pem)
    root_key = X509.PrivateKey.new_ec(:secp256r1)

    root =
      X509.Certificate.self_signed(root_key, "/CN=isolated-publication-root", template: :root_ca)

    leaf_key = X509.PrivateKey.from_pem!(key.private_key_pem)

    cert =
      X509.Certificate.new(X509.PublicKey.derive(leaf_key), "/CN=example.com", root, root_key,
        template: :server,
        extensions: [
          subject_alt_name: Extension.subject_alt_name(resource.identifiers)
        ]
      )

    {:ok, order} =
      Repo.update(
        Ecto.Changeset.change(order,
          encrypted_pending_key: encrypted,
          downloaded_chain: X509.Certificate.to_pem(cert),
          state: "running",
          phase: "publish",
          claim_token: Ecto.UUID.generate(),
          claim_expires_at: DateTime.add(Managed.now(), 300)
        )
      )

    {order, key.private_key_pem,
     [test_mode: true, test_issuance_cacerts: [X509.Certificate.to_der(root)]]}
  end

  defp account_attrs do
    %{
      "name" => "Staging",
      "environment" => "staging",
      "contact" => ["mailto:owner@example.com"],
      "terms_url" => "https://letsencrypt.org/repository/",
      "terms_accepted" => true
    }
  end

  defp resource do
    {:ok, credential} =
      Secrets.create_secret(%{
        "name" => "DNS",
        "secret_path" => "test.dns.token",
        "secret_data" => %{"api_token" => "scoped-test-token"}
      })

    {:ok, provider} =
      Managed.create_provider(%{
        "name" => "Cloudflare",
        "provider" => "cloudflare",
        "credential_secret_id" => credential.id,
        "zones" => [%{"zone_id" => "zone-1", "zone_name" => "example.com"}]
      })

    {:ok, account} = Managed.create_account(account_attrs())

    Managed.create_managed(%{
      "slug" => "example",
      "account_id" => account.id,
      "identifiers" => ["Example.COM.", "*.example.com"],
      "bindings" => [
        %{
          "suffix" => "example.com",
          "provider_id" => provider.id,
          "zone_id" => "zone-1",
          "zone_name" => "example.com"
        }
      ]
    })
  end
end
