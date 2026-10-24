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
  alias SecretHub.Shared.Schemas.AuditLog
  alias SecretHub.Shared.Schemas.ManagedCertificate
  alias SecretHub.Shared.Schemas.DNSProvider
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

  test "credential options expose only usable static secret metadata ordered by path" do
    last = credential("test.z.dns")
    first = credential("test.a.dns")
    dynamic = credential("test.dynamic.dns")
    inactive = credential("test.inactive.dns")
    Repo.update!(Ecto.Changeset.change(dynamic, secret_type: :dynamic, engine_type: "aws"))
    Repo.update!(Ecto.Changeset.change(inactive, status: "error"))

    assert Managed.credential_secret_options() == [
             %{id: first.id, secret_path: first.secret_path},
             %{id: last.id, secret_path: last.secret_path}
           ]
  end

  test "provider secret paths resolve to durable UUID references and replace stale IDs" do
    original = credential("test.original.dns")
    replacement = credential("test.replacement.dns")

    assert {:ok, provider} =
             Managed.create_provider(provider_attrs(original.secret_path))

    assert Repo.get!(DNSProvider, provider.id).credential_secret_id == original.id

    assert {:ok, %{"api_token" => "scoped-test-token"}} =
             Managed.credentials(%{"credential_secret_id" => provider.credential_secret_id})

    assert {:ok, updated} =
             Managed.update_provider(provider.id, %{
               "credential_secret_path" => replacement.secret_path,
               "credential_secret_id" => original.id
             })

    assert updated.credential_secret_id == replacement.id
    assert Repo.get!(DNSProvider, provider.id).credential_secret_id == replacement.id

    assert {:error, :credential_secret_not_found} =
             Managed.update_provider(provider.id, %{
               "credential_secret_path" => "test.missing.dns",
               "credential_secret_id" => original.id
             })

    assert Repo.get!(DNSProvider, provider.id).credential_secret_id == replacement.id
  end

  test "unknown or empty credential paths cannot fall back to submitted UUIDs" do
    secret = credential("test.dns")

    for path <- ["test.missing.dns", "", nil] do
      attrs = Map.put(provider_attrs(path), "credential_secret_id", secret.id)
      assert {:error, reason} = Managed.create_provider(attrs)
      assert reason in [:credential_secret_not_found, :credential_reference_required]
    end

    attrs = provider_attrs(secret.secret_path)

    assert {:ok, provider} =
             Managed.create_provider(
               attrs
               |> Map.delete("credential_secret_path")
               |> Map.put("credential_secret_id", secret.id)
             )

    assert provider.credential_secret_id == secret.id
  end

  test "Route 53 environment credentials clear persisted secret references" do
    secret = credential("test.route53")
    attrs = Map.put(provider_attrs(secret.secret_path), "provider", "route53")
    {:ok, provider} = Managed.create_provider(attrs)

    assert {:ok, updated} =
             Managed.update_provider(provider.id, %{
               "credential_mode" => "aws_environment",
               "credential_secret_path" => "",
               "credential_secret_id" => secret.id
             })

    assert updated.credential_mode == "aws_environment"
    assert Repo.get!(DNSProvider, provider.id).credential_secret_id == nil
  end

  test "zone discovery resolves secret paths without returning plaintext credentials" do
    secret = credential("test.discovery")

    transport = fn :get, url, headers, "", _opts ->
      assert URI.parse(url).host == "api.cloudflare.com"
      assert URI.parse(url).path == "/client/v4/zones"
      assert {"authorization", "Bearer scoped-test-token"} in headers

      {:ok,
       %{
         status: 200,
         headers: %{},
         body:
           JSON.encode!(%{
             "success" => true,
             "result" => [%{"id" => "zone-1", "name" => "example.com", "status" => "active"}],
             "result_info" => %{"total_pages" => 1}
           })
       }}
    end

    assert {:ok, [%{"zone_id" => "zone-1", "zone_name" => "example.com"}]} =
             Managed.discover_provider_zones(provider_attrs(secret.secret_path),
               transport: transport
             )

    audit = Repo.get_by!(AuditLog, event_type: "acme.provider.zones_discovered")
    assert audit.hash_version == 2

    assert audit.event_data == %{
             "resource_id" => secret.id,
             "provider" => "cloudflare",
             "zone_count" => 1
           }

    assert {:error, :credential_secret_not_found} =
             Managed.discover_provider_zones(provider_attrs("test.missing"),
               transport: fn _, _, _, _, _ ->
                 flunk("missing credential must not call provider")
               end
             )

    assert {:error, :zone_discovery_failed} =
             Managed.discover_provider_zones(provider_attrs(secret.secret_path),
               transport: fn _, _, _, _, _ ->
                 {:error, "scoped-test-token private remote error"}
               end
             )
  end

  test "Cloudflare zone discovery accepts a scalar secret from the ordinary Value form" do
    {:ok, secret} =
      Secrets.create_secret(%{
        "name" => "Cloudflare scalar credential",
        "secret_path" => "test.cloudflare.scalar",
        "value" => "fixture-scalar-api-token"
      })

    assert %{id: secret.id, secret_path: secret.secret_path} in Managed.credential_secret_options()

    transport = fn :get, url, headers, "", _opts ->
      assert URI.parse(url).host == "api.cloudflare.com"
      assert URI.parse(url).path == "/client/v4/zones"
      assert {"authorization", "Bearer fixture-scalar-api-token"} in headers

      {:ok,
       %{
         status: 200,
         headers: %{},
         body:
           JSON.encode!(%{
             "success" => true,
             "result" => [%{"id" => "scalar-zone", "name" => "example.com", "status" => "active"}],
             "result_info" => %{"page" => 1, "total_pages" => 1}
           })
       }}
    end

    assert {:ok, [%{"zone_id" => "scalar-zone", "zone_name" => "example.com"}]} =
             Managed.discover_provider_zones(provider_attrs(secret.secret_path),
               transport: transport
             )
  end

  test "Route 53 zone discovery signs requests with decrypted stored credentials" do
    {:ok, secret} =
      Secrets.create_secret(%{
        "name" => "Route 53",
        "secret_path" => "test.route53.discovery",
        "secret_data" => %{
          "access_key_id" => "fixture-access",
          "secret_access_key" => "fixture-secret"
        }
      })

    attrs = Map.put(provider_attrs(secret.secret_path), "provider", "route53")

    transport = fn :get, url, headers, "", _opts ->
      assert URI.parse(url).host == "route53.amazonaws.com"

      assert Enum.any?(headers, fn {key, value} ->
               key == "authorization" and String.contains?(value, "Credential=fixture-access/")
             end)

      {:ok,
       %{
         status: 200,
         headers: %{},
         body:
           "<ListHostedZonesResponse><HostedZones><HostedZone><Id>/hostedzone/Z123</Id><Name>example.com.</Name><Config><PrivateZone>false</PrivateZone></Config></HostedZone></HostedZones><IsTruncated>false</IsTruncated></ListHostedZonesResponse>"
       }}
    end

    assert {:ok, [%{"zone_id" => "Z123", "zone_name" => "example.com"}]} =
             Managed.discover_provider_zones(attrs, transport: transport)
  end

  test "zone discovery obeys sealed Vault and disabled ACME" do
    secret = credential("test.discovery")
    attrs = provider_attrs(secret.secret_path)
    no_transport = fn _, _, _, _, _ -> flunk("discovery must not call provider") end
    stop_supervised!(SealState)
    start_supervised!({SealState, repo: RuntimeDatabaseFixture.VaultRepo}, restart: :temporary)
    await_vault_state(:sealed)
    assert {:error, :sealed} = Managed.discover_provider_zones(attrs, transport: no_transport)

    previous = Application.get_env(:secrethub_core, :acme_enabled)
    Application.put_env(:secrethub_core, :acme_enabled, false)

    on_exit(fn ->
      if is_nil(previous),
        do: Application.delete_env(:secrethub_core, :acme_enabled),
        else: Application.put_env(:secrethub_core, :acme_enabled, previous)
    end)

    assert {:error, :feature_unavailable} =
             Managed.discover_provider_zones(attrs, transport: no_transport)

    assert Managed.credential_secret_options() == []
    assert {:error, :feature_unavailable} = Managed.create_provider(attrs)
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

  test "account terms discovery uses the fixed environment directory and current metadata" do
    current_terms = "https://letsencrypt.org/documents/current-test-agreement.pdf"

    transport = fn :get, url, _headers, "", _opts ->
      assert url == "https://acme-v02.api.letsencrypt.org/directory"
      terms_directory(current_terms, "https://acme-v02.api.letsencrypt.org/")
    end

    assert {:ok, ^current_terms} =
             Managed.discover_account_terms("production", transport: transport)

    assert {:error, :unsupported_environment} =
             Managed.discover_account_terms("https://attacker.example/directory",
               transport: fn _, _, _, _, _ ->
                 flunk("unsupported environments must not be fetched")
               end
             )
  end

  test "account terms discovery fails closed for absent or unsafe metadata and transport errors" do
    for terms <- [nil, "", "http://example.com/terms", "javascript:alert(1)"] do
      assert {:error, :terms_unavailable} =
               Managed.discover_account_terms("staging",
                 transport: fn _, _, _, _, _ -> terms_directory(terms) end
               )
    end

    assert {:error, _} =
             Managed.discover_account_terms("staging",
               transport: fn _, _, _, _, _ -> {:error, :timeout} end
             )
  end

  test "fresh accepted account terms atomically queue registration while availability edits do not" do
    assert {:ok, account} = Managed.create_account(account_attrs())
    Repo.delete_all(Oban.Job)
    terms = "https://letsencrypt.org/documents/current-test-agreement.pdf"

    assert {:ok, updated} =
             Managed.update_account(account.id, %{"terms_url" => terms, "terms_accepted" => true})

    assert updated.terms_url == terms
    assert [%Oban.Job{args: %{"account_id" => id}, state: "available"}] = Repo.all(Oban.Job)
    assert id == account.id
    Repo.delete_all(Oban.Job)
    assert {:ok, _} = Managed.update_account(account.id, %{"enabled" => false})
    assert Repo.all(Oban.Job) == []
    assert {:ok, _} = Managed.update_account(account.id, %{"enabled" => true})
    assert Repo.all(Oban.Job) == []
  end

  test "confirmed account terms make an existing registration retry due without duplicating jobs" do
    assert {:ok, account} = Managed.create_account(account_attrs())
    [job] = Repo.all(Oban.Job)

    for state <- ["scheduled", "retryable"] do
      Repo.update!(
        Ecto.Changeset.change(job,
          state: state,
          inserted_at: DateTime.add(DateTime.utc_now(), -3600),
          scheduled_at: DateTime.add(DateTime.utc_now(), 3600)
        )
      )

      assert {:ok, _} =
               Managed.update_account(account.id, %{
                 "terms_url" => "https://letsencrypt.org/documents/current-test-agreement.pdf",
                 "terms_accepted" => true
               })

      assert [%Oban.Job{id: id, state: "available", scheduled_at: scheduled_at}] =
               Repo.all(Oban.Job)

      assert id == job.id
      assert DateTime.compare(scheduled_at, DateTime.utc_now()) != :gt
    end

    for state <- ["available", "executing"] do
      Repo.update!(
        Ecto.Changeset.change(job,
          state: state,
          inserted_at: DateTime.add(DateTime.utc_now(), -3600)
        )
      )

      assert {:ok, _} = Managed.register_account(account.id)
      assert [%Oban.Job{id: id, state: ^state}] = Repo.all(Oban.Job)
      assert id == job.id
    end
  end

  test "name-only creation preserves a domain-like name and generates a safe internal slug" do
    {:ok, legacy} = resource()

    assert {:ok, certificate} =
             Managed.create_managed(Map.put(managed_attrs(legacy), "name", "  gsmlg.net  "))

    assert certificate.name == "gsmlg.net"
    assert certificate.slug =~ ~r/\Acert-[a-z0-9]+(?:-[a-z0-9]+)*\z/
    assert String.length(certificate.slug) <= 80
    refute certificate.slug == legacy.slug
    assert {:ok, %{name: "gsmlg.net", slug: slug}} = Managed.get_managed(certificate.id)
    assert slug == certificate.slug
  end

  test "human certificate names preserve spaces and Unicode with distinct generated slugs" do
    {:ok, legacy} = resource()
    attrs = managed_attrs(legacy)

    assert {:ok, first} = Managed.create_managed(Map.put(attrs, "name", "  Production API  "))
    assert {:ok, second} = Managed.create_managed(Map.put(attrs, "name", "  生产证书  "))
    assert first.name == "Production API"
    assert second.name == "生产证书"
    refute first.slug == second.slug
  end

  test "display name edits preserve internal slug and ACME account" do
    {:ok, legacy} = resource()

    {:ok, certificate} =
      Managed.create_managed(Map.put(managed_attrs(legacy), "name", "gsmlg.net"))

    assert {:ok, renamed} =
             Managed.update_managed(certificate.id, %{
               "name" => "  gsmlg.net production  ",
               "slug" => "replacement-slug",
               "account_id" => Ecto.UUID.generate()
             })

    assert renamed.name == "gsmlg.net production"
    assert renamed.slug == certificate.slug
    assert renamed.account_id == certificate.account_id
    assert {:ok, unchanged} = Managed.update_managed(certificate.id, %{"enabled" => false})
    assert unchanged.name == renamed.name
    assert unchanged.slug == certificate.slug
  end

  test "explicit blank certificate names return name field errors on create and update" do
    {:ok, legacy} = resource()

    for name <- ["", "   ", nil] do
      assert {:error, %Ecto.Changeset{} = changeset} =
               Managed.create_managed(Map.put(managed_attrs(legacy), "name", name))

      assert {"can't be blank", _} = Keyword.fetch!(changeset.errors, :name)
      refute Keyword.has_key?(changeset.errors, :slug)

      assert {:error, %Ecto.Changeset{} = changeset} =
               Managed.update_managed(legacy.id, %{"name" => name})

      assert {"can't be blank", _} = Keyword.fetch!(changeset.errors, :name)
    end
  end

  test "duplicate and overlong certificate names return name field errors" do
    {:ok, legacy} = resource()
    attrs = managed_attrs(legacy)
    {:ok, _} = Managed.create_managed(Map.put(attrs, "name", "gsmlg.net"))
    {:ok, second} = Managed.create_managed(Map.put(attrs, "name", "gsmlg.org"))

    assert {:error, %Ecto.Changeset{} = duplicate} =
             Managed.create_managed(Map.put(attrs, "name", "  gsmlg.net  "))

    assert {"has already been taken", _} = Keyword.fetch!(duplicate.errors, :name)

    assert {:error, %Ecto.Changeset{} = duplicate} =
             Managed.update_managed(second.id, %{"name" => "gsmlg.net"})

    assert {"has already been taken", _} = Keyword.fetch!(duplicate.errors, :name)

    assert {:error, %Ecto.Changeset{} = overlong} =
             Managed.create_managed(Map.put(attrs, "name", String.duplicate("a", 256)))

    assert {"should be at most %{count} character(s)", _} =
             Keyword.fetch!(overlong.errors, :name)
  end

  test "legacy slug-only certificates retain nil names and their original slug during edits" do
    assert {:ok, legacy} = resource()
    assert legacy.name == nil
    assert legacy.slug == "example"
    assert {:ok, updated} = Managed.update_managed(legacy.id, %{"enabled" => false})
    assert updated.name == nil
    assert updated.slug == "example"

    assert {:ok, named} = Managed.update_managed(legacy.id, %{"name" => "gsmlg.net"})
    assert named.name == "gsmlg.net"
    assert named.slug == "example"

    assert {:error, %Ecto.Changeset{} = changeset} =
             Managed.create_managed(
               Map.merge(managed_attrs(legacy), %{"name" => "Safe name", "slug" => "gsmlg.net"})
             )

    assert {"has invalid format", _} = Keyword.fetch!(changeset.errors, :slug)
  end

  test "Unicode name length matches the database codepoint limit without raising" do
    {:ok, legacy} = resource()
    attrs = managed_attrs(legacy)
    boundary_name = String.duplicate("e\u0301", 127) <> "e"
    overlong_name = String.duplicate("e\u0301", 128)

    assert {:ok, certificate} = Managed.create_managed(Map.put(attrs, "name", boundary_name))
    assert certificate.name == boundary_name

    assert {:error, %Ecto.Changeset{} = changeset} =
             Managed.create_managed(Map.put(attrs, "name", overlong_name))

    assert {"should be at most %{count} character(s)", _} =
             Keyword.fetch!(changeset.errors, :name)

    assert {:error, %Ecto.Changeset{} = changeset} =
             Managed.update_managed(certificate.id, %{"name" => overlong_name})

    assert {"should be at most %{count} character(s)", _} =
             Keyword.fetch!(changeset.errors, :name)
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

  defp terms_directory(terms, base \\ "https://acme-staging-v02.api.letsencrypt.org/") do
    body =
      Map.new(~w(newNonce newAccount newOrder revokeCert), &{&1, base <> &1})
      |> Map.put("meta", %{"termsOfService" => terms})

    {:ok, %{status: 200, headers: %{}, body: Jason.encode!(body)}}
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

  defp credential(path) do
    {:ok, secret} =
      Secrets.create_secret(%{
        "name" => "DNS credential",
        "secret_path" => path,
        "secret_data" => %{"api_token" => "scoped-test-token"}
      })

    secret
  end

  defp provider_attrs(path) do
    %{
      "name" => "Cloudflare",
      "provider" => "cloudflare",
      "credential_mode" => "secret",
      "credential_secret_path" => path,
      "zones" => [%{"zone_id" => "zone-1", "zone_name" => "example.com"}]
    }
  end

  defp managed_attrs(resource) do
    %{
      "account_id" => resource.account_id,
      "identifiers" => resource.identifiers,
      "bindings" => resource.bindings,
      "key_policy" => resource.key_policy
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
