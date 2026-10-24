defmodule SecretHub.Core.PKI.ACME.WorkflowTest do
  use ExUnit.Case, async: false
  alias Ecto.Changeset
  alias SecretHub.Core.PKI.ACME.Client
  alias SecretHub.Core.PKI.ACME.DNSOperations
  alias SecretHub.Core.PKI.ACME.Reconciler
  alias SecretHub.Core.PKI.ACME.RenewalScheduler
  alias SecretHub.Core.PKI.ACME.Revocation
  alias SecretHub.Core.PKI.ACME.Workflow
  alias SecretHub.Core.PKI.HTTP
  alias SecretHub.Core.PKI.ManagedCertificates
  alias SecretHub.Core.Repo
  alias SecretHub.Core.RuntimeDatabaseFixture
  alias SecretHub.Core.Secrets
  alias SecretHub.Core.Vault.SealState
  alias SecretHub.Shared.Schemas.AcmeAccount
  alias SecretHub.Shared.Schemas.AcmeOrder
  alias SecretHub.Shared.Schemas.DNSChallengeOperation
  alias SecretHub.Shared.Schemas.ManagedCertificate
  alias X509.Certificate.Extension
  import Ecto.Query
  import SecretHub.Core.VaultTestHelpers

  @base "https://localhost:24444"
  @names ["*.example.com", "example.com"]
  @moduletag timeout: 120_000

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
    root_key = X509.PrivateKey.new_ec(:secp256r1)
    root = X509.Certificate.self_signed(root_key, "/CN=workflow-test-root", template: :root_ca)
    ari_start = DateTime.add(ManagedCertificates.now(), 86_400)

    {:ok, remote} =
      Agent.start_link(fn ->
        %{
          records: %{},
          sequence: 0,
          acked: MapSet.new(),
          certificate: nil,
          orders: 0,
          finalizations: 0,
          ari_window: %{
            "start" => DateTime.to_iso8601(ari_start),
            "end" => DateTime.to_iso8601(DateTime.add(ari_start, 86_400))
          },
          revoked: false
        }
      end)

    opts = [
      test_mode: true,
      test_issuance_cacerts: [X509.Certificate.to_der(root)],
      resolver: fn _, :cname -> {:ok, []} end,
      transport: fixture_transport(remote, root, root_key),
      authoritative_resolver: fn _ ->
        {:ok,
         [
           %{
             server: "fixture",
             authoritative: true,
             values:
               Agent.get(remote, &Enum.map(Map.values(&1.records), fn r -> r["content"] end))
           }
         ]}
      end
    ]

    {:ok, secret} =
      Secrets.create_secret(%{
        "name" => "DNS",
        "secret_path" => "test.workflow.dns",
        "secret_data" => %{"api_token" => "fixture-token"}
      })

    {:ok, provider} =
      ManagedCertificates.create_provider(%{
        "name" => "Cloudflare",
        "provider" => "cloudflare",
        "credential_secret_id" => secret.id,
        "zones" => [%{"zone_id" => "zone-1", "zone_name" => "example.com"}]
      })

    {:ok, account} =
      ManagedCertificates.create_account(%{
        "name" => "Staging",
        "environment" => "staging",
        "terms_accepted" => true,
        "terms_url" => "https://example.test/terms"
      })

    Repo.update!(Changeset.change(account, directory_url: @base <> "/dir"))

    {:ok, resource} =
      ManagedCertificates.create_managed(%{
        "slug" => "workflow",
        "account_id" => account.id,
        "identifiers" => @names,
        "bindings" => [
          %{"provider_id" => provider.id, "zone_id" => "zone-1", "zone_name" => "example.com"}
        ]
      })

    %{resource: resource, account: account, remote: remote, opts: opts}
  end

  test "durable workflow survives effect boundaries with one key, order and publication", c do
    {:ok, order} = ManagedCertificates.request_issue(c.resource.id, "crash-recovery")

    for checkpoint <- [:acknowledged, :finalized, :downloaded, :before_publication] do
      hook = fn phase -> if phase == checkpoint, do: raise("interrupted #{phase}") end

      assert_raise RuntimeError, "interrupted #{checkpoint}", fn ->
        drive(order.id, Keyword.put(c.opts, :workflow_checkpoint, hook))
      end

      current = Repo.get!(AcmeOrder, order.id)
      assert is_binary(current.encrypted_pending_key)
      assert current.csr_digest == Base.encode16(:crypto.hash(:sha256, current.csr), case: :lower)
      assert current.claim_token == nil
    end

    drive(order.id, c.opts)
    assert Repo.get!(AcmeOrder, order.id).state == "published"

    assert [%{publication_sequence: 1} = version] =
             ManagedCertificates.list_versions(c.resource.id)

    assert {:ok, material} = ManagedCertificates.export_version(version.id)
    assert material["identifiers"] == @names
    assert c.remote |> Agent.get(& &1.orders) == 1
    assert c.remote |> Agent.get(& &1.finalizations) == 1
    cleanup(order.id, c.opts)
    assert Agent.get(c.remote, & &1.records) == %{}
    assert :ok = Workflow.step(order.id, c.opts)
  end

  test "lost order-create response is visible and never guessed or repeated", c do
    {:ok, order} = ManagedCertificates.request_issue(c.resource.id, "uncertain")

    broken = fn method, url, headers, body, opts ->
      response = c.opts[:transport].(method, url, headers, body, opts)
      if String.ends_with?(url, "/new-order"), do: {:error, :timeout}, else: response
    end

    drive_until(order.id, "order", c.opts)
    assert {:snooze, _} = Workflow.step(order.id, Keyword.put(c.opts, :transport, broken))
    due_now(order.id)
    Workflow.step(order.id, c.opts)

    assert %{state: "failed", last_error: %{"code" => "remote_order_outcome_unknown"}} =
             Repo.get!(AcmeOrder, order.id)

    assert Agent.get(c.remote, & &1.orders) == 1
    assert :ok = Workflow.step(order.id, c.opts)
    assert {:ok, _} = ManagedCertificates.request_issue(c.resource.id, "explicit-replacement")
  end

  test "pending authorization with a processing challenge is polled without another acknowledgment",
       c do
    {:ok, effects} = Agent.start_link(fn -> %{acks: %{}, processing: MapSet.new()} end)

    transport = fn method, url, headers, body, opts ->
      result = c.opts[:transport].(method, url, headers, body, opts)

      case URI.parse(url).path do
        "/challenge/" <> id ->
          count =
            Agent.get_and_update(effects, fn s ->
              next = Map.update(s.acks, id, 1, &(&1 + 1))
              {next[id], %{s | acks: next}}
            end)

          assert count == 1, "challenge was acknowledged while already processing"
          result

        "/auth/" <> id ->
          pending =
            Agent.get_and_update(effects, fn s ->
              first = Map.has_key?(s.acks, id) and not MapSet.member?(s.processing, id)
              {first, if(first, do: %{s | processing: MapSet.put(s.processing, id)}, else: s)}
            end)

          if pending do
            {:ok, response} = result
            json = JSON.decode!(response.body)
            challenges = Enum.map(json["challenges"], &Map.put(&1, "status", "processing"))
            response(Map.merge(json, %{"status" => "pending", "challenges" => challenges}))
          else
            result
          end

        _ ->
          result
      end
    end

    {:ok, order} = ManagedCertificates.request_issue(c.resource.id, "challenge-poll")
    drive(order.id, Keyword.put(c.opts, :transport, transport))
    assert Agent.get(effects, & &1.acks) == %{"1" => 1, "2" => 1}
  end

  test "a known remote order receipt is retained when cancellation races its response", c do
    {:ok, order} = ManagedCertificates.request_issue(c.resource.id, "cancel-response")
    drive_until(order.id, "order", c.opts)

    racing = fn method, url, headers, body, opts ->
      response = c.opts[:transport].(method, url, headers, body, opts)
      if String.ends_with?(url, "/new-order"), do: ManagedCertificates.cancel_order(order.id)
      response
    end

    Workflow.step(order.id, Keyword.put(c.opts, :transport, racing))
    current = Repo.get!(AcmeOrder, order.id)
    assert current.state == "cancelled"
    assert current.remote_url == @base <> "/order/1"
    assert current.finalize_url == @base <> "/finalize"
    assert current.claim_token == nil
  end

  test "bounded badNonce exhaustion defers authorization polling without abandoning the order",
       c do
    {:ok, order} = ManagedCertificates.request_issue(c.resource.id, "bad-nonce-recovery")
    drive_until(order.id, "challenges", c.opts)
    due_now(order.id)
    assert {:snooze, _} = Workflow.step(order.id, c.opts)

    bad_nonce = fn method, url, headers, body, opts ->
      if String.contains?(URI.parse(url).path, "/auth/") do
        {:ok, response} = response(%{"type" => "urn:ietf:params:acme:error:badNonce"})
        {:ok, %{response | status: 400}}
      else
        c.opts[:transport].(method, url, headers, body, opts)
      end
    end

    due_now(order.id)
    assert {:snooze, _} = Workflow.step(order.id, Keyword.put(c.opts, :transport, bad_nonce))
    refute Repo.get!(AcmeOrder, order.id).state == "failed"

    assert Repo.get!(AcmeOrder, order.id).last_error["type"] ==
             "urn:ietf:params:acme:error:badNonce"

    drive(order.id, c.opts)
  end

  test "explicit badNonce rejection of newOrder permits a later bounded retry", c do
    {:ok, order} = ManagedCertificates.request_issue(c.resource.id, "rejected-new-order")
    drive_until(order.id, "order", c.opts)

    transport = fn method, url, headers, body, opts ->
      if String.ends_with?(url, "/new-order") do
        {:ok, response} = response(%{"type" => "urn:ietf:params:acme:error:badNonce"})
        {:ok, %{response | status: 400}}
      else
        c.opts[:transport].(method, url, headers, body, opts)
      end
    end

    due_now(order.id)
    assert {:snooze, _} = Workflow.step(order.id, Keyword.put(c.opts, :transport, transport))
    assert Repo.get!(AcmeOrder, order.id).remote_started_at == nil
    drive(order.id, c.opts)
    assert Agent.get(c.remote, & &1.orders) == 1
  end

  test "acknowledgment intent recovers when the first request never reaches the CA", c do
    {:ok, lost} = Agent.start_link(fn -> false end)

    transport = fn method, url, headers, body, opts ->
      drop =
        String.contains?(URI.parse(url).path, "/challenge/") and
          Agent.get_and_update(lost, fn dropped -> {not dropped, true} end)

      if drop, do: {:error, :timeout}, else: c.opts[:transport].(method, url, headers, body, opts)
    end

    {:ok, order} = ManagedCertificates.request_issue(c.resource.id, "lost-acknowledgment")
    drive(order.id, Keyword.put(c.opts, :transport, transport))
    assert Agent.get(lost, & &1)
    assert Repo.get!(AcmeOrder, order.id).state == "published"
  end

  test "renewal failure retains serving material, backs off and is reconciled durably", c do
    {:ok, first_order} = ManagedCertificates.request_issue(c.resource.id, "first")
    drive(first_order.id, c.opts)
    [version] = ManagedCertificates.list_versions(c.resource.id)
    {:ok, resource} = ManagedCertificates.get_managed(c.resource.id)
    {:ok, replacement} = ManagedCertificates.request_issue(resource.id, "renewal-failure")
    drive_until(replacement.id, "publish", c.opts)

    Repo.update!(
      Changeset.change(Repo.get!(AcmeOrder, replacement.id), downloaded_chain: "invalid")
    )

    assert :ok = Workflow.step(replacement.id, c.opts)
    assert Repo.get!(AcmeOrder, replacement.id).state == "failed"
    assert {:ok, _} = ManagedCertificates.export_version(version.id)
    resource = Repo.get!(ManagedCertificate, resource.id)
    assert resource.current_version_id == version.id
    assert DateTime.compare(resource.next_renewal_at, ManagedCertificates.now()) == :gt
    assert resource.last_error != %{}
    assert {:ok, _} = RenewalScheduler.refresh(version, c.opts)

    assert DateTime.compare(
             Repo.get!(ManagedCertificate, resource.id).next_renewal_at,
             resource.next_renewal_at
           ) != :lt

    Repo.update!(
      Changeset.change(resource, next_renewal_at: DateTime.add(ManagedCertificates.now(), -1))
    )

    assert :ok = Reconciler.perform(nil)

    assert Enum.any?(
             ManagedCertificates.list_orders(resource.id),
             &String.starts_with?(&1.request_id, "renewal:")
           )
  end

  test "ARI refresh persists stable windows and failed revocation retains quarantine", c do
    {:ok, order} = ManagedCertificates.request_issue(c.resource.id, "ari-revoke")
    drive(order.id, c.opts)
    [version] = ManagedCertificates.list_versions(c.resource.id)
    assert {:ok, _} = RenewalScheduler.refresh(version, c.opts)
    {:ok, current} = ManagedCertificates.get_version(version.id)
    assert current.ari["start"]
    assert {:ok, _} = RenewalScheduler.refresh(current, c.opts)
    assert {:ok, %{renewal_due_at: due}} = ManagedCertificates.get_version(version.id)
    assert due == current.renewal_due_at
    {:ok, _} = ManagedCertificates.request_revocation(version.id)
    failing = Keyword.put(c.opts, :transport, fn _, _, _, _, _ -> {:error, :timeout} end)
    assert {:error, _} = Revocation.run(version.id, failing)
    assert {:error, :certificate_quarantined} = ManagedCertificates.export_version(version.id)
    assert {:ok, %{revocation_state: "failed"}} = ManagedCertificates.get_version(version.id)
    assert :ok = Revocation.run(version.id, c.opts)
    assert {:ok, %{revocation_state: "confirmed"}} = ManagedCertificates.get_version(version.id)
    assert {:error, :certificate_quarantined} = ManagedCertificates.export_version(version.id)
  end

  @tag :pebble
  @tag timeout: 300_000
  @tag skip: is_nil(System.get_env("SECRETHUB_PEBBLE_DIRECTORY"))
  test "real Pebble drives persisted orders, two replacements, ARI and remote revocation", c do
    [{:Certificate, tls_root, _}] =
      :public_key.pem_decode(File.read!(System.fetch_env!("SECRETHUB_PEBBLE_TLS_CERT")))

    tls_opts = [test_mode: true, test_cacerts: [tls_root]]

    {:ok, %{body: root_pem}} =
      HTTP.request(
        :get,
        System.fetch_env!("SECRETHUB_PEBBLE_MANAGEMENT") <> "/roots/0",
        [],
        "",
        tls_opts
      )

    [{:Certificate, root, _}] = :public_key.pem_decode(root_pem)
    account = Repo.get!(AcmeAccount, c.account.id)

    Repo.update!(
      Changeset.change(account, directory_url: System.fetch_env!("SECRETHUB_PEBBLE_DIRECTORY"))
    )

    opts =
      c.opts
      |> Keyword.merge(tls_opts)
      |> Keyword.put(:test_issuance_cacerts, [root])
      |> Keyword.put(:transport, pebble_transport(c.remote))
      |> Keyword.put(:authoritative_resolver, &pebble_txt/1)

    {:ok, directory} = Client.directory(System.fetch_env!("SECRETHUB_PEBBLE_DIRECTORY"), opts)

    {:ok, _} =
      ManagedCertificates.update_account(account.id, %{
        "terms_accepted" => true,
        "terms_url" => get_in(directory, ["meta", "termsOfService"])
      })

    versions =
      for sequence <- 1..3 do
        {:ok, order} = ManagedCertificates.request_issue(c.resource.id, "pebble-#{sequence}")
        drive(order.id, opts, 300)
        assert Repo.get!(AcmeOrder, order.id).state == "published"
        cleanup(order.id, opts)
        [version | _] = ManagedCertificates.list_versions(c.resource.id)
        assert version.publication_sequence == sequence
        assert {:ok, _} = RenewalScheduler.refresh(version, opts)
        version
      end

    [latest | _] = Enum.reverse(versions)
    {:ok, _} = ManagedCertificates.request_revocation(latest.id)
    assert :ok = Revocation.run(latest.id, opts)
    assert {:ok, %{revocation_state: "confirmed"}} = ManagedCertificates.get_version(latest.id)
    assert Agent.get(c.remote, & &1.records) == %{}

    IO.puts(
      "Durable Pebble: three publications, two renewals, ARI, exact material and revocation PASS"
    )
  end

  defp drive(id, opts, attempts \\ 100)

  defp drive(id, _, 0) do
    order = Repo.get!(AcmeOrder, id)

    ops =
      Repo.all(
        from(d in DNSChallengeOperation,
          where: d.order_id == ^id,
          select: {d.state, d.last_error}
        )
      )

    flunk("workflow deadline: #{inspect({order.phase, order.state, order.last_error, ops})}")
  end

  defp drive(id, opts, attempts) do
    order = Repo.get!(AcmeOrder, id)

    if order.state in ["published", "failed", "cancelled"] do
      assert order.state == "published", inspect(order.last_error)
    else
      due_now(id)
      result = Workflow.step(id, opts)
      assert result == :ok or match?({:snooze, _}, result), inspect(result)
      if System.get_env("SECRETHUB_PEBBLE_DIRECTORY"), do: Process.sleep(100)
      drive(id, opts, attempts - 1)
    end
  end

  defp drive_until(id, phase, opts, attempts \\ 100)
  defp drive_until(_, _, _, 0), do: flunk("workflow phase deadline")

  defp drive_until(id, phase, opts, attempts) do
    unless Repo.get!(AcmeOrder, id).phase == phase do
      due_now(id)
      Workflow.step(id, opts)
      drive_until(id, phase, opts, attempts - 1)
    end
  end

  defp due_now(id),
    do: Repo.update_all(from(o in AcmeOrder, where: o.id == ^id), set: [next_attempt_at: nil])

  defp cleanup(id, opts) do
    for op <- Repo.all(from(d in DNSChallengeOperation, where: d.order_id == ^id)) do
      assert {:ok, %{cleanup_status: "cleaned"}} = DNSOperations.cleanup(op, opts)
    end
  end

  defp fixture_transport(remote, root, root_key) do
    fn method, url, _, body, _ ->
      uri = URI.parse(url)

      if uri.host == "api.cloudflare.com",
        do: cloudflare(remote, method, uri.path, body),
        else: acme_fixture(remote, root, root_key, uri.path, body)
    end
  end

  defp acme_fixture(_, _, _, "/dir", _) do
    response(%{
      "newNonce" => @base <> "/nonce",
      "newAccount" => @base <> "/account",
      "newOrder" => @base <> "/new-order",
      "revokeCert" => @base <> "/revoke",
      "renewalInfo" => @base <> "/ari"
    })
  end

  defp acme_fixture(_, _, _, "/nonce", _), do: response(%{})

  defp acme_fixture(_, _, _, "/account", _),
    do: response(%{"status" => "valid"}, @base <> "/account/1")

  defp acme_fixture(remote, _, _, "/new-order", _) do
    Agent.update(remote, &%{&1 | orders: &1.orders + 1, acked: MapSet.new(), certificate: nil})

    response(
      %{
        "status" => "pending",
        "authorizations" => [@base <> "/auth/1", @base <> "/auth/2"],
        "finalize" => @base <> "/finalize"
      },
      @base <> "/order/1"
    )
  end

  defp acme_fixture(remote, _, _, "/auth/" <> id, _) do
    valid = Agent.get(remote, &MapSet.member?(&1.acked, id))

    response(%{
      "status" => if(valid, do: "valid", else: "pending"),
      "wildcard" => id == "2",
      "identifier" => %{"type" => "dns", "value" => "example.com"},
      "challenges" => [
        %{
          "type" => "dns-01",
          "token" => "token-#{id}",
          "url" => @base <> "/challenge/" <> id,
          "status" => if(valid, do: "valid", else: "pending")
        }
      ]
    })
  end

  defp acme_fixture(remote, _, _, "/challenge/" <> id, _) do
    assert Agent.get(remote, &map_size(&1.records)) == 2
    Agent.update(remote, &%{&1 | acked: MapSet.put(&1.acked, id)})
    response(%{"status" => "processing"})
  end

  defp acme_fixture(remote, _, _, "/order/1", _) do
    issued = Agent.get(remote, & &1.certificate)

    response(%{
      "status" => if(issued, do: "valid", else: "ready"),
      "certificate" => @base <> "/certificate"
    })
  end

  defp acme_fixture(remote, root, root_key, "/finalize", body) do
    csr =
      body
      |> JSON.decode!()
      |> Map.fetch!("payload")
      |> Base.url_decode64!(padding: false)
      |> JSON.decode!()
      |> Map.fetch!("csr")
      |> Base.url_decode64!(padding: false)
      |> X509.CSR.from_der!()

    cert =
      X509.Certificate.new(X509.CSR.public_key(csr), "/CN=example.com", root, root_key,
        template: :server,
        extensions: [subject_alt_name: Extension.subject_alt_name(@names)]
      )

    Agent.update(
      remote,
      &%{&1 | certificate: X509.Certificate.to_pem(cert), finalizations: &1.finalizations + 1}
    )

    response(%{"status" => "processing"})
  end

  defp acme_fixture(remote, _, _, "/certificate", _), do: raw(Agent.get(remote, & &1.certificate))

  defp acme_fixture(remote, _, _, "/ari/" <> _, _),
    do: response(%{"suggestedWindow" => Agent.get(remote, & &1.ari_window)})

  defp acme_fixture(remote, _, _, "/revoke", _) do
    Agent.update(remote, &%{&1 | revoked: true})
    response(%{})
  end

  defp cloudflare(remote, method, path, body) do
    result =
      cond do
        String.ends_with?(path, "/zones/zone-1") ->
          %{"id" => "zone-1", "name" => "example.com", "status" => "active"}

        method == :get and String.ends_with?(path, "/dns_records") ->
          Agent.get(remote, &Map.values(&1.records))

        method == :post ->
          Agent.get_and_update(remote, fn s ->
            id = "record-#{s.sequence + 1}"
            r = JSON.decode!(body) |> Map.put("id", id)
            {r, %{s | sequence: s.sequence + 1, records: Map.put(s.records, id, r)}}
          end)

        method == :get ->
          Agent.get(remote, & &1.records[List.last(String.split(path, "/"))])

        method == :delete ->
          id = List.last(String.split(path, "/"))
          Agent.update(remote, &%{&1 | records: Map.delete(&1.records, id)})
          %{"id" => id}
      end

    if result,
      do:
        response(%{"success" => true, "result" => result, "result_info" => %{"total_pages" => 1}}),
      else: {:ok, %{status: 404, headers: %{}, body: ""}}
  end

  defp response(body, location \\ nil), do: raw(JSON.encode!(body), location)

  defp raw(body, location \\ nil) do
    headers = %{
      "replay-nonce" => [Base.url_encode64(:crypto.strong_rand_bytes(12))],
      "content-type" => ["application/json"]
    }

    headers = if location, do: Map.put(headers, "location", [location]), else: headers
    {:ok, %{status: 200, headers: headers, body: body}}
  end

  defp pebble_transport(remote) do
    fn method, url, headers, body, opts ->
      if URI.parse(url).host == "api.cloudflare.com" do
        pebble_cloudflare(remote, method, url, body, opts)
      else
        pebble_request(method, url, headers, body, opts)
      end
    end
  end

  defp pebble_request(method, url, headers, body, opts) do
    result = HTTP.request(method, url, headers, body, Keyword.delete(opts, :transport))

    case result do
      {:ok, %{status: status, body: problem}} when status >= 400 ->
        IO.puts(
          "Pebble fixture problem at #{URI.parse(url).path}: #{String.slice(problem, 0, 600)}"
        )

      _ ->
        :ok
    end

    result
  end

  defp pebble_cloudflare(remote, method, url, body, opts) do
    result = cloudflare(remote, method, URI.parse(url).path, body)
    if method in [:post, :delete], do: sync_pebble_dns(remote, opts)
    result
  end

  defp sync_pebble_dns(remote, opts) do
    endpoint = System.fetch_env!("SECRETHUB_PEBBLE_DNS_API")
    owner = "_acme-challenge.example.com."
    clean = Keyword.delete(opts, :transport)

    {:ok, _} =
      HTTP.request(:post, endpoint <> "/clear-txt", [], JSON.encode!(%{"host" => owner}), clean)

    for record <- Agent.get(remote, &Map.values(&1.records)) do
      {:ok, _} =
        HTTP.request(
          :post,
          endpoint <> "/set-txt",
          [],
          JSON.encode!(%{"host" => owner, "value" => record["content"]}),
          clean
        )
    end
  end

  defp pebble_txt(owner) do
    port = System.fetch_env!("SECRETHUB_PEBBLE_DNS_PORT") |> String.to_integer()

    case :inet_res.resolve(String.to_charlist(owner), :in, :txt,
           nameservers: [{{127, 0, 0, 1}, port}],
           timeout: 1_000
         ) do
      {:ok, message} ->
        values =
          :inet_dns.msg(message, :anlist)
          |> Enum.map(&IO.iodata_to_binary(:inet_dns.rr(&1, :data)))

        {:ok,
         [
           %{
             server: "Pebble",
             authoritative: :inet_dns.header(:inet_dns.msg(message, :header), :aa),
             values: values
           }
         ]}

      error ->
        error
    end
  end
end
