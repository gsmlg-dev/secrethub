defmodule SecretHub.Core.PKI.ACME.DNSOperationsTest do
  use ExUnit.Case, async: false
  alias Ecto.Changeset
  import Ecto.Query
  alias SecretHub.Core.PKI.ACME.{CleanupWorker, DNSOperations}
  alias SecretHub.Core.{Repo, RuntimeDatabaseFixture}

  alias SecretHub.Shared.Schemas.{
    AcmeAccount,
    AcmeAuthorization,
    AcmeOrder,
    DNSChallengeOperation,
    DNSProvider,
    ManagedCertificate,
    Secret
  }

  setup_all do
    RuntimeDatabaseFixture.prepare_template()
  end

  setup tags do
    RuntimeDatabaseFixture.setup(tags)
    {:ok, remote} = Agent.start_link(fn -> %{records: %{}, creates: 0, deletes: 0} end)
    {order, authorization, resource} = fixtures()

    opts = [
      credentials_resolver: fn _ -> {:ok, %{"api_token" => "fixture-token"}} end,
      resolver: fn _, :cname -> {:ok, []} end,
      transport: transport(remote),
      authoritative_resolver: fn _ ->
        {:ok,
         [
           %{
             server: "fixture-authoritative",
             authoritative: true,
             values:
               Agent.get(remote, fn s -> Enum.map(s.records, fn {_, r} -> r["content"] end) end)
           }
         ]}
      end
    ]

    %{order: order, authorization: authorization, resource: resource, remote: remote, opts: opts}
  end

  test "intent is durable before mutation and propagation uses authoritative values", context do
    %{order: order, authorization: authorization, opts: opts, remote: remote} = context
    assert {:ok, operation} = DNSOperations.create_intent(order, authorization, "challenge", opts)
    assert operation.state == "intent"
    assert Repo.get!(DNSChallengeOperation, operation.id).intent["id"] == operation.id
    assert {:ok, same} = DNSOperations.create_intent(order, authorization, "challenge", opts)
    assert same.id == operation.id

    assert {:error, :intent_conflict} =
             DNSOperations.create_intent(order, authorization, "different", opts)

    assert {:ok, prepared} = DNSOperations.advance(operation, opts)
    assert prepared.state == "prepared"
    assert Agent.get(remote, & &1.creates) == 0
    assert {:ok, presented} = DNSOperations.advance(prepared, opts)
    assert presented.state == "presented"
    assert presented.receipt["ownership"] == "created"
    assert Agent.get(remote, & &1.creates) == 1
    assert {:ok, propagated} = DNSOperations.advance(presented, opts)
    assert propagated.state == "propagated"
    assert {:error, :order_active} = DNSOperations.cleanup(propagated, opts)
    Repo.update!(Changeset.change(order, state: "cancelled"))
    assert {:ok, cleaned} = DNSOperations.cleanup(propagated, opts)
    assert cleaned.cleanup_status == "cleaned"
    assert Agent.get(remote, & &1.deletes) == 1
  end

  test "crash after remote creation resumes via marker without another create", context do
    %{order: order, authorization: authorization, opts: opts, remote: remote} = context
    {:ok, operation} = DNSOperations.create_intent(order, authorization, "challenge", opts)
    {:ok, prepared} = DNSOperations.advance(operation, opts)

    assert_raise RuntimeError, "simulated crash", fn ->
      DNSOperations.advance(
        prepared,
        Keyword.put(opts, :after_effect, fn _ -> raise "simulated crash" end)
      )
    end

    interrupted = Repo.get!(DNSChallengeOperation, operation.id)
    assert interrupted.state == "presenting"
    assert interrupted.receipt == %{}

    Repo.update!(
      Changeset.change(interrupted,
        claim_expires_at: DateTime.add(DateTime.utc_now() |> DateTime.truncate(:second), -1)
      )
    )

    assert {:ok, resumed} = DNSOperations.advance(operation.id, opts)
    assert resumed.state == "presented"
    assert resumed.receipt["record_id"] == "record-1"
    assert Agent.get(remote, & &1.creates) == 1
    Repo.update!(Changeset.change(order, state: "failed"))
    assert {:ok, %{cleanup_status: "cleaned"}} = DNSOperations.cleanup(resumed, opts)
  end

  test "disable after creation stops new work and retains original credentials for cleanup",
       context do
    %{order: order, authorization: authorization, resource: resource, opts: opts} = context
    {:ok, operation} = DNSOperations.create_intent(order, authorization, "challenge", opts)
    {:ok, prepared} = DNSOperations.advance(operation, opts)
    {:ok, presented} = DNSOperations.advance(prepared, opts)
    Repo.update!(Changeset.change(resource, enabled: false))
    Repo.update!(Changeset.change(order, state: "cancelled"))
    assert {:ok, %{cleanup_status: "cleaned"}} = DNSOperations.cleanup(presented, opts)
  end

  test "shared values remain until all active orders release them", context do
    %{order: first, authorization: first_auth, opts: opts, remote: remote} = context
    {:ok, op1} = DNSOperations.create_intent(first, first_auth, "shared", opts)
    {:ok, op1} = DNSOperations.advance(op1, opts)
    {:ok, op1} = DNSOperations.advance(op1, opts)
    {second, second_auth, _} = fixtures(first.bindings)
    {:ok, op2} = DNSOperations.create_intent(second, second_auth, "shared", opts)
    {:ok, op2} = DNSOperations.advance(op2, opts)
    {:ok, op2} = DNSOperations.advance(op2, opts)
    assert op2.receipt["ownership"] == "borrowed"
    Repo.update!(Changeset.change(first, state: "published"))
    assert {:error, :value_in_use} = DNSOperations.cleanup(op1, opts)
    assert Agent.get(remote, & &1.deletes) == 0
    Repo.update!(Changeset.change(second, state: "failed"))
    assert {:ok, %{cleanup_status: "cleaned"}} = DNSOperations.cleanup(op1, opts)
    assert {:ok, %{cleanup_status: "cleaned"}} = DNSOperations.cleanup(op2, opts)
    assert Agent.get(remote, & &1.deletes) == 1
  end

  test "stale order claims cannot create records and cancellation cannot discard a receipt",
       context do
    %{order: order, authorization: authorization, opts: opts, remote: remote} = context
    {:ok, operation} = DNSOperations.create_intent(order, authorization, "challenge", opts)
    {:ok, prepared} = DNSOperations.advance(operation, opts)

    assert {:error, :stale_order_claim} =
             DNSOperations.advance(
               prepared,
               Keyword.put(opts, :order_claim, Ecto.UUID.generate())
             )

    assert Agent.get(remote, & &1.creates) == 0

    effect = fn _ ->
      Repo.update!(Changeset.change(order, state: "cancelled", claim_token: nil))
    end

    assert {:ok, presented} =
             DNSOperations.advance(prepared, Keyword.put(opts, :after_effect, effect))

    assert presented.receipt["record_id"] == "record-1"
    assert Repo.get!(AcmeOrder, order.id).state == "cancelled"
    assert {:ok, %{cleanup_status: "cleaned"}} = DNSOperations.cleanup(presented, opts)
  end

  test "expired DNS ownership cannot authorize a new mutation", context do
    %{order: order, authorization: authorization, opts: opts, remote: remote} = context
    {:ok, operation} = DNSOperations.create_intent(order, authorization, "challenge", opts)
    {:ok, prepared} = DNSOperations.advance(operation, opts)

    steal = fn _ ->
      Repo.update_all(from(d in DNSChallengeOperation, where: d.id == ^prepared.id),
        set: [claim_token: Ecto.UUID.generate()]
      )

      {:ok, %{"api_token" => "fixture-token"}}
    end

    assert {:error, :stale_dns_claim} =
             DNSOperations.advance(prepared, Keyword.put(opts, :credentials_resolver, steal))

    assert Agent.get(remote, & &1.creates) == 0

    Repo.update_all(from(d in DNSChallengeOperation, where: d.id == ^prepared.id),
      set: [claim_token: nil, claim_expires_at: nil]
    )

    assert {:ok, presented} = DNSOperations.advance(prepared, opts)
    Repo.update!(Changeset.change(order, state: "cancelled"))

    assert {:error, :stale_dns_claim} =
             DNSOperations.cleanup(
               presented,
               Keyword.put(opts, :credentials_resolver, steal)
             )

    assert Agent.get(remote, & &1.deletes) == 0

    Repo.update_all(from(d in DNSChallengeOperation, where: d.id == ^prepared.id),
      set: [claim_token: nil, claim_expires_at: nil]
    )

    assert {:ok, %{cleanup_status: "cleaned"}} = DNSOperations.cleanup(presented, opts)
  end

  test "operation cleanup jobs finish while order jobs continue to the next obligation",
       context do
    %{order: order, authorization: authorization, opts: opts} = context
    {:ok, operation} = DNSOperations.create_intent(order, authorization, "challenge", opts)
    Repo.update!(Changeset.change(order, state: "cancelled"))
    job = %Oban.Job{args: %{"cleanup_operation_id" => operation.id}}
    assert :ok = CleanupWorker.perform(job)
    assert :ok = CleanupWorker.perform(job)

    authorization =
      Repo.insert!(%AcmeAuthorization{
        order_id: order.id,
        url: "https://ca.example/second",
        identifier: "example.com",
        token: "second",
        challenge_url: "https://ca.example/challenge/second"
      })

    operation =
      Repo.insert!(%DNSChallengeOperation{
        order_id: order.id,
        authorization_id: authorization.id,
        provider_id: operation.provider_id,
        provider_snapshot: operation.provider_snapshot,
        original_owner: operation.original_owner,
        owner: operation.owner,
        value: "second",
        intent: %{}
      })

    order_job = %Oban.Job{args: %{"cleanup_order_id" => order.id}}
    assert {:snooze, 1} = CleanupWorker.perform(order_job)
    assert Repo.get!(DNSChallengeOperation, operation.id).cleanup_status == "cleaned"
    assert :ok = CleanupWorker.perform(order_job)
  end

  test "the pinned owner lock spans a bounded provider mutation across concurrent orders",
       context do
    %{order: first, authorization: first_auth, opts: opts} = context
    {:ok, op1} = DNSOperations.create_intent(first, first_auth, "first", opts)
    {:ok, op1} = DNSOperations.advance(op1, opts)
    {second, second_auth, _} = fixtures(first.bindings)
    {:ok, op2} = DNSOperations.create_intent(second, second_auth, "second", opts)
    {:ok, op2} = DNSOperations.advance(op2, opts)
    parent = self()
    base_transport = opts[:transport]

    blocking = fn method, url, headers, body, options ->
      if method == :post do
        send(parent, {:mutation_started, self()})

        receive do
          :continue -> :ok
        after
          5_000 -> flunk("mutation was not released")
        end
      end

      base_transport.(method, url, headers, body, options)
    end

    task =
      Task.async(fn ->
        Repo.put_dynamic_repo(:runtime_authorization_fixture)
        DNSOperations.advance(op1, Keyword.put(opts, :transport, blocking))
      end)

    assert_receive {:mutation_started, worker}, 5_000
    assert {:error, :owner_busy} = DNSOperations.advance(op2, opts)
    send(worker, :continue)
    assert {:ok, %{state: "presented"}} = Task.await(task, 5_000)
    assert {:ok, %{state: "presented"}} = DNSOperations.advance(op2, opts)
  end

  test "Route53 concurrent preimages refresh only after a definite rejected change", context do
    %{order: original, remote: remote, opts: opts} = context
    binding = hd(original.bindings) |> Map.put("provider", "route53")
    {first, first_auth, _} = fixtures([binding])
    {second, second_auth, _} = fixtures([binding])

    opts =
      opts
      |> Keyword.put(:transport, route53_transport(remote))
      |> Keyword.put(:credentials_resolver, fn _ ->
        {:ok, %{"access_key_id" => "fixture", "secret_access_key" => "fixture"}}
      end)

    {:ok, op1} = DNSOperations.create_intent(first, first_auth, "first", opts)
    {:ok, op2} = DNSOperations.create_intent(second, second_auth, "second", opts)
    {:ok, op1} = DNSOperations.advance(op1, opts)
    {:ok, op2} = DNSOperations.advance(op2, opts)
    assert {:ok, %{state: "presented"}} = DNSOperations.advance(op1, opts)
    assert {:error, :record_conflict} = DNSOperations.advance(op2, opts)
    assert Repo.get!(DNSChallengeOperation, op2.id).state == "intent"
    assert {:ok, %{state: "prepared"}} = DNSOperations.advance(op2, opts)
    assert {:ok, %{state: "presented"}} = DNSOperations.advance(op2, opts)
    assert Agent.get(remote, & &1.values) == ["first", "second"]
  end

  defp route53_transport(remote) do
    Agent.update(remote, &Map.put(&1, :values, []))

    fn method, url, _, body, _ ->
      xml =
        case {method, URI.parse(url).path} do
          {:get, "/2013-04-01/hostedzone/zone-1"} ->
            "<GetHostedZoneResponse><HostedZone><Id>/hostedzone/zone-1</Id><Name>example.com.</Name><Config><PrivateZone>false</PrivateZone></Config></HostedZone></GetHostedZoneResponse>"

          {:get, "/2013-04-01/hostedzone/zone-1/rrset"} ->
            values = Agent.get(remote, & &1.values)

            record = fixture_rrset(values)

            "<ListResourceRecordSetsResponse><ResourceRecordSets>#{record}</ResourceRecordSets><IsTruncated>false</IsTruncated></ListResourceRecordSetsResponse>"

          {:post, "/2013-04-01/hostedzone/zone-1/rrset"} ->
            [_, created] = String.split(body, "<Action>CREATE</Action>")

            values =
              Regex.scan(~r/<Value>&quot;([^&]+)&quot;<\/Value>/, created,
                capture: :all_but_first
              )
              |> List.flatten()

            Agent.update(remote, &Map.put(&1, :values, values))

            "<ChangeResourceRecordSetsResponse><ChangeInfo><Id>/change/fixture</Id><Status>INSYNC</Status></ChangeInfo></ChangeResourceRecordSetsResponse>"
        end

      {:ok, %{status: 200, headers: %{}, body: xml}}
    end
  end

  defp fixture_rrset(values) do
    if values == [],
      do: "",
      else:
        "<ResourceRecordSet><Name>_acme-challenge.example.com.</Name><Type>TXT</Type><TTL>60</TTL><ResourceRecords>" <>
          Enum.map_join(
            values,
            &"<ResourceRecord><Value>&quot;#{&1}&quot;</Value></ResourceRecord>"
          ) <>
          "</ResourceRecords></ResourceRecordSet>"
  end

  defp transport(remote) do
    fn method, url, _, body, _ ->
      path = URI.parse(url).path

      result =
        cond do
          method == :get and String.ends_with?(path, "/zones/zone-1") ->
            %{"id" => "zone-1", "name" => "example.com", "status" => "active"}

          method == :get and String.ends_with?(path, "/dns_records") ->
            Agent.get(remote, &Map.values(&1.records))

          method == :post ->
            create_cloudflare_record(remote, body)

          method == :get ->
            Agent.get(remote, & &1.records[List.last(String.split(path, "/"))])

          method == :delete ->
            id = List.last(String.split(path, "/"))

            Agent.update(remote, &remove_cloudflare_record(&1, id))

            %{"id" => id}
        end

      if result == nil do
        {:ok, %{status: 404, headers: %{}, body: ""}}
      else
        {:ok,
         %{
           status: 200,
           headers: %{},
           body:
             JSON.encode!(%{
               "success" => true,
               "result" => result,
               "result_info" => %{"total_pages" => 1}
             })
         }}
      end
    end
  end

  defp remove_cloudflare_record(state, id),
    do: %{state | records: Map.delete(state.records, id), deletes: state.deletes + 1}

  defp create_cloudflare_record(remote, body) do
    Agent.get_and_update(remote, fn state ->
      record = JSON.decode!(body) |> Map.put("id", "record-#{state.creates + 1}")

      {record,
       %{
         state
         | records: Map.put(state.records, record["id"], record),
           creates: state.creates + 1
       }}
    end)
  end

  defp fixtures(existing_bindings \\ nil) do
    binding =
      if existing_bindings do
        hd(existing_bindings)
      else
        credential =
          Repo.insert!(%Secret{
            name: "DNS fixture",
            secret_path: "test.dns.#{System.unique_integer([:positive])}",
            secret_type: :static,
            encrypted_data: <<0>>
          })

        provider =
          Repo.insert!(%DNSProvider{
            name: "Cloudflare fixture",
            provider: "cloudflare",
            credential_secret_id: credential.id,
            zones: [%{"zone_id" => "zone-1", "zone_name" => "example.com"}]
          })

        %{
          "provider_id" => provider.id,
          "provider" => "cloudflare",
          "suffix" => "example.com",
          "zone_id" => "zone-1",
          "zone_name" => "example.com",
          "credential_mode" => "secret",
          "credential_secret_id" => credential.id
        }
      end

    account =
      Repo.insert!(%AcmeAccount{
        name: "Staging",
        environment: "staging",
        directory_url: "https://acme-staging-v02.api.letsencrypt.org/directory",
        terms_url: "https://letsencrypt.org/repository/",
        terms_accepted_at: DateTime.utc_now() |> DateTime.truncate(:second),
        encrypted_key: <<0>>
      })

    resource =
      Repo.insert!(%ManagedCertificate{
        slug: "fixture-#{System.unique_integer([:positive])}",
        account_id: account.id,
        identifiers: ["example.com"],
        bindings: [binding]
      })

    order =
      Repo.insert!(%AcmeOrder{
        managed_certificate_id: resource.id,
        request_id: Ecto.UUID.generate(),
        request_digest: "fixture",
        configuration_revision: 1,
        identifiers: ["example.com"],
        bindings: [binding],
        account_snapshot: %{"id" => account.id, "environment" => "staging"},
        deadline_at: DateTime.add(DateTime.utc_now() |> DateTime.truncate(:second), 3600)
      })

    authorization =
      Repo.insert!(%AcmeAuthorization{
        order_id: order.id,
        url: "https://ca.example/acme/auth/#{Ecto.UUID.generate()}",
        identifier: "example.com",
        challenge_url: "https://ca.example/acme/challenge",
        token: "fixture"
      })

    {order, authorization, resource}
  end
end
