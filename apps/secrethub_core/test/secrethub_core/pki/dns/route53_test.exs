defmodule SecretHub.Core.PKI.DNS.Route53Test do
  use ExUnit.Case, async: true
  alias SecretHub.Core.PKI.DNS.Route53

  @config %{"zone_id" => "Z123", "zone_name" => "example.com"}
  @credentials %{
    "access_key_id" => "AKIDEXAMPLE",
    "secret_access_key" => "fixture-secret",
    "session_token" => "fixture-session"
  }
  @intent %{"id" => "intent-1", "owner" => "_acme-challenge.example.com", "value" => "challenge"}

  test "persists a preimage before exact DELETE/CREATE and signs temporary credentials" do
    parent = self()

    transport = fn method, url, headers, body, _ ->
      assert {"x-amz-security-token", "fixture-session"} in headers

      assert Enum.any?(headers, fn {k, v} ->
               k == "authorization" and String.contains?(v, "Credential=AKIDEXAMPLE/") and
                 String.contains?(v, "x-amz-security-token")
             end)

      case {method, URI.parse(url).path} do
        {:get, "/2013-04-01/hostedzone/Z123"} ->
          zone()

        {:get, "/2013-04-01/hostedzone/Z123/rrset"} ->
          rrset(["unrelated"], 90)

        {:post, "/2013-04-01/hostedzone/Z123/rrset"} ->
          refute String.contains?(body, "UPSERT")
          assert String.contains?(body, "<Action>DELETE</Action>")
          assert String.contains?(body, "<Action>CREATE</Action>")
          assert String.contains?(body, "<TTL>90</TTL>")
          assert String.contains?(body, "&quot;unrelated&quot;")
          assert String.contains?(body, "&quot;challenge&quot;")
          send(parent, :changed)
          change("PENDING")

        {:get, "/2013-04-01/change/C123"} ->
          change("INSYNC")
      end
    end

    assert {:error, :intent_not_prepared} =
             Route53.present(@config, @credentials, @intent, transport: transport)

    assert {:ok, %{"prepared" => true, "preimage" => %{"ttl" => 90}} = prepared} =
             Route53.prepare(@config, @credentials, @intent, transport: transport)

    assert {:ok, %{"ownership" => "created", "change_status" => "PENDING"} = receipt} =
             Route53.present(@config, @credentials, prepared, transport: transport)

    assert_received :changed

    assert {:ok, %{"change_status" => "INSYNC"}} =
             Route53.poll_change(@config, @credentials, receipt, transport: transport)
  end

  test "cleanup rereads current RRset and preserves external additions and TTL" do
    receipt =
      Map.merge(@intent, %{
        "intent_id" => "intent-1",
        "zone_id" => "Z123",
        "ownership" => "created",
        "phase" => "present",
        "change_status" => "INSYNC"
      })

    transport = fn method, url, _, body, _ ->
      case {method, URI.parse(url).path} do
        {:get, "/2013-04-01/hostedzone/Z123"} ->
          zone()

        {:get, "/2013-04-01/hostedzone/Z123/rrset"} ->
          rrset(["challenge", "unrelated", "external"], 180)

        {:post, "/2013-04-01/hostedzone/Z123/rrset"} ->
          [_, create] = String.split(body, "<Action>CREATE</Action>")
          refute String.contains?(create, "&quot;challenge&quot;")
          assert String.contains?(create, "&quot;unrelated&quot;")
          assert String.contains?(create, "&quot;external&quot;")
          assert String.contains?(create, "<TTL>180</TTL>")
          change("PENDING")

        {:get, "/2013-04-01/change/C123"} ->
          change("INSYNC")
      end
    end

    assert {:ok, %{"cleanup_status" => "pending_change"} = pending} =
             Route53.cleanup(@config, @credentials, receipt, transport: transport)

    assert {:ok, %{"cleanup_status" => "cleaned"}} =
             Route53.cleanup(@config, @credentials, pending, transport: transport)
  end

  test "borrowed value is never deleted and absent set uses guarded CREATE" do
    transport = fn :get, url, _, _, _ ->
      if String.ends_with?(URI.parse(url).path, "/rrset"),
        do: rrset(["challenge"], 60),
        else: zone()
    end

    assert {:ok, prepared} = Route53.prepare(@config, @credentials, @intent, transport: transport)

    assert {:ok, %{"ownership" => "borrowed"} = receipt} =
             Route53.present(@config, @credentials, prepared, transport: transport)

    assert {:ok, %{"cleanup_status" => "cleaned"}} =
             Route53.cleanup(@config, @credentials, receipt,
               transport: fn _, _, _, _, _ -> flunk("borrowed deletion") end
             )

    absent = fn
      :get, url, _, _, _ ->
        if String.ends_with?(URI.parse(url).path, "/rrset"), do: rrset([], nil), else: zone()

      :post, _, _, body, _ ->
        refute String.contains?(body, "DELETE")
        change("PENDING")
    end

    assert {:ok, prepared} = Route53.prepare(@config, @credentials, @intent, transport: absent)

    assert {:ok, %{"ownership" => "created"}} =
             Route53.present(@config, @credentials, prepared, transport: absent)
  end

  test "rejects private zones, unfamiliar routing and XML entities" do
    assert {:error, :private_zone} =
             Route53.validate_zone(@config, @credentials,
               transport: fn _, _, _, _, _ -> zone(true) end
             )

    routed = fn :get, url, _, _, _ ->
      if String.ends_with?(URI.parse(url).path, "/rrset"),
        do:
          response(
            "<ListResourceRecordSetsResponse><ResourceRecordSets><ResourceRecordSet><Name>_acme-challenge.example.com.</Name><Type>TXT</Type><SetIdentifier>weighted</SetIdentifier><Weight>2</Weight><TTL>60</TTL><ResourceRecords><ResourceRecord><Value>\"challenge\"</Value></ResourceRecord></ResourceRecords></ResourceRecordSet></ResourceRecordSets><IsTruncated>false</IsTruncated></ListResourceRecordSetsResponse>"
          ),
        else: zone()
    end

    assert {:error, :unsupported_record_shape} =
             Route53.observe(@config, @credentials, @intent["owner"], transport: routed)

    assert {:error, :invalid_provider_response} =
             Route53.validate_zone(@config, @credentials,
               transport: fn _, _, _, _, _ ->
                 response(
                   "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>"
                 )
               end
             )
  end

  test "conflicting current preimage is not overwritten" do
    prepared =
      Map.merge(@intent, %{
        "prepared" => true,
        "preimage" => %{"name" => @intent["owner"], "ttl" => 60, "values" => ["old"]}
      })

    transport = fn :get, url, _, _, _ ->
      if String.ends_with?(URI.parse(url).path, "/rrset"),
        do: rrset(["changed"], 60),
        else: zone()
    end

    assert {:error, :record_conflict} =
             Route53.present(@config, @credentials, prepared, transport: transport)
  end

  test "lost mutation response retains preimage and reconciles only the intended RRset" do
    prepared = Map.merge(@intent, %{"prepared" => true, "preimage" => nil})

    transport = fn
      :get, url, _, _, _ ->
        if String.ends_with?(URI.parse(url).path, "/rrset"), do: rrset([], nil), else: zone()

      :post, _, _, _, _ ->
        {:error, :timeout}
    end

    assert {:error,
            %{
              reason: :ambiguous_mutation,
              receipt: %{"preimage" => nil, "ownership" => "ambiguous"}
            }} = Route53.present(@config, @credentials, prepared, transport: transport)

    found = fn :get, url, _, _, _ ->
      if String.ends_with?(URI.parse(url).path, "/rrset"),
        do: rrset(["challenge"], 60),
        else: zone()
    end

    assert {:ok, %{"ownership" => "ambiguous", "change_status" => "UNKNOWN"}} =
             Route53.reconcile(@config, @credentials, prepared, transport: found)
  end

  test "invalid or incomplete provider responses cannot be mistaken for an absent RRset" do
    assert {:error, :invalid_provider_response} =
             Route53.validate_zone(@config, @credentials,
               transport: fn _, _, _, _, _ ->
                 response(
                   "<GetHostedZoneResponse><HostedZone><Id>/hostedzone/Z123</Id><Name>example.com.</Name></HostedZone></GetHostedZoneResponse>"
                 )
               end
             )

    incomplete = fn :get, url, _, _, _ ->
      if String.ends_with?(URI.parse(url).path, "/rrset"),
        do:
          response(
            "<ListResourceRecordSetsResponse><ResourceRecordSets/></ListResourceRecordSetsResponse>"
          ),
        else: zone()
    end

    assert {:error, :invalid_provider_response} =
             Route53.prepare(@config, @credentials, @intent, transport: incomplete)
  end

  test "AWS rejects a changed exact preimage and throttling without leaking response bodies" do
    prepared = Map.merge(@intent, %{"prepared" => true, "preimage" => nil})

    for {code, expected} <- [
          {"InvalidChangeBatch", :record_conflict},
          {"Throttling", %{reason: :throttled, retry_after: "3"}}
        ] do
      transport = fn
        :get, url, _, _, _ ->
          if String.ends_with?(URI.parse(url).path, "/rrset"), do: rrset([], nil), else: zone()

        :post, _, _, _, _ ->
          {:ok,
           %{
             status: 400,
             headers: %{"retry-after" => ["3"]},
             body:
               "<ErrorResponse><Error><Code>#{code}</Code><Message>untrusted secret response</Message></Error></ErrorResponse>"
           }}
      end

      assert {:error, ^expected} =
               Route53.present(@config, @credentials, prepared, transport: transport)
    end
  end

  defp response(body), do: {:ok, %{status: 200, headers: %{}, body: body}}

  defp zone(private \\ false),
    do:
      response(
        "<GetHostedZoneResponse><HostedZone><Id>/hostedzone/Z123</Id><Name>example.com.</Name><Config><PrivateZone>#{private}</PrivateZone></Config></HostedZone></GetHostedZoneResponse>"
      )

  defp change(status),
    do:
      response(
        "<ChangeResourceRecordSetsResponse><ChangeInfo><Id>/change/C123</Id><Status>#{status}</Status></ChangeInfo></ChangeResourceRecordSetsResponse>"
      )

  defp rrset(values, ttl) do
    record =
      if ttl,
        do:
          "<ResourceRecordSet><Name>_acme-challenge.example.com.</Name><Type>TXT</Type><TTL>#{ttl}</TTL><ResourceRecords>#{Enum.map_join(values, fn value -> "<ResourceRecord><Value>&quot;#{value}&quot;</Value></ResourceRecord>" end)}</ResourceRecords></ResourceRecordSet>",
        else: ""

    response(
      "<ListResourceRecordSetsResponse><ResourceRecordSets>#{record}</ResourceRecordSets><IsTruncated>false</IsTruncated></ListResourceRecordSetsResponse>"
    )
  end
end
