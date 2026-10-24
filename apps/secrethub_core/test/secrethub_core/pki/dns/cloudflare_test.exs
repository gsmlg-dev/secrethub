defmodule SecretHub.Core.PKI.DNS.CloudflareTest do
  use ExUnit.Case, async: true
  alias SecretHub.Core.PKI.DNS.Cloudflare

  @config %{"zone_id" => "zone-1", "zone_name" => "example.com"}
  @credentials %{"api_token" => "fixture-token"}
  @intent %{"id" => "intent-1", "owner" => "_acme-challenge.example.com", "value" => "challenge"}

  test "creates a marked individual TXT and deletes only the unchanged owned ID" do
    parent = self()

    transport = fn method, url, headers, body, _opts ->
      assert {"authorization", "Bearer fixture-token"} in headers
      send(parent, {method, URI.parse(url).path, body})

      case {method, URI.parse(url).path} do
        {:get, "/client/v4/zones/zone-1/dns_records"} ->
          response(%{"result" => [], "result_info" => %{"total_pages" => 1}})

        {:post, "/client/v4/zones/zone-1/dns_records"} ->
          assert %{
                   "type" => "TXT",
                   "name" => "_acme-challenge.example.com",
                   "content" => "challenge",
                   "comment" => "secrethub-acme:intent-1",
                   "ttl" => 120
                 } = JSON.decode!(body)

          response(%{"result" => record("record-1")})

        {:get, "/client/v4/zones/zone-1/dns_records/record-1"} ->
          response(%{"result" => record("record-1")})

        {:delete, "/client/v4/zones/zone-1/dns_records/record-1"} ->
          response(%{"result" => %{"id" => "record-1"}})
      end
    end

    assert {:ok, %{"ownership" => "created", "record_id" => "record-1"} = receipt} =
             Cloudflare.present(@config, @credentials, @intent, transport: transport)

    assert {:ok, %{"cleanup_status" => "cleaned"}} =
             Cloudflare.cleanup(@config, @credentials, receipt, transport: transport)

    assert_received {:delete, "/client/v4/zones/zone-1/dns_records/record-1", _}
  end

  test "matching records are borrowed and never deleted" do
    transport = fn :get, _url, _headers, _body, _opts ->
      response(%{
        "result" => [record("foreign") |> Map.put("comment", "someone else")],
        "result_info" => %{"total_pages" => 1}
      })
    end

    assert {:ok, %{"ownership" => "borrowed"} = receipt} =
             Cloudflare.present(@config, @credentials, @intent, transport: transport)

    assert {:ok, %{"cleanup_status" => "cleaned"}} =
             Cloudflare.cleanup(@config, @credentials, receipt,
               transport: fn _, _, _, _, _ -> flunk("borrowed record must not be deleted") end
             )
  end

  test "pagination preserves unrelated TXT and recovers an ambiguous create by marker" do
    transport = fn :get, url, _headers, _body, _opts ->
      case URI.decode_query(URI.parse(url).query)["page"] do
        "1" ->
          response(%{
            "result" => [record("unrelated") |> Map.put("content", "unrelated")],
            "result_info" => %{"total_pages" => 2}
          })

        "2" ->
          response(%{"result" => [record("recovered")], "result_info" => %{"total_pages" => 2}})
      end
    end

    assert {:ok, %{"ownership" => "created", "record_id" => "recovered"}} =
             Cloudflare.present(@config, @credentials, @intent, transport: transport)
  end

  test "changed ownership is preserved and authentication/throttling are redacted" do
    receipt =
      Map.merge(@intent, %{
        "intent_id" => "intent-1",
        "record_id" => "record-1",
        "ownership" => "created",
        "marker" => "secrethub-acme:intent-1",
        "zone_id" => "zone-1"
      })

    changed = fn :get, _, _, _, _ ->
      response(%{"result" => record("record-1") |> Map.put("content", "changed")})
    end

    assert {:error, :ownership_conflict} =
             Cloudflare.cleanup(@config, @credentials, receipt, transport: changed)

    assert {:error, %{reason: :authentication, status: 403}} =
             Cloudflare.observe(@config, @credentials, @intent["owner"],
               transport: fn _, _, _, _, _ ->
                 {:ok, %{status: 403, headers: %{}, body: "secret remote body"}}
               end
             )

    assert {:error, %{reason: :throttled, retry_after: "7"}} =
             Cloudflare.observe(@config, @credentials, @intent["owner"],
               transport: fn _, _, _, _, _ ->
                 {:ok, %{status: 429, headers: %{"retry-after" => ["7"]}, body: ""}}
               end
             )
  end

  test "timed out create returns durable ambiguity, then reconciliation finds its marker" do
    transport = fn
      :get, _, _, _, _ -> response(%{"result" => [], "result_info" => %{"total_pages" => 1}})
      :post, _, _, _, _ -> {:error, :timeout}
    end

    assert {:error,
            %{
              reason: :ambiguous_mutation,
              receipt: %{"ownership" => "ambiguous", "intent_id" => "intent-1"}
            }} = Cloudflare.present(@config, @credentials, @intent, transport: transport)

    assert {:ok, %{"record_id" => "found"}} =
             Cloudflare.reconcile(@config, @credentials, @intent,
               transport: fn :get, _, _, _, _ ->
                 response(%{
                   "result" => [record("found")],
                   "result_info" => %{"total_pages" => 1}
                 })
               end
             )
  end

  test "a record edited after ownership was established is preserved" do
    transport = fn :get, _, _, _, _ ->
      response(%{"result" => [record("record-1")], "result_info" => %{"total_pages" => 1}})
    end

    assert {:ok, receipt} =
             Cloudflare.reconcile(@config, @credentials, @intent, transport: transport)

    edited = fn :get, _, _, _, _ ->
      response(%{"result" => record("record-1") |> Map.put("ttl", 600)})
    end

    assert {:error, :ownership_conflict} =
             Cloudflare.cleanup(@config, @credentials, receipt, transport: edited)
  end

  test "failed cleanup retains ownership evidence and succeeds on retry" do
    {:ok, calls} = Agent.start_link(fn -> 0 end)

    transport = fn
      :get, _, _, _, _ ->
        response(%{"result" => record("record-1")})

      :delete, _, _, _, _ ->
        case Agent.get_and_update(calls, &{&1, &1 + 1}) do
          0 -> {:ok, %{status: 503, headers: %{}, body: "redacted"}}
          1 -> response(%{"result" => %{"id" => "record-1"}})
        end
    end

    receipt =
      Map.merge(@intent, %{
        "record_id" => "record-1",
        "ownership" => "created",
        "marker" => "secrethub-acme:intent-1",
        "zone_id" => "zone-1"
      })

    assert {:error, %{reason: :provider_unavailable}} =
             Cloudflare.cleanup(@config, @credentials, receipt, transport: transport)

    assert {:ok, %{"cleanup_status" => "cleaned"}} =
             Cloudflare.cleanup(@config, @credentials, receipt, transport: transport)
  end

  test "malformed zone data returns a bounded provider error" do
    assert {:error, :invalid_provider_response} =
             Cloudflare.validate_zone(@config, @credentials,
               transport: fn _, _, _, _, _ -> response(%{"result" => "malformed"}) end
             )
  end

  test "malformed record entries return a bounded provider error" do
    assert {:error, :invalid_provider_response} =
             Cloudflare.observe(@config, @credentials, @intent["owner"],
               transport: fn _, _, _, _, _ -> response(%{"result" => [42]}) end
             )
  end

  test "malformed JSON returns a bounded provider error" do
    for body <- ["", "{", "provider response with credential-shaped data"] do
      assert {:error, :invalid_provider_response} =
               Cloudflare.observe(@config, @credentials, @intent["owner"],
                 transport: fn _, _, _, _, _ ->
                   {:ok, %{status: 200, headers: %{}, body: body}}
                 end
               )
    end
  end

  test "malformed pagination metadata returns a bounded provider error" do
    assert {:error, :invalid_provider_response} =
             Cloudflare.observe(@config, @credentials, @intent["owner"],
               transport: fn _, _, _, _, _ ->
                 response(%{"result" => [], "result_info" => "malformed"})
               end
             )
  end

  test "malformed cleanup observation never authorizes deletion" do
    receipt =
      Map.merge(@intent, %{
        "record_id" => "record-1",
        "ownership" => "created",
        "marker" => "secrethub-acme:intent-1",
        "zone_id" => "zone-1"
      })

    assert {:error, :invalid_provider_response} =
             Cloudflare.cleanup(@config, @credentials, receipt,
               transport: fn :get, _, _, _, _ -> response(%{"result" => "malformed"}) end
             )
  end

  test "discovers all active zones across pages through the provider dispatcher" do
    parent = self()

    transport = fn :get, url, headers, "", _ ->
      assert URI.parse(url).path == "/client/v4/zones"
      assert {"authorization", "Bearer fixture-token"} in headers
      query = URI.decode_query(URI.parse(url).query)
      send(parent, {:list_zones_query, query})

      case query["page"] do
        "1" ->
          response(%{
            "result" => [
              zone_entry("first", "EXAMPLE.COM."),
              zone_entry("pending", "pending.com", "pending")
            ],
            "result_info" => %{"page" => 1, "total_pages" => 2}
          })

        "2" ->
          response(%{
            "result" => [zone_entry("second", "second.com")],
            "result_info" => %{"page" => 2, "total_pages" => 2}
          })
      end
    end

    assert {:ok,
            [
              %{"zone_id" => "first", "zone_name" => "example.com"},
              %{"zone_id" => "second", "zone_name" => "second.com"}
            ]} =
             SecretHub.Core.PKI.DNS.list_zones(%{"provider" => "cloudflare"}, @credentials,
               transport: transport
             )

    assert_received {:list_zones_query, %{"page" => "1", "per_page" => "50"}}
    assert_received {:list_zones_query, %{"page" => "2", "per_page" => "50"}}
  end

  test "zone discovery accepts the standard secret value as the API token" do
    transport = fn :get, url, headers, "", _opts ->
      assert URI.parse(url).path == "/client/v4/zones"
      assert {"authorization", "Bearer fixture-token"} in headers
      response(%{"result" => [zone_entry("zone-1", "example.com")]})
    end

    assert {:ok, [%{"zone_id" => "zone-1", "zone_name" => "example.com"}]} =
             Cloudflare.list_zones(%{"value" => "fixture-token"}, transport: transport)
  end

  test "zone discovery rejects malformed results and pagination" do
    for result <- [
          nil,
          "bad",
          [42],
          [zone_entry("", "example.com")],
          [zone_entry("id", "*.example.com")],
          [zone_entry("id", "invalid")]
        ] do
      assert {:error, :invalid_provider_response} =
               Cloudflare.list_zones(@credentials,
                 transport: fn :get, _, _, _, _ -> response(%{"result" => result}) end
               )
    end

    for info <- [
          "bad",
          %{"page" => 2, "total_pages" => 2},
          %{"total_pages" => "2"},
          %{"total_pages" => 0}
        ] do
      assert {:error, :invalid_provider_response} =
               Cloudflare.list_zones(@credentials,
                 transport: fn :get, _, _, _, _ ->
                   response(%{"result" => [], "result_info" => info})
                 end
               )
    end

    assert {:error, :pagination_limit} =
             Cloudflare.list_zones(@credentials,
               transport: fn :get, _, _, _, _ ->
                 response(%{"result" => [], "result_info" => %{"total_pages" => 21}})
               end
             )
  end

  test "zone discovery returns credential and authentication errors without remote bodies" do
    assert {:error, :credentials_unavailable} =
             Cloudflare.list_zones(%{},
               transport: fn _, _, _, _, _ ->
                 flunk("missing credentials must not make requests")
               end
             )

    assert {:error, %{reason: :authentication, status: 403}} =
             Cloudflare.list_zones(@credentials,
               transport: fn :get, _, _, _, _ ->
                 {:ok, %{status: 403, headers: %{}, body: "fixture-token"}}
               end
             )

    assert {:error, :unsupported_provider} =
             SecretHub.Core.PKI.DNS.list_zones(%{"provider" => "unknown"}, @credentials)
  end

  defp zone_entry(id, name, status \\ "active"),
    do: %{"id" => id, "name" => name, "status" => status}

  defp record(id),
    do: %{
      "id" => id,
      "type" => "TXT",
      "name" => @intent["owner"],
      "content" => @intent["value"],
      "comment" => "secrethub-acme:intent-1",
      "ttl" => 120
    }

  defp response(body),
    do: {:ok, %{status: 200, headers: %{}, body: JSON.encode!(Map.put(body, "success", true))}}
end
