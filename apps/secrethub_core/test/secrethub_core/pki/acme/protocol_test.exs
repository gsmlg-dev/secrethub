defmodule SecretHub.Core.PKI.ACME.ProtocolTest do
  use ExUnit.Case, async: true

  alias SecretHub.Core.PKI.ACME.{Client, Keys, Renewal}
  alias SecretHub.Core.PKI.{HTTP, TrustStores}

  test "catalogue identifies the exact offline bundle bytes and roots" do
    assert {:ok, pem} = TrustStores.pem("mozilla_webpki")
    assert {:ok, catalogue} = TrustStores.catalogue("mozilla_webpki")
    assert catalogue.sha256 == Base.encode16(:crypto.hash(:sha256, pem), case: :lower)
    assert catalogue.root_count > 50
    assert catalogue.root_count == length(catalogue.roots)

    assert %{fingerprint_sha256: _, subject: _, issuer: _, not_before: _, not_after: _} =
             hd(catalogue.roots)

    assert {:error, :unknown_trust_store} = TrustStores.pem("internal")
  end

  test "malformed PEM cannot silently become an empty trust profile" do
    assert {:error, :invalid_bundle} = TrustStores.parse_bundle("garbage")

    assert {:error, :invalid_bundle} =
             TrustStores.parse_bundle(
               "-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----"
             )
  end

  test "transport must be HTTPS and cannot silently downgrade peer verification" do
    assert {:error, :https_required} = HTTP.request(:get, "http://example.com/", [], "")

    assert {:error, :invalid_url} =
             HTTP.request(:get, "https://user:password@example.com/", [], "")
  end

  test "bounded injected transport preserves status headers and binary body" do
    transport = fn :get, "https://example.com/", [], "", _opts ->
      {:ok, %{status: 429, headers: [{"Retry-After", "12"}], body: "busy"}}
    end

    assert {:ok, %{status: 429, headers: %{"retry-after" => ["12"]}, body: "busy"}} =
             HTTP.request(:get, "https://example.com/", [], "", transport: transport)

    assert {:error, :response_too_large} =
             HTTP.request(:get, "https://example.com/", [], "",
               transport: transport,
               max_body_bytes: 2
             )
  end

  test "caller-owned account and leaf keys produce valid distinct keys and signed CSR" do
    assert {:ok, account} = Keys.generate()
    assert {:ok, leaf} = Keys.generate()
    refute account.private_key_pem == leaf.private_key_pem

    assert {:ok, %{der: der, sha256: digest}} =
             Keys.csr(leaf.private_key_pem, ["example.com", "*.example.com"])

    assert X509.CSR.valid?(X509.CSR.from_der!(der))
    assert digest == Base.encode16(:crypto.hash(:sha256, der), case: :lower)

    assert account.thumbprint ==
             JOSE.JWK.from_pem(account.private_key_pem) |> JOSE.JWK.thumbprint()
  end

  test "DNS-01 uses the digest of key authorization" do
    key_authorization = "token.thumbprint"

    assert Client.dns_value("token", "thumbprint") ==
             Base.url_encode64(:crypto.hash(:sha256, key_authorization), padding: false)

    refute Client.dns_value("token", "thumbprint") == key_authorization
  end

  test "directory endpoint policy prevents remote URL substitution" do
    directory = %{
      "_directory_url" => "https://acme-staging-v02.api.letsencrypt.org/directory",
      "newNonce" => "https://evil.invalid/nonce"
    }

    assert {:error, :untrusted_acme_url} =
             Client.read_order(
               directory,
               %{key_pem: "bad", kid: "https://evil.invalid/account"},
               "https://evil.invalid/order"
             )
  end

  test "mutating requests use JWS, caller-owned key and bounded badNonce retry" do
    {:ok, key} = Keys.generate()
    {:ok, counter} = Agent.start_link(fn -> 0 end)
    on_exit(fn -> if Process.alive?(counter), do: Agent.stop(counter) end)
    directory_url = "https://acme-staging-v02.api.letsencrypt.org/directory"
    base = "https://acme-staging-v02.api.letsencrypt.org"

    directory = %{
      "_directory_url" => directory_url,
      "newNonce" => base <> "/nonce",
      "newOrder" => base <> "/orders"
    }

    account = %{key_pem: key.private_key_pem, kid: base <> "/account/1"}
    parent = self()

    transport = fn method, url, _headers, body, _opts ->
      case {method, URI.parse(url).path} do
        {:head, "/nonce"} ->
          {:ok, %{status: 200, headers: %{"replay-nonce" => ["fresh-nonce"]}, body: ""}}

        {:post, "/orders"} ->
          jws = JSON.decode!(body)
          send(parent, {:signed, jws})

          case Agent.get_and_update(counter, &{&1, &1 + 1}) do
            0 ->
              {:ok,
               %{
                 status: 400,
                 headers: %{"replay-nonce" => ["replacement"]},
                 body: JSON.encode!(%{"type" => "urn:ietf:params:acme:error:badNonce"})
               }}

            _ ->
              {:ok,
               %{
                 status: 201,
                 headers: %{"location" => [base <> "/order/1"]},
                 body: JSON.encode!(%{"status" => "pending"})
               }}
          end
      end
    end

    assert {:ok, %{location: location, body: %{"status" => "pending"}}} =
             Client.new_order(directory, account, ["example.com"], transport: transport)

    assert location == base <> "/order/1"
    assert Agent.get(counter, & &1) == 2
    assert_receive {:signed, jws}
    protected = jws["protected"] |> Base.url_decode64!(padding: false) |> JSON.decode!()
    assert protected["kid"] == account.kid
    refute Map.has_key?(protected, "jwk")
    assert protected["url"] == base <> "/orders"

    assert jws["payload"] |> Base.url_decode64!(padding: false) |> JSON.decode!() == %{
             "identifiers" => [%{"type" => "dns", "value" => "example.com"}]
           }
  end

  test "POST-as-GET signs an empty payload and does not retry ambiguous transport errors" do
    {:ok, key} = Keys.generate()
    base = "https://acme-v02.api.letsencrypt.org"
    directory = %{"_directory_url" => base <> "/directory", "newNonce" => base <> "/nonce"}
    account = %{key_pem: key.private_key_pem, kid: base <> "/account/1"}
    parent = self()

    transport = fn
      :head, _, _, _, _ ->
        {:ok, %{status: 200, headers: %{"replay-nonce" => ["nonce"]}, body: ""}}

      :post, _, _, body, _ ->
        assert JSON.decode!(body)["payload"] == ""
        send(parent, :called)
        {:error, :timeout}
    end

    assert {:error, %{kind: :transport, reason: :timeout, uncertain: true}} =
             Client.read_order(directory, account, base <> "/order/1", transport: transport)

    assert_receive :called
    refute_receive :called
  end

  test "terms are explicit and Retry-After supports seconds and HTTP dates" do
    assert {:error, :terms_not_accepted} = Client.register_account(%{}, "", [], false)
    now = ~U[2026-10-22 00:00:00Z]
    assert Client.retry_at(%{"retry-after" => ["60"]}, now) == DateTime.add(now, 60)

    assert Client.retry_at(%{"retry-after" => ["Thu, 22 Oct 2026 00:02:00 GMT"]}, now) ==
             DateTime.add(now, 120)
  end

  test "renewal fallback follows actual 90/64/45/6-day lifetimes" do
    start = ~U[2026-10-22 00:00:00Z]

    for days <- [90, 64, 45, 6] do
      finish = DateTime.add(start, days * 86_400)
      due = Renewal.fallback(start, finish, jitter: 0.5)
      expected = if days < 10, do: div(days * 86_400, 2), else: div(days * 86_400 * 2, 3)
      assert DateTime.diff(due, start) == expected
      assert DateTime.compare(due, finish) == :lt
    end
  end

  test "ARI windows choose a persisted point, refresh timing and reject invalid windows" do
    now = ~U[2026-10-22 00:00:00Z]

    body = %{
      "suggestedWindow" => %{"start" => "2026-10-24T00:00:00Z", "end" => "2026-10-26T00:00:00Z"}
    }

    assert {:ok, %{renew_at: ~U[2026-10-25 00:00:00Z], refresh_at: refresh}} =
             Renewal.window(body, %{"retry-after" => ["3600"]}, now: now, jitter: 0.5)

    assert refresh == DateTime.add(now, 3600)

    assert {:error, :invalid_renewal_window} =
             Renewal.window(
               %{
                 "suggestedWindow" => %{
                   "start" => "2026-10-26T00:00:00Z",
                   "end" => "2026-10-24T00:00:00Z"
                 }
               },
               %{},
               now: now
             )
  end

  test "account registration uses public JWK, while recovery preserves caller identity" do
    {:ok, key} = Keys.generate()
    base = "https://acme-v02.api.letsencrypt.org"

    directory = %{
      "_directory_url" => base <> "/directory",
      "newNonce" => base <> "/nonce",
      "newAccount" => base <> "/accounts"
    }

    transport = fn
      :head, _, _, _, _ ->
        {:ok, %{status: 200, headers: %{"replay-nonce" => ["nonce"]}, body: ""}}

      :post, _, _, encoded, _ ->
        jws = JSON.decode!(encoded)
        protected = jws["protected"] |> Base.url_decode64!(padding: false) |> JSON.decode!()
        assert protected["jwk"] == key.public_jwk
        refute Map.has_key?(protected, "kid")
        {true, payload, _} = JOSE.JWS.verify(JOSE.JWK.from_map(key.public_jwk), jws)
        payload = JSON.decode!(payload)
        assert payload["onlyReturnExisting"] == true or payload["termsOfServiceAgreed"] == true

        {:ok,
         %{
           status: 200,
           headers: %{"location" => [base <> "/account/existing"]},
           body: JSON.encode!(%{"status" => "valid"})
         }}
    end

    assert {:ok, %{location: location}} =
             Client.register_account(
               directory,
               key.private_key_pem,
               ["mailto:operator@example.com"],
               true,
               transport: transport
             )

    assert {:ok, %{location: ^location}} =
             Client.recover_account(directory, key.private_key_pem, transport: transport)
  end

  test "existing valid authorizations and delayed order states preserve CA evidence" do
    {:ok, key} = Keys.generate()
    base = "https://acme-v02.api.letsencrypt.org"
    directory = %{"_directory_url" => base <> "/directory", "newNonce" => base <> "/nonce"}
    account = %{key_pem: key.private_key_pem, kid: base <> "/account/1"}
    now = DateTime.utc_now()

    for state <- ["pending", "ready", "processing", "valid", "invalid"] do
      transport = fn
        :head, _, _, _, _ ->
          {:ok, %{status: 200, headers: %{"replay-nonce" => ["nonce"]}, body: ""}}

        :post, _, _, _, _ ->
          {:ok,
           %{
             status: 200,
             headers: %{"retry-after" => ["3"]},
             body: JSON.encode!(%{"status" => state})
           }}
      end

      assert {:ok, %{body: %{"status" => ^state}, retry_at: retry}} =
               Client.read_order(directory, account, base <> "/order/1", transport: transport)

      assert DateTime.diff(retry, now) in 3..5

      assert {:ok, %{body: %{"status" => ^state}}} =
               Client.authorization(directory, account, base <> "/authorization/1",
                 transport: transport
               )
    end
  end

  test "finalization errors are redacted and repeated badNonce is bounded" do
    {:ok, key} = Keys.generate()
    base = "https://acme-v02.api.letsencrypt.org"
    directory = %{"_directory_url" => base <> "/directory", "newNonce" => base <> "/nonce"}
    account = %{key_pem: key.private_key_pem, kid: base <> "/account/1"}
    parent = self()

    transport = fn
      :head, _, _, _, _ ->
        {:ok, %{status: 200, headers: %{"replay-nonce" => ["nonce"]}, body: ""}}

      :post, _, _, _, _ ->
        send(parent, :bad_nonce_request)

        {:ok,
         %{
           status: 400,
           headers: %{"replay-nonce" => ["nonce"]},
           body:
             JSON.encode!(%{
               "type" => "urn:ietf:params:acme:error:badNonce",
               "detail" => "sensitive body must never persist"
             })
         }}
    end

    assert {:error, %{type: "urn:ietf:params:acme:error:badNonce"} = problem} =
             Client.finalize(directory, account, base <> "/finalize/1", "CSR DER",
               transport: transport
             )

    refute Map.has_key?(problem, :detail)
    assert_receive :bad_nonce_request
    assert_receive :bad_nonce_request
    assert_receive :bad_nonce_request
    refute_receive :bad_nonce_request
  end

  test "revocation reports explicit rejection and never pretends a transport failure was confirmed" do
    {:ok, key} = Keys.generate()
    base = "https://acme-v02.api.letsencrypt.org"

    directory = %{
      "_directory_url" => base <> "/directory",
      "newNonce" => base <> "/nonce",
      "revokeCert" => base <> "/revoke"
    }

    account = %{key_pem: key.private_key_pem, kid: base <> "/account/1"}

    transport = fn
      :head, _, _, _, _ ->
        {:ok, %{status: 200, headers: %{"replay-nonce" => ["nonce"]}, body: ""}}

      :post, _, _, _, _ ->
        {:ok,
         %{
           status: 403,
           headers: %{},
           body:
             JSON.encode!(%{
               "type" => "urn:ietf:params:acme:error:unauthorized",
               "detail" => "credential-looking contents"
             })
         }}
    end

    assert {:error,
            %{status: 403, type: "urn:ietf:params:acme:error:unauthorized", uncertain: false}} =
             Client.revoke(directory, account, "DER", 0, transport: transport)

    assert {:error, :unsupported_revocation_reason} =
             Client.revoke(directory, account, "DER", 2, transport: transport)
  end
end
