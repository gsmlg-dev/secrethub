defmodule SecretHub.Core.PKI.ACME.PebbleTest do
  use ExUnit.Case, async: false

  alias SecretHub.Core.PKI.ACME.{CertificateValidation, Client, Keys, Renewal}
  alias SecretHub.Core.PKI.HTTP

  @moduletag :pebble
  @moduletag skip: is_nil(System.get_env("SECRETHUB_PEBBLE_DIRECTORY"))
  @moduletag timeout: 120_000

  test "real native TLS/JWS DNS-01 issuance, ARI replacement, revocation and TXT cleanup" do
    Application.ensure_all_started(:req)
    tls_pem = File.read!(System.fetch_env!("SECRETHUB_PEBBLE_TLS_CERT"))
    [{:Certificate, tls_root, :not_encrypted}] = :public_key.pem_decode(tls_pem)
    opts = [test_mode: true, test_cacerts: [tls_root]]
    directory_url = System.fetch_env!("SECRETHUB_PEBBLE_DIRECTORY")
    management = System.fetch_env!("SECRETHUB_PEBBLE_MANAGEMENT")
    dns_api = System.fetch_env!("SECRETHUB_PEBBLE_DNS_API")
    assert {:ok, directory} = Client.directory(directory_url, opts)
    assert {:ok, account_key} = Keys.generate()

    assert {:ok, registered} =
             Client.register_account(
               directory,
               account_key.private_key_pem,
               ["mailto:acme@example.test"],
               true,
               opts
             )

    assert is_binary(registered.location)
    account = %{key_pem: account_key.private_key_pem, kid: registered.location}
    assert {:ok, recovered} = Client.recover_account(directory, account.key_pem, opts)
    assert recovered.location == account.kid
    assert {:ok, %{body: root_pem}} = HTTP.request(:get, management <> "/roots/0", [], "", opts)
    [{:Certificate, issuance_root, :not_encrypted}] = :public_key.pem_decode(root_pem)
    validation_opts = Keyword.put(opts, :test_issuance_cacerts, [issuance_root])
    names = ["*.native-acme.example.test", "native-acme.example.test"]

    first = issue(directory, account, names, dns_api, opts, validation_opts)
    assert {:ok, ari} = Client.renewal_info(directory, first.ari_certificate_id, opts)
    assert {:ok, window} = Renewal.window(ari.body, ari.headers)
    assert DateTime.compare(window.window_start, window.window_end) == :lt

    replacement =
      issue(
        directory,
        account,
        names,
        dns_api,
        Keyword.put(opts, :replaces, first.ari_certificate_id),
        validation_opts
      )

    refute first.fingerprint_sha256 == replacement.fingerprint_sha256

    assert {:ok, %{status: status}} =
             Client.revoke(directory, account, first.certificate_der, 0, opts)

    assert status in [200, 201]
    # A second call has explicit alreadyRevoked evidence rather than assumed success.
    assert {:error, %{type: "urn:ietf:params:acme:error:alreadyRevoked"}} =
             Client.revoke(directory, account, first.certificate_der, 0, opts)

    owner = "_acme-challenge.native-acme.example.test."

    assert [] ==
             :inet_res.lookup(String.to_charlist(owner), :in, :txt,
               nameservers: [
                 {{127, 0, 0, 1},
                  String.to_integer(System.fetch_env!("SECRETHUB_PEBBLE_DNS_PORT"))}
               ],
               timeout: 1000
             )

    IO.puts(
      "Pebble native lifecycle: issuance=#{first.fingerprint_sha256} renewal=#{replacement.fingerprint_sha256}; revocation confirmed; DNS cleanup confirmed"
    )
  end

  defp issue(directory, account, names, dns_api, opts, validation_opts) do
    assert {:ok, key} = Keys.generate()
    assert {:ok, csr} = Keys.csr(key.private_key_pem, names)
    assert {:ok, created} = Client.new_order(directory, account, names, opts)
    assert is_binary(created.location)

    owners =
      Enum.reduce(created.body["authorizations"], [], fn url, owners ->
        assert {:ok, authorization} = Client.authorization(directory, account, url, opts)

        if authorization.body["status"] == "valid" do
          owners
        else
          challenge = Enum.find(authorization.body["challenges"], &(&1["type"] == "dns-01"))
          owner = "_acme-challenge." <> authorization.body["identifier"]["value"] <> "."

          value =
            Client.dns_value(
              challenge["token"],
              JOSE.JWK.from_pem(account.key_pem) |> JOSE.JWK.thumbprint()
            )

          assert {:ok, %{status: 200}} =
                   HTTP.request(
                     :post,
                     dns_api <> "/set-txt",
                     [{"content-type", "application/json"}],
                     JSON.encode!(%{"host" => owner, "value" => value}),
                     opts
                   )

          # Exercise public DNS rather than provider acknowledgment alone.
          port = System.fetch_env!("SECRETHUB_PEBBLE_DNS_PORT") |> String.to_integer()

          values =
            :inet_res.lookup(String.to_charlist(owner), :in, :txt,
              nameservers: [{{127, 0, 0, 1}, port}],
              timeout: 1000
            )

          assert Enum.any?(values, &(IO.iodata_to_binary(&1) == value))
          assert {:ok, _} = Client.acknowledge(directory, account, challenge["url"], opts)
          [owner | owners]
        end
      end)

    ready =
      poll(fn -> Client.read_order(directory, account, created.location, opts) end, [
        "ready",
        "valid"
      ])

    if ready.body["status"] == "ready" do
      assert {:ok, _} = Client.finalize(directory, account, ready.body["finalize"], csr.der, opts)
    end

    issued =
      poll(fn -> Client.read_order(directory, account, created.location, opts) end, ["valid"])

    assert {:ok, %{body: fullchain}} =
             Client.download(directory, account, issued.body["certificate"], opts)

    assert {:ok, material} =
             CertificateValidation.validate(
               fullchain,
               key.private_key_pem,
               names,
               "staging",
               validation_opts
             )

    for owner <- Enum.uniq(owners) do
      assert {:ok, %{status: 200}} =
               HTTP.request(
                 :post,
                 dns_api <> "/clear-txt",
                 [{"content-type", "application/json"}],
                 JSON.encode!(%{"host" => owner}),
                 opts
               )
    end

    material
  end

  defp poll(fun, acceptable, attempts \\ 200)
  defp poll(_fun, _acceptable, 0), do: flunk("Pebble polling deadline exceeded")

  defp poll(fun, acceptable, attempts) do
    assert {:ok, response} = fun.()

    case response.body["status"] do
      "invalid" ->
        flunk("Pebble rejected an order")

      status ->
        if status in acceptable do
          response
        else
          Process.sleep(100)
          poll(fun, acceptable, attempts - 1)
        end
    end
  end
end
