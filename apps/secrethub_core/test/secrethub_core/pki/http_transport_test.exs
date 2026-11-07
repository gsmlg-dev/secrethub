defmodule SecretHub.Core.PKI.HTTPTransportTest do
  use ExUnit.Case, async: true

  alias SecretHub.Core.PKI.HTTP, as: PKIHTTP

  test "consumes acknowledged chunks and preserves duplicate response headers" do
    url =
      serve(fn socket ->
        :ok =
          :gen_tcp.send(socket, [
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-Test: one\r\nX-Test: two\r\n\r\n",
            "3\r\none\r\n3\r\ntwo\r\n0\r\n\r\n"
          ])
      end)

    assert {:ok, %{status: 200, body: "onetwo", headers: %{"x-test" => ["one", "two"]}}} =
             PKIHTTP.request(:get, url, [], "", test_mode: true, test_cacerts: [])
  end

  test "rejects oversized fixed-length and chunked responses while reading" do
    for response <- [
          "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecret",
          "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nsec\r\n3\r\nret\r\n0\r\n\r\n"
        ] do
      url = serve(fn socket -> :ok = :gen_tcp.send(socket, response) end)

      assert {:error, :response_too_large} =
               PKIHTTP.request(:get, url, [], "",
                 test_mode: true,
                 test_cacerts: [],
                 max_body_bytes: 5
               )
    end
  end

  test "returns redirects without following them" do
    url =
      serve(fn socket ->
        :ok =
          :gen_tcp.send(
            socket,
            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/leak\r\nContent-Length: 0\r\n\r\n"
          )
      end)

    assert {:ok, %{status: 302, body: ""}} =
             PKIHTTP.request(:get, url, [], "", test_mode: true, test_cacerts: [])
  end

  test "fails incomplete bodies instead of accepting a successful status" do
    url =
      serve(fn socket ->
        :ok = :gen_tcp.send(socket, "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort")
      end)

    assert {:error, _reason} =
             PKIHTTP.request(:get, url, [], "", test_mode: true, test_cacerts: [])
  end

  for {protocol, ca_alert, hostname_alert} <- [
        {:"tlsv1.2", :bad_certificate, :bad_certificate},
        {:"tlsv1.3", :unknown_ca, :certificate_unknown}
      ] do
    test "trusts an explicitly supplied CA over real #{protocol}" do
      {identity, ca} = tls_identity("localhost")
      url = serve_tls(identity, unquote(protocol))

      assert {:ok, %{status: 200, body: "trusted"}} =
               PKIHTTP.request(:get, url, [], "", test_mode: true, test_cacerts: [ca])
    end

    test "rejects a server signed by an untrusted CA over real #{protocol}" do
      {identity, _ca} = tls_identity("localhost")
      {_identity, unrelated_ca} = tls_identity("unrelated.invalid")
      url = serve_tls(identity, unquote(protocol))
      expected_alert = unquote(ca_alert)

      assert {:error, {:tls_alert, {^expected_alert, _description}}} =
               PKIHTTP.request(:get, url, [], "", test_mode: true, test_cacerts: [unrelated_ca])
    end

    test "rejects a trusted server with the wrong hostname over real #{protocol}" do
      {identity, ca} = tls_identity("wrong.localhost")
      url = serve_tls(identity, unquote(protocol))
      expected_alert = unquote(hostname_alert)

      assert {:error, {:tls_alert, {^expected_alert, _description}}} =
               PKIHTTP.request(:get, url, [], "", test_mode: true, test_cacerts: [ca])
    end
  end

  defp tls_identity(hostname) do
    ca_key = X509.PrivateKey.new_ec(:secp256r1)
    ca = X509.Certificate.self_signed(ca_key, "/CN=HTTP transport test CA", template: :root_ca)
    key = X509.PrivateKey.new_ec(:secp256r1)

    certificate =
      X509.Certificate.new(X509.PublicKey.derive(key), "/CN=#{hostname}", ca, ca_key,
        template: :server,
        extensions: [subject_alt_name: X509.Certificate.Extension.subject_alt_name([hostname])]
      )

    identity = [
      cert: X509.Certificate.to_der(certificate),
      key: {elem(key, 0), :public_key.der_encode(elem(key, 0), key)}
    ]

    {identity, X509.Certificate.to_der(ca)}
  end

  defp serve_tls(identity, protocol) do
    {:ok, _apps} = Application.ensure_all_started(:ssl)

    {:ok, listener} =
      :ssl.listen(
        0,
        [:binary, active: false, ip: {127, 0, 0, 1}, versions: [protocol]] ++ identity
      )

    {:ok, {_ip, port}} = :ssl.sockname(listener)

    server =
      spawn_link(fn ->
        {:ok, socket} = :ssl.transport_accept(listener, 5_000)

        try do
          case :ssl.handshake(socket, 5_000) do
            {:ok, socket} ->
              assert {:ok, [protocol: ^protocol]} =
                       :ssl.connection_information(socket, [:protocol])

              {:ok, _request} = :ssl.recv(socket, 0, 5_000)
              :ok = :ssl.send(socket, "HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ntrusted")

            {:error, {:tls_alert, _alert}} ->
              :ok
          end
        after
          :ssl.close(socket)
        end
      end)

    on_exit(fn ->
      :ssl.close(listener)
      if Process.alive?(server), do: Process.exit(server, :kill)
    end)

    "https://localhost:#{port}/directory"
  end

  defp serve(reply) do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, {_ip, port}} = :inet.sockname(listener)

    server =
      spawn_link(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 5_000)

        try do
          {:ok, _request} = :gen_tcp.recv(socket, 0, 5_000)
          reply.(socket)
        after
          :gen_tcp.close(socket)
        end
      end)

    on_exit(fn ->
      :gen_tcp.close(listener)
      if Process.alive?(server), do: Process.exit(server, :kill)
    end)

    "http://127.0.0.1:#{port}/directory"
  end
end
