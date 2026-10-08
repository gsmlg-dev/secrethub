defmodule SecretHub.Web.ProxyOriginIntegrationTest do
  use ExUnit.Case, async: false

  alias SecretHub.Web.Endpoint

  @root Path.expand("../../../..", __DIR__)
  @origins ["https://secrethub.example.test", "https://admin.example.test:8443"]
  @env %{
    "RELEASE_DISTRIBUTION" => "none",
    "SECRETHUB_ROLE" => "core",
    "PHX_SERVER" => nil,
    "SECRET_HUB_AGENT_ENDPOINT_SERVER" => nil,
    "SECRET_HUB_ADMIN_ENDPOINT_SERVER" => nil,
    "SECRET_HUB_CLUSTER_NODE_ID" => "proxy-origin-test",
    "DATABASE_URL" => "postgresql://fixture:fixture@localhost/fixture",
    "SECRET_KEY_BASE" => String.duplicate("x", 64),
    "AUDIT_HMAC_KEY" => Base.encode64(String.duplicate("k", 32)),
    "AUDIT_HMAC_KEY_ID" => "fixture",
    "SECRET_HUB_MANAGEMENT_ORIGIN" => hd(@origins),
    "SECRET_HUB_MANAGEMENT_ALLOWED_ORIGINS" => Enum.join(@origins, ","),
    "SECRET_HUB_MANAGEMENT_BIND_IP" => "127.0.0.1",
    "SECRET_HUB_TRUSTED_PROXY_IP" => "127.0.0.1",
    "PORT" => "4664",
    "SECRET_HUB_MACHINE_PORT" => "4668",
    "SECRET_HUB_AGENT_ENDPOINT_PORT" => "4665"
  }

  setup do
    saved_env = Map.new(@env, fn {key, _} -> {key, System.get_env(key)} end)
    old_config = Application.fetch_env!(:secrethub_web, Endpoint)
    set_env(@env)

    on_exit(fn ->
      set_env(saved_env)
      Endpoint.config_change([{Endpoint, old_config}], [])
    end)

    config = Config.Reader.read!(Path.join(@root, "config/core_runtime.exs"), env: :prod)
    runtime_config = config[:secrethub_web][Endpoint]
    Endpoint.config_change([{Endpoint, Keyword.merge(old_config, runtime_config)}], [])

    server = start_supervised!({Bandit, plug: Endpoint, ip: {127, 0, 0, 1}, port: 0})
    {:ok, {_ip, port}} = ThousandIsland.listener_info(server)
    {:ok, port: port}
  end

  test "production origins work over HTTP for WebSocket and longpoll on both hosts", %{port: port} do
    for origin <- @origins do
      assert request(port, "/live/websocket?vsn=2.0.0", origin) == 101
      assert request(port, "/live/longpoll?vsn=2.0.0", origin) == 200
    end
  end

  test "unrelated origins, HTTP origins and wrong ports fail despite forwarded headers", %{
    port: port
  } do
    for origin <- [
          "https://unrelated.example.test",
          "http://secrethub.example.test",
          "https://admin.example.test",
          "https://secrethub.example.test:8443",
          "https://secrethub.example.test.attacker.test",
          "null"
        ],
        path <- ["/live/websocket?vsn=2.0.0", "/live/longpoll?vsn=2.0.0"] do
      assert request(port, path, origin) == 403
    end
  end

  test "an allowed origin and forged proxy headers cannot authorize another transport peer" do
    for path <- ["/live/websocket?vsn=2.0.0", "/live/longpoll?vsn=2.0.0"] do
      conn =
        Plug.Test.conn(:get, "http://secrethub.example.test" <> path)
        |> Map.put(:remote_ip, {203, 0, 113, 1})
        |> Plug.Conn.put_req_header("origin", hd(@origins))
        |> Plug.Conn.put_req_header("x-forwarded-for", "127.0.0.1")
        |> Plug.Conn.put_req_header("x-forwarded-proto", "https")
        |> Endpoint.call(Endpoint.init([]))

      assert conn.status == 403
      assert conn.halted
    end
  end

  defp request(port, path, origin) do
    {:ok, socket} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false], 5_000)

    upgrade =
      if String.contains?(path, "websocket") do
        "Connection: Upgrade\r\nUpgrade: websocket\r\n" <>
          "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
      else
        "Connection: close\r\n"
      end

    :ok =
      :gen_tcp.send(socket, [
        "GET ",
        path,
        " HTTP/1.1\r\nHost: ",
        URI.parse(origin).authority || "localhost",
        "\r\nOrigin: ",
        origin,
        "\r\nX-Forwarded-Proto: https\r\nX-Forwarded-Host: secrethub.example.test\r\n",
        upgrade,
        "\r\n"
      ])

    response = receive_headers(socket, "")
    :gen_tcp.close(socket)
    [_, status | _] = String.split(response, " ", parts: 3)
    String.to_integer(status)
  end

  defp receive_headers(socket, response) do
    if String.contains?(response, "\r\n\r\n") do
      response
    else
      {:ok, data} = :gen_tcp.recv(socket, 0, 5_000)
      receive_headers(socket, response <> data)
    end
  end

  defp set_env(values) do
    for {key, value} <- values do
      if value, do: System.put_env(key, value), else: System.delete_env(key)
    end
  end
end
