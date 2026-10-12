defmodule SecretHub.Web.ManagementIngressTest do
  use ExUnit.Case, async: true

  import Plug.Conn

  alias SecretHub.Web.Plugs.ManagementIngress

  defmodule DevelopmentEndpoint do
    def config(:development_direct_access, _default), do: true
    def config(:trusted_proxy_ips, default), do: default
    def config(:check_origin), do: :conn
    def url, do: "http://localhost:4664"
  end

  defmodule ProxyEndpoint do
    def config(_key, default), do: default
    def config(:check_origin), do: ["https://admin.example.test"]
    def url, do: "https://admin.example.test"
  end

  test "the explicit development exception admits private LAN peers as operators" do
    for peer <- [{10, 100, 10, 20}, {172, 16, 0, 1}, {172, 31, 255, 254}, {192, 168, 1, 2}] do
      conn =
        request(peer)
        |> put_req_header("origin", "http://10.100.10.10:4664")
        |> ManagementIngress.call(DevelopmentEndpoint)

      refute conn.halted

      assert %{type: "operator", id: "operator", external_id: "operator"} =
               conn.assigns.current_actor

      assert get_resp_header(conn, "cache-control") == ["no-store"]
    end
  end

  test "the development exception rejects public peers and private range neighbors" do
    for peer <- [{203, 0, 113, 1}, {172, 15, 255, 254}, {172, 32, 0, 1}, {192, 169, 1, 2}] do
      conn =
        request(peer)
        |> put_req_header("x-forwarded-for", "10.100.10.20")
        |> put_req_header("x-ssl-client-verify", "SUCCESS")
        |> ManagementIngress.call(DevelopmentEndpoint)

      assert conn.status == 403
      assert conn.halted
    end
  end

  test "private LAN peers remain forbidden without the development exception" do
    conn =
      request({10, 100, 10, 20})
      |> put_req_header("origin", "https://admin.example.test")
      |> ManagementIngress.call(ProxyEndpoint)

    assert conn.status == 403
    assert conn.halted
  end

  test "development requests still reject cross-origin and duplicate Origin headers" do
    for origins <- [
          ["https://10.100.10.10:4664"],
          ["http://attacker.example:4664"],
          ["http://10.100.10.10:4665"],
          ["null"],
          ["http://10.100.10.10:4664", "http://10.100.10.10:4664"]
        ] do
      conn = request({10, 100, 10, 20})
      conn = %{conn | req_headers: Enum.map(origins, &{"origin", &1})}
      conn = ManagementIngress.call(conn, DevelopmentEndpoint)

      assert conn.status == 403
      assert conn.halted
    end
  end

  test "development same-origin access also works on loopback and the default HTTP port" do
    for url <- ["http://localhost:4664", "http://127.0.0.1:4664", "http://10.100.10.10"] do
      conn =
        Plug.Test.conn(:get, url <> "/")
        |> put_req_header("origin", url)
        |> ManagementIngress.call(DevelopmentEndpoint)

      refute conn.halted
    end
  end

  defp request(peer) do
    Plug.Test.conn(:get, "http://10.100.10.10:4664/")
    |> Map.put(:remote_ip, peer)
  end
end
