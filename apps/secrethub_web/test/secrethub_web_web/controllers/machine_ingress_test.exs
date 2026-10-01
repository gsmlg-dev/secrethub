defmodule SecretHub.Web.MachineIngressTest do
  use SecretHub.Web.ConnCase, async: false

  setup do
    if is_nil(Process.whereis(SecretHub.Web.AgentEndpoint)) do
      start_supervised!(SecretHub.Web.AgentEndpoint)
    end

    :ok
  end

  @management_paths [
    {:get, "/admin"},
    {:get, "/admin/dashboard"},
    {:get, "/admin/api/dashboard/stats"},
    {:get, "/vault/init"},
    {:get, "/vault/unseal"},
    {:post, "/v1/sys/init"},
    {:post, "/v1/sys/unseal"},
    {:post, "/v1/sys/seal"},
    {:get, "/v1/sys/csrf-token"},
    {:post, "/v1/auth/approle/role/example"},
    {:get, "/v1/auth/approle/role"},
    {:post, "/v1/pki/ca/root/generate"},
    {:post, "/v1/pki/sign-request"},
    {:post, "/v1/pki/app/revoke"},
    {:post, "/v1/pki/client-auth/authority/init"},
    {:get, "/v1/pki/client-auth/identities"},
    {:post, "/v1/apps"},
    {:get, "/live/websocket?vsn=2.0.0"},
    {:get, "/live/longpoll?vsn=2.0.0"}
  ]

  test "exposed machine listener cannot route management operations despite forged credentials" do
    for {method, path} <- @management_paths do
      conn =
        build_conn()
        |> Map.put(:host, "localhost")
        |> put_req_header("x-forwarded-for", "127.0.0.1")
        |> put_req_header("x-ssl-client-verify", "SUCCESS")
        |> put_req_header("x-ssl-client-cert", "operator")
        |> put_req_header("x-vault-token", "forged-admin-token")
        |> dispatch(SecretHub.Web.MachineEndpoint, method, path, %{})

      assert conn.status == 404, "machine listener routed #{path}"
    end
  end

  test "every browser and management API route is absent from machine ingress" do
    management_routes =
      Enum.filter(SecretHub.Web.Router.__routes__(), fn route ->
        path = Regex.replace(~r/[:*][a-zA-Z_]+/, route.path, "example")
        method = route.verb |> to_string() |> String.upcase()
        info = Phoenix.Router.route_info(SecretHub.Web.Router, method, path, "localhost")
        Enum.any?(info.pipe_through, &(&1 in [:browser, :admin_browser, :admin_api]))
      end)

    assert length(management_routes) > 60

    for route <- management_routes do
      path = Regex.replace(~r/[:*][a-zA-Z_]+/, route.path, "example")
      conn = dispatch(build_conn(), SecretHub.Web.MachineEndpoint, route.verb, path, %{})
      assert conn.status == 404, "machine listener routed #{route.verb} #{route.path}"
    end
  end

  test "Agent runtime listener cannot route HTTP management or LiveView" do
    for {method, path} <- @management_paths do
      conn = dispatch(build_conn(), SecretHub.Web.AgentEndpoint, method, path, %{})
      assert conn.status == 404
    end
  end

  test "machine APIs still reject missing credentials" do
    for {method, path} <- [
          {:get, "/v1/secret/data/example"},
          {:get, "/v1/apps"},
          {:get, "/v1/pki/certificates"},
          {:post, "/v1/agent/certificate/renew"},
          {:post, "/v1/sys/leases/renew"}
        ] do
      conn = dispatch(build_conn(), SecretHub.Web.MachineEndpoint, method, path, %{})
      assert conn.status == 401, "machine authentication bypass on #{path}"
      assert get_resp_header(conn, "cache-control") == ["no-store"]
    end
  end

  test "agent runtime rejects client-supplied identity without a peer certificate" do
    socket = %Phoenix.Socket{endpoint: SecretHub.Web.AgentEndpoint}

    assert :error =
             SecretHub.Web.AgentTrustedSocket.connect(
               %{"agent_id" => "operator", "token" => "forged"},
               socket,
               %{x_headers: [{"x-ssl-client-verify", "SUCCESS"}]}
             )
  end

  test "machine enrollment remains reachable without management authorization" do
    conn =
      dispatch(build_conn(), SecretHub.Web.MachineEndpoint, :post, "/v1/agent/enrollments", %{})

    assert conn.status == 400
  end
end
