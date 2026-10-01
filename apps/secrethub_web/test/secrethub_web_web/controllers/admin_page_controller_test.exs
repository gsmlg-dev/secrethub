defmodule SecretHub.Web.AdminPageControllerTest do
  use SecretHub.Web.ConnCase, async: false

  setup do
    Ecto.Adapters.SQL.Sandbox.mode(SecretHub.Core.Repo, {:shared, self()})
    start_supervised!(SecretHub.Core.Vault.SealState)
    await_loaded(200)
    :ok
  end

  test "protected ingress opens management without a login or authentication session", %{
    conn: conn
  } do
    conn = get(conn, "/admin")

    assert redirected_to(conn) == "/admin/dashboard"
    refute get_session(conn, :admin_id)
    refute get_session(conn, :admin_authenticated)
    assert get_resp_header(conn, "cache-control") == ["no-store"]
  end

  test "direct untrusted peers cannot access management even with forged identity headers", %{
    conn: conn
  } do
    conn =
      conn
      |> Map.put(:remote_ip, {203, 0, 113, 12})
      |> init_test_session(%{admin_id: "admin", admin_authenticated: true})
      |> put_req_header("x-forwarded-for", "127.0.0.1")
      |> put_req_header("x-ssl-client-verify", "SUCCESS")
      |> put_req_header("x-ssl-client-cert", "admin")
      |> Map.put(:host, "localhost")
      |> get("/admin")

    assert conn.status == 403
    assert conn.halted
  end

  test "untrusted peers cannot reach management APIs, vault or either LiveView transport" do
    for {method, path} <- [
          {:get, "/admin/api/dashboard/stats"},
          {:post, "/v1/sys/init"},
          {:post, "/v1/sys/unseal"},
          {:post, "/v1/auth/approle/role/example"},
          {:post, "/v1/pki/client-auth/authority/init"},
          {:post, "/v1/pki/ca/root/generate"},
          {:post, "/v1/apps"},
          {:get, "/live/websocket"},
          {:get, "/live/longpoll"}
        ] do
      conn =
        build_conn()
        |> Map.put(:remote_ip, {203, 0, 113, 12})
        |> dispatch(SecretHub.Web.Endpoint, method, path, %{})

      assert conn.status == 403, "untrusted peer reached #{path}"
    end
  end

  test "cross-origin management mutations are rejected before controller work" do
    for path <- ["/v1/sys/init", "/v1/sys/unseal", "/v1/apps", "/admin/api/actions/rotate-leases"] do
      conn =
        build_conn()
        |> put_req_header("origin", "https://attacker.invalid")
        |> post(path, %{})

      assert conn.status == 403
    end
  end

  test "management API mutations require a CSRF token" do
    assert_raise Plug.CSRFProtection.InvalidCSRFTokenError, fn ->
      build_conn()
      |> put_private(:plug_skip_csrf_protection, false)
      |> post("/v1/sys/init", %{})
    end
  end

  test "untrusted LiveView origins are rejected on websocket and longpoll" do
    for path <- ["/live/websocket?vsn=2.0.0", "/live/longpoll?vsn=2.0.0"] do
      conn =
        build_conn()
        |> put_req_header("origin", "https://attacker.invalid")
        |> get(path)

      assert conn.status == 403
    end
  end

  test "management API rejects shares above the v4 public limit" do
    conn = post(build_conn(), "/v1/sys/init", %{"secret_shares" => 252, "secret_threshold" => 2})
    assert json_response(conn, 400) == %{"error" => "secret_shares must be between 1 and 251"}
  end

  defp await_loaded(0), do: flunk("Vault state did not finish loading")

  defp await_loaded(attempts) do
    if SecretHub.Core.Vault.SealState.status().state == :loading do
      Process.sleep(5)
      await_loaded(attempts - 1)
    else
      :ok
    end
  end
end
