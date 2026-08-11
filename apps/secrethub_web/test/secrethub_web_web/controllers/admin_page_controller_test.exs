defmodule SecretHub.Web.AdminPageControllerTest do
  use SecretHub.Web.ConnCase, async: false

  alias SecretHub.Web.AdminAuthController

  setup do
    previous_dev_mode = Application.get_env(:secrethub_web, :dev_mode)

    Application.put_env(:secrethub_web, :dev_mode, true)

    on_exit(fn ->
      Application.put_env(:secrethub_web, :dev_mode, previous_dev_mode)
    end)

    :ok
  end

  test "development password input uses input styling", %{conn: conn} do
    html =
      conn
      |> get(~p"/admin/auth/login")
      |> html_response(200)

    assert html =~
             ~r/<input(?=[^>]*id="dev_password")(?=[^>]*type="password")(?=[^>]*class="[^"]*\binput\b)[^>]*>/
  end

  test "protected admin browser routes still redirect to login", %{conn: conn} do
    conn = get(conn, ~p"/admin/dashboard")

    assert redirected_to(conn, 302) == ~p"/admin/auth/login"
  end

  test "malformed client certificates are rejected by admin APIs", %{conn: conn} do
    conn =
      conn
      |> init_test_session(%{})
      |> put_req_header("x-ssl-client-cert", "not-a-certificate")
      |> AdminAuthController.require_admin_api_auth([])

    assert conn.halted
    assert json_response(conn, 401) == %{"error" => "Admin authentication required"}
  end

  test "Bearer headers do not authenticate admin APIs", %{conn: conn} do
    conn =
      conn
      |> init_test_session(%{})
      |> put_req_header("authorization", "Bearer untrusted")
      |> AdminAuthController.require_admin_api_auth([])

    assert conn.halted
    assert json_response(conn, 401) == %{"error" => "Admin authentication required"}
  end

  test "raw certificate headers do not authenticate admin APIs", %{conn: conn} do
    conn =
      conn
      |> init_test_session(%{})
      |> put_req_header("x-ssl-client-cert", "untrusted certificate")
      |> AdminAuthController.require_admin_api_auth([])

    assert conn.halted
    assert json_response(conn, 401) == %{"error" => "Admin authentication required"}
  end

  test "raw certificate headers do not enable the certificate login form", %{conn: conn} do
    html =
      conn
      |> put_req_header("x-ssl-client-cert", "untrusted")
      |> get(~p"/admin/auth/login")
      |> html_response(200)

    refute html =~ "Client Certificate Detected"
    refute html =~ "Authenticate with Certificate"
    assert html =~ "No Client Certificate"
  end

  test "verified mTLS certificate assigns authenticate admin APIs", %{conn: conn} do
    conn =
      conn
      |> init_test_session(%{})
      |> assign(:mtls_authenticated, true)
      |> assign(:client_certificate, %{subject: "admin@example.com"})
      |> AdminAuthController.require_admin_api_auth([])

    refute conn.halted
    assert get_session(conn, :admin_id) == "admin"
  end

  test "malformed client certificates preserve browser redirects", %{conn: conn} do
    conn =
      conn
      |> put_req_header("x-ssl-client-cert", "not-a-certificate")
      |> get(~p"/admin/dashboard")

    assert redirected_to(conn, 302) == ~p"/admin/auth/login"
  end
end
