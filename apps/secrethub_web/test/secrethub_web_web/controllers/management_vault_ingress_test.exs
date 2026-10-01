defmodule SecretHub.Web.ManagementVaultIngressTest do
  use SecretHub.Web.ConnCase, async: false

  import Phoenix.LiveViewTest

  alias Ecto.Adapters.SQL.Sandbox
  alias SecretHub.Core.Repo
  alias SecretHub.Core.Vault.SealState

  setup do
    Sandbox.mode(Repo, {:shared, self()})
    start_supervised!(SealState)
    await_loaded(200)
    :ok
  end

  test "protected initialization and manual unseal work while sealed, without login state" do
    assert SealState.sealed?()

    csrf_conn = get(build_conn(), "/v1/sys/csrf-token")
    csrf_token = json_response(csrf_conn, 200)["csrf_token"]
    assert is_binary(csrf_token)
    refute get_session(csrf_conn, :admin_id)

    conn =
      csrf_conn
      |> recycle()
      |> put_private(:plug_skip_csrf_protection, false)
      |> put_req_header("x-csrf-token", csrf_token)
      |> post("/v1/sys/init", %{"secret_shares" => 3, "secret_threshold" => 2})

    %{"shares" => [first, second, _]} = json_response(conn, 200)
    assert get_resp_header(conn, "cache-control") == ["no-store"]
    assert SealState.sealed?()

    for share <- [first, second] do
      conn =
        csrf_conn
        |> recycle()
        |> put_private(:plug_skip_csrf_protection, false)
        |> put_req_header("x-csrf-token", csrf_token)
        |> post("/v1/sys/unseal", %{"share" => share})

      assert conn.status == 200
      assert get_resp_header(conn, "cache-control") == ["no-store"]
    end

    refute SealState.sealed?()
  end

  test "connected vault workflow has no second administrator login" do
    assert {:ok, view, html} = live(build_conn(), "/vault/init")
    assert html =~ "Initialize"
    assert render(view) =~ "Initialize"
  end

  test "sealed vault pages are available through the management ingress" do
    assert build_conn() |> get("/vault/init") |> html_response(200) =~ "Initialize"
    assert build_conn() |> get("/vault/unseal") |> html_response(200) =~ "Unseal"
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
