defmodule SecretHub.Web.PolicyEditorLiveTest do
  use SecretHub.Web.ConnCase, async: false

  import Phoenix.LiveViewTest

  setup %{conn: conn} do
    conn = init_test_session(conn, %{admin_id: "test-admin"})

    {:ok, conn: conn}
  end

  test "adds an allowed secret pattern from the input control", %{conn: conn} do
    {:ok, view, _html} = live(conn, "/admin/policies/new")

    view
    |> element("button[phx-value-tab='secrets']", "Allowed Secrets")
    |> render_click()

    html =
      view
      |> form("#secret-pattern-form", %{"pattern" => "prod.db.*"})
      |> render_submit()

    assert html =~ "prod.db.*"
    assert html =~ "&quot;allowed_secrets&quot;: ["
    refute html =~ "No patterns added yet"
  end
end
