defmodule SecretHub.Web.AdminSidebarLiveTest do
  use SecretHub.Web.ConnCase, async: true

  import Phoenix.LiveViewTest

  alias SecretHub.Web.AdminSidebarLive

  test "attaches independent tooltips to the native navigation links", %{conn: conn} do
    {:ok, view, _html} = live_isolated(conn, AdminSidebarLive)

    for {path, id, label} <- [
          {"/admin/dashboard", "sidebar-menu-dashboard-tooltip", "Dashboard"},
          {"/admin/secrets", "sidebar-menu-secrets-tooltip", "Secrets"}
        ] do
      assert has_element?(
               view,
               "a[href='#{path}'][aria-label='#{label}'][aria-describedby='#{id}'][interestfor='#{id}'][data-phx-link='redirect'][style='anchor-name: --anchor-#{id}']"
             )

      assert has_element?(view, "span[id='#{id}'][popover='hint'][role='tooltip']", label)
    end

    refute has_element?(view, "a [role='tooltip']")
  end

  test "selects the initial active link from the session", %{conn: conn} do
    {:ok, view, _html} =
      live_isolated(conn, AdminSidebarLive, session: %{"active_nav" => "secrets"})

    assert has_element?(view, "a[href='/admin/secrets'][aria-current='page']")
    assert has_element?(view, "a[href='/admin/secrets'][class~='active']")
    refute has_element?(view, "a[href='/admin/dashboard'][aria-current='page']")
  end

  test "updates the active link while preserving navigation destinations", %{conn: conn} do
    {:ok, view, _html} = live_isolated(conn, AdminSidebarLive)

    assert has_element?(view, "a[href='/admin/dashboard'][aria-current='page']")

    render_hook(view, "set_active_nav", %{"active_nav" => "secrets"})

    assert has_element?(view, "a[href='/admin/secrets'][aria-current='page']")
    assert has_element?(view, "a[href='/admin/secrets'][class~='active']")
    assert has_element?(view, "a[href='/admin/dashboard']")
    refute has_element?(view, "a[href='/admin/dashboard'][aria-current='page']")
    refute has_element?(view, "a[href='/admin/dashboard'][class~='active']")
  end

  test "ignores unknown active links and malformed payloads", %{conn: conn} do
    {:ok, view, _html} =
      live_isolated(conn, AdminSidebarLive, session: %{"active_nav" => "secrets"})

    for payload <- [
          %{"active_nav" => "unknown"},
          %{"active_nav" => nil},
          %{"active_nav" => ["dashboard"]},
          %{}
        ] do
      render_hook(view, "set_active_nav", payload)

      assert has_element?(view, "a[href='/admin/secrets'][aria-current='page']")
      assert has_element?(view, "a[href='/admin/secrets'][class~='active']")
      refute has_element?(view, "a[href='/admin/dashboard'][aria-current='page']")
    end
  end
end
