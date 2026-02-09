defmodule SecretHub.Web.ClusterStatusLiveTest do
  use SecretHub.Web.ConnCase, async: true
  import Phoenix.LiveViewTest

  setup %{conn: conn} do
    # Set up admin session so tests can access /admin routes
    conn =
      conn
      |> init_test_session(%{admin_id: "test-admin"})

    {:ok, conn: conn}
  end

  describe "ClusterStatusLive" do
    test "mounts successfully and displays page title", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/admin/cluster")

      # Check page title is present
      assert html =~ "Cluster Status"
    end

    test "shows error when ClusterState GenServer is not running", %{conn: conn} do
      # ClusterState GenServer is not started in test env
      # The LiveView should handle this gracefully and show an error
      {:ok, _view, html} = live(conn, "/admin/cluster")

      assert html =~ "Error loading cluster data" or
               html =~ "Cluster state service not available"
    end

    test "renders refresh buttons", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/admin/cluster")

      assert html =~ "Refresh Now"
      assert html =~ "Auto-refresh"
    end

    test "toggle auto-refresh button works", %{conn: conn} do
      {:ok, view, html} = live(conn, "/admin/cluster")

      # Initially auto-refresh should be ON
      assert html =~ "Auto-refresh ON"

      # Click toggle button
      html = render_click(view, "toggle_refresh")

      # Should now be OFF
      assert html =~ "Auto-refresh OFF"

      # Click again to turn back ON
      html = render_click(view, "toggle_refresh")

      assert html =~ "Auto-refresh ON"
    end

    test "refresh now button works without crash", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/admin/cluster")

      # Click refresh now - should not crash even though ClusterState isn't running
      html = render_click(view, "refresh_now")

      assert html =~ "Cluster Status"
    end
  end
end
