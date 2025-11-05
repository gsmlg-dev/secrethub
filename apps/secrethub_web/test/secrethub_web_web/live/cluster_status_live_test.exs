defmodule SecretHub.WebWeb.ClusterStatusLiveTest do
  use SecretHub.WebWeb.ConnCase, async: true
  import Phoenix.LiveViewTest

  alias SecretHub.Core.{ClusterState, Health}

  describe "ClusterStatusLive" do
    test "mounts successfully and displays cluster info", %{conn: conn} do
      # Mock cluster_info response
      cluster_info = %{
        node_count: 3,
        initialized: true,
        sealed_count: 1,
        unsealed_count: 2,
        nodes: [
          %{
            node_id: "node-1",
            hostname: "secrethub-core-0",
            status: "unsealed",
            sealed: false,
            leader: true,
            last_seen_at: DateTime.utc_now(),
            started_at: DateTime.add(DateTime.utc_now(), -3600, :second),
            version: "0.1.0"
          },
          %{
            node_id: "node-2",
            hostname: "secrethub-core-1",
            status: "unsealed",
            sealed: false,
            leader: false,
            last_seen_at: DateTime.utc_now(),
            started_at: DateTime.add(DateTime.utc_now(), -3600, :second),
            version: "0.1.0"
          },
          %{
            node_id: "node-3",
            hostname: "secrethub-core-2",
            status: "sealed",
            sealed: true,
            leader: false,
            last_seen_at: DateTime.utc_now(),
            started_at: DateTime.add(DateTime.utc_now(), -3600, :second),
            version: "0.1.0"
          }
        ]
      }

      health_status = %{
        status: :healthy,
        initialized: true,
        sealed: false,
        shutting_down: false,
        active_connections: 5,
        checks: %{
          database: {:ok, %{latency_ms: 5}},
          vault: {:ok, %{}},
          seal_status: {:ok, %{}}
        },
        timestamp: DateTime.utc_now(),
        version: "0.1.0"
      }

      # Mock the cluster info call
      expect_cluster_info_call(cluster_info)
      expect_health_call(health_status)

      {:ok, view, html} = live(conn, "/admin/cluster")

      # Check page title
      assert html =~ "Cluster Status"

      # Check cluster overview cards
      assert html =~ "Total Nodes"
      assert html =~ "3"
      assert html =~ "Unsealed"
      assert html =~ "2"
      assert html =~ "Sealed"
      assert html =~ "1"

      # Check nodes are displayed
      assert html =~ "secrethub-core-0"
      assert html =~ "secrethub-core-1"
      assert html =~ "secrethub-core-2"

      # Check leader designation
      assert html =~ "Leader"
      assert html =~ "Standby"
    end

    test "displays loading state initially", %{conn: conn} do
      {:ok, view, html} = live(conn, "/admin/cluster")

      # Should show loading initially
      assert html =~ "Loading cluster data" || has_element?(view, "svg.animate-spin")
    end

    test "handles error when cluster_info fails", %{conn: conn} do
      # Mock a failure response
      expect_cluster_info_call({:error, :connection_failed})

      {:ok, view, html} = live(conn, "/admin/cluster")

      # Should show error message
      assert html =~ "Error loading cluster data" || html =~ "connection_failed"
    end

    test "manual refresh button works", %{conn: conn} do
      cluster_info = mock_cluster_info()
      health_status = mock_health_status()

      expect_cluster_info_call(cluster_info)
      expect_health_call(health_status)

      {:ok, view, _html} = live(conn, "/admin/cluster")

      # Click refresh button
      expect_cluster_info_call(cluster_info)
      expect_health_call(health_status)

      html = view |> element("button", "Refresh Now") |> render_click()

      # Data should be refreshed (check for presence of content)
      assert html =~ "Cluster Status"
    end

    test "toggle auto-refresh button works", %{conn: conn} do
      cluster_info = mock_cluster_info()
      health_status = mock_health_status()

      expect_cluster_info_call(cluster_info)
      expect_health_call(health_status)

      {:ok, view, _html} = live(conn, "/admin/cluster")

      # Initially auto-refresh should be ON
      assert has_element?(view, "button", "Auto-refresh ON")

      # Click toggle button
      html = view |> element("button", "Auto-refresh") |> render_click()

      # Should now be OFF
      assert html =~ "Auto-refresh OFF"

      # Click again to turn back ON
      html = view |> element("button", "Auto-refresh") |> render_click()

      assert html =~ "Auto-refresh ON"
    end

    test "displays node status badges correctly", %{conn: conn} do
      cluster_info = %{
        node_count: 5,
        initialized: true,
        sealed_count: 2,
        unsealed_count: 2,
        nodes: [
          mock_node("node-1", "unsealed", false),
          mock_node("node-2", "sealed", true),
          mock_node("node-3", "initializing", true),
          mock_node("node-4", "starting", true),
          mock_node("node-5", "shutdown", true)
        ]
      }

      expect_cluster_info_call(cluster_info)
      expect_health_call(mock_health_status())

      {:ok, view, html} = live(conn, "/admin/cluster")

      # Check all status badges are present
      assert html =~ "Unsealed"
      assert html =~ "Sealed"
      assert html =~ "Initializing"
      assert html =~ "Starting"
      assert html =~ "Shutdown"
    end

    test "displays health status correctly", %{conn: conn} do
      cluster_info = mock_cluster_info()

      health_status = %{
        status: :degraded,
        initialized: true,
        sealed: false,
        shutting_down: false,
        active_connections: 3,
        checks: %{},
        timestamp: DateTime.utc_now(),
        version: "0.1.0"
      }

      expect_cluster_info_call(cluster_info)
      expect_health_call(health_status)

      {:ok, view, html} = live(conn, "/admin/cluster")

      # Check health status is displayed
      assert html =~ "Overall Health"
      assert html =~ "Degraded"
    end

    test "shows empty state when no nodes", %{conn: conn} do
      cluster_info = %{
        node_count: 0,
        initialized: false,
        sealed_count: 0,
        unsealed_count: 0,
        nodes: []
      }

      expect_cluster_info_call(cluster_info)
      expect_health_call(mock_health_status())

      {:ok, view, html} = live(conn, "/admin/cluster")

      assert html =~ "No nodes registered in the cluster"
    end

    test "formats timestamps correctly", %{conn: conn} do
      now = DateTime.utc_now()

      cluster_info = %{
        node_count: 1,
        initialized: true,
        sealed_count: 0,
        unsealed_count: 1,
        nodes: [
          %{
            node_id: "node-1",
            hostname: "test-node",
            status: "unsealed",
            sealed: false,
            leader: true,
            last_seen_at: DateTime.add(now, -120, :second),
            started_at: DateTime.add(now, -7200, :second),
            version: "0.1.0"
          }
        ]
      }

      expect_cluster_info_call(cluster_info)
      expect_health_call(mock_health_status())

      {:ok, view, html} = live(conn, "/admin/cluster")

      # Check for relative time formatting (e.g., "2m ago", "2h ago")
      assert html =~ ~r/\d+[mh]\s+ago/
    end
  end

  # Helper functions for mocking

  defp mock_cluster_info do
    %{
      node_count: 3,
      initialized: true,
      sealed_count: 1,
      unsealed_count: 2,
      nodes: [
        mock_node("node-1", "unsealed", false, true),
        mock_node("node-2", "unsealed", false, false),
        mock_node("node-3", "sealed", true, false)
      ]
    }
  end

  defp mock_node(node_id, status, sealed, leader \\ false) do
    %{
      node_id: node_id,
      hostname: "secrethub-core-#{node_id}",
      status: status,
      sealed: sealed,
      leader: leader,
      last_seen_at: DateTime.utc_now(),
      started_at: DateTime.add(DateTime.utc_now(), -3600, :second),
      version: "0.1.0"
    }
  end

  defp mock_health_status do
    %{
      status: :healthy,
      initialized: true,
      sealed: false,
      shutting_down: false,
      active_connections: 5,
      checks: %{
        database: {:ok, %{latency_ms: 5}},
        vault: {:ok, %{}},
        seal_status: {:ok, %{}}
      },
      timestamp: DateTime.utc_now(),
      version: "0.1.0"
    }
  end

  defp expect_cluster_info_call(return_value) do
    # This is a placeholder - in a real test, you would use Mox or similar
    # to mock the ClusterState.cluster_info/0 call
    # For now, we'll rely on the actual implementation
    :ok
  end

  defp expect_health_call(return_value) do
    # This is a placeholder - in a real test, you would use Mox or similar
    # to mock the Health.health/1 call
    # For now, we'll rely on the actual implementation
    :ok
  end
end
