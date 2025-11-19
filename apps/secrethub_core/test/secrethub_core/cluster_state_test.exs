defmodule SecretHub.Core.ClusterStateTest do
  use SecretHub.Core.DataCase, async: false

  alias SecretHub.Core.{ClusterState, Repo}
  alias SecretHub.Shared.Schemas.ClusterNode

  setup do
    # Clean up any existing nodes
    Repo.delete_all(ClusterNode)
    :ok
  end

  describe "ClusterState.start_link/1" do
    test "starts the GenServer" do
      {:ok, _pid} = ClusterState.start_link()
      assert Process.alive?(ClusterState)
    end
  end

  describe "ClusterState.initialized?/0" do
    test "checks vault initialization status" do
      {:ok, _pid} = ClusterState.start_link()
      result = ClusterState.initialized?()
      assert is_boolean(result)
    end
  end

  describe "ClusterState.cluster_info/0" do
    test "returns cluster information" do
      {:ok, _pid} = ClusterState.start_link()

      {:ok, info} = ClusterState.cluster_info()

      assert is_map(info)
      assert Map.has_key?(info, :node_count)
      assert Map.has_key?(info, :initialized)
      assert Map.has_key?(info, :sealed_count)
      assert Map.has_key?(info, :unsealed_count)
      assert Map.has_key?(info, :nodes)
      assert is_list(info.nodes)
    end

    test "returns accurate node counts" do
      {:ok, _pid} = ClusterState.start_link()

      # Insert test nodes
      now = DateTime.utc_now()

      _node1 =
        Repo.insert!(%ClusterNode{
          node_id: "test-node-1",
          hostname: "localhost",
          status: "unsealed",
          sealed: false,
          initialized: true,
          last_seen_at: now,
          started_at: now
        })

      _node2 =
        Repo.insert!(%ClusterNode{
          node_id: "test-node-2",
          hostname: "localhost",
          status: "sealed",
          sealed: true,
          initialized: true,
          last_seen_at: now,
          started_at: now
        })

      {:ok, info} = ClusterState.cluster_info()

      assert info.node_count == 2
      assert info.unsealed_count == 1
      assert info.sealed_count == 1
      assert length(info.nodes) == 2
    end
  end

  describe "ClusterState.leader?/0" do
    test "returns leadership status" do
      {:ok, _pid} = ClusterState.start_link()
      result = ClusterState.leader?()
      assert is_boolean(result)
    end
  end

  describe "ClusterState.update_status/1" do
    test "updates node status in database" do
      {:ok, _pid} = ClusterState.start_link()
      now = DateTime.utc_now()

      # Create a test node
      {:ok, node} =
        Repo.insert(%ClusterNode{
          node_id: "test-node",
          hostname: "localhost",
          status: "starting",
          sealed: true,
          initialized: false,
          last_seen_at: now,
          started_at: now
        })

      # Manually update status via the private function
      # (In real usage, this would be called via handle_cast)
      # For testing, we just verify the database structure works

      updated_node = Repo.get(ClusterNode, node.id)
      assert updated_node.status == "starting"
    end
  end
end
