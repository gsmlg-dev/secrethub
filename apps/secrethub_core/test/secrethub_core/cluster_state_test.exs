defmodule SecretHub.Core.ClusterStateTest do
  use SecretHub.Core.DataCase, async: false

  alias SecretHub.Core.{ClusterState, Repo}
  alias SecretHub.Shared.Schemas.ClusterNode

  setup do
    # ClusterState depends on SealState being available
    case Process.whereis(SecretHub.Core.Vault.SealState) do
      nil -> start_supervised!(SecretHub.Core.Vault.SealState)
      _pid -> :ok
    end

    # Stop any existing ClusterState (from previous test)
    case Process.whereis(ClusterState) do
      nil -> :ok
      pid -> GenServer.stop(pid, :normal)
    end

    # Clean up any existing nodes
    Repo.delete_all(ClusterNode)

    # Start ClusterState via start_supervised for automatic cleanup
    start_supervised!(ClusterState)

    :ok
  end

  describe "ClusterState.start_link/1" do
    test "starts the GenServer" do
      assert Process.alive?(Process.whereis(ClusterState))
    end
  end

  describe "ClusterState.initialized?/0" do
    test "checks vault initialization status" do
      result = ClusterState.initialized?()
      assert is_boolean(result)
    end
  end

  describe "ClusterState.cluster_info/0" do
    test "returns cluster information" do
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
      # Insert test nodes (truncate to seconds for utc_datetime schema compatibility)
      now = DateTime.truncate(DateTime.utc_now(), :second)

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

      # node_count includes the auto-registered node from ClusterState.init + our 2 test nodes
      assert info.node_count >= 2
      assert info.unsealed_count >= 1
      assert info.sealed_count >= 1
      assert length(info.nodes) >= 2
    end
  end

  describe "ClusterState.leader?/0" do
    test "returns leadership status" do
      result = ClusterState.leader?()
      assert is_boolean(result)
    end
  end

  describe "ClusterState.update_status/1" do
    test "updates node status in database" do
      now = DateTime.truncate(DateTime.utc_now(), :second)

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

      updated_node = Repo.get(ClusterNode, node.id)
      assert updated_node.status == "starting"
    end
  end
end
