defmodule SecretHub.Core.ClusterStateTest do
  use SecretHub.Core.DataCase, async: false

  alias SecretHub.Core.{ClusterState, Repo}
  alias SecretHub.Shared.Schemas.ClusterNode

  @node_id "cluster-state-test-node"

  setup do
    case Process.whereis(SecretHub.Core.Vault.SealState) do
      nil -> start_supervised!(SecretHub.Core.Vault.SealState)
      _pid -> :ok
    end

    for name <- [ClusterState, :old_cluster_state, :replacement_cluster_state] do
      case Process.whereis(name) do
        nil -> :ok
        pid -> GenServer.stop(pid, :normal)
      end
    end

    Repo.delete_all(ClusterNode)

    :ok
  end

  describe "ClusterState.start_link/1" do
    test "uses the explicitly injected stable node identity" do
      pid = start_cluster_state(node_id: @node_id)

      assert %{node_id: @node_id} = :sys.get_state(pid)
      assert %ClusterNode{node_id: @node_id} = Repo.get_by(ClusterNode, node_id: @node_id)
    end

    test "starts a new incarnation for the same node without creating a duplicate row" do
      pid = start_cluster_state(node_id: @node_id)
      first_node = Repo.get_by!(ClusterNode, node_id: @node_id)

      assert {:ok, _} = Ecto.UUID.cast(Map.get(first_node, :incarnation_id))

      stop_supervised(ClusterState)

      replacement_pid = start_cluster_state(node_id: @node_id)
      replacement_node = Repo.get_by!(ClusterNode, node_id: @node_id)

      refute replacement_pid == pid

      refute Map.get(replacement_node, :incarnation_id) ==
               Map.get(first_node, :incarnation_id)

      assert Repo.aggregate(ClusterNode, :count) == 1
    end

    test "normalizes code-owned capabilities without erasing unrelated metadata" do
      start_cluster_state(
        node_id: @node_id,
        metadata: %{
          "operator_note" => "rack-4",
          "capabilities" => %{"upgrade_gates" => 0, "caller_claim" => 99}
        }
      )

      node = Repo.get_by!(ClusterNode, node_id: @node_id)

      assert node.metadata["operator_note"] == "rack-4"
      assert node.metadata["capabilities"] == %{"upgrade_gates" => 1}
    end
  end

  describe "incarnation fencing" do
    test "an old incarnation cannot heartbeat or update its replacement" do
      old_pid =
        start_cluster_state(
          node_id: @node_id,
          name: :old_cluster_state,
          child_id: :old_cluster_state
        )

      old_node = Repo.get_by!(ClusterNode, node_id: @node_id)

      replacement_pid =
        start_cluster_state(
          node_id: @node_id,
          name: :replacement_cluster_state,
          child_id: :replacement_cluster_state
        )

      replacement = Repo.get_by!(ClusterNode, node_id: @node_id)
      refute Map.get(replacement, :incarnation_id) == Map.get(old_node, :incarnation_id)

      fixed_heartbeat = ~U[2026-01-01 00:00:00Z]

      replacement
      |> Ecto.Changeset.change(last_seen_at: fixed_heartbeat)
      |> Repo.update!()

      GenServer.cast(old_pid, {:update_status, :shutdown})
      send(old_pid, :heartbeat)
      :sys.get_state(old_pid)

      persisted = Repo.get_by!(ClusterNode, node_id: @node_id)

      assert Map.get(persisted, :incarnation_id) == Map.get(replacement, :incarnation_id)
      assert persisted.status == "starting"
      assert persisted.last_seen_at == fixed_heartbeat
      assert Process.alive?(replacement_pid)
    end
  end

  describe "ClusterState.initialized?/0" do
    test "checks vault initialization status" do
      start_cluster_state(node_id: @node_id)

      assert is_boolean(ClusterState.initialized?())
    end
  end

  describe "ClusterState.cluster_info/0" do
    test "returns cluster information" do
      start_cluster_state(node_id: @node_id)

      assert {:ok,
              %{
                node_count: node_count,
                initialized: initialized,
                sealed_count: sealed_count,
                unsealed_count: unsealed_count,
                nodes: nodes
              }} = ClusterState.cluster_info()

      assert is_integer(node_count)
      assert is_boolean(initialized)
      assert is_integer(sealed_count)
      assert is_integer(unsealed_count)
      assert is_list(nodes)
    end

    test "returns accurate node counts" do
      start_cluster_state(node_id: @node_id)
      now = DateTime.truncate(DateTime.utc_now(), :second)

      Repo.insert!(%ClusterNode{
        node_id: "test-node-1",
        hostname: "localhost",
        status: "unsealed",
        sealed: false,
        initialized: true,
        last_seen_at: now,
        started_at: now
      })

      Repo.insert!(%ClusterNode{
        node_id: "test-node-2",
        hostname: "localhost",
        status: "sealed",
        sealed: true,
        initialized: true,
        last_seen_at: now,
        started_at: now
      })

      assert {:ok, info} = ClusterState.cluster_info()
      assert info.node_count == 3
      assert info.unsealed_count == 1
      assert info.sealed_count == 2
      assert length(info.nodes) == 3
    end
  end

  describe "ClusterState.leader?/0" do
    test "returns leadership status" do
      start_cluster_state(node_id: @node_id)

      assert is_boolean(ClusterState.leader?())
    end
  end

  describe "ClusterState.update_status/1" do
    test "updates the current incarnation status in the database" do
      pid = start_cluster_state(node_id: @node_id)

      ClusterState.update_status(:unsealed)
      :sys.get_state(pid)

      assert %ClusterNode{status: "unsealed"} =
               Repo.get_by(ClusterNode, node_id: @node_id)
    end
  end

  describe "stale node evidence" do
    test "heartbeat maintenance retains stale node rows" do
      pid = start_cluster_state(node_id: @node_id)
      stale_time = DateTime.add(DateTime.utc_now(), -120, :second) |> DateTime.truncate(:second)

      stale_node =
        Repo.insert!(%ClusterNode{
          node_id: "stale-node",
          hostname: "stale-host",
          status: "unsealed",
          sealed: false,
          initialized: true,
          last_seen_at: stale_time,
          started_at: stale_time
        })

      send(pid, :heartbeat)
      :sys.get_state(pid)

      assert %ClusterNode{id: id, last_seen_at: ^stale_time} =
               Repo.get(ClusterNode, stale_node.id)

      assert id == stale_node.id
    end
  end

  defp start_cluster_state(opts) do
    child_id = Keyword.get(opts, :child_id, ClusterState)
    opts = Keyword.delete(opts, :child_id)

    start_supervised!(%{
      id: child_id,
      start: {ClusterState, :start_link, [opts]},
      restart: :temporary
    })
  end
end
