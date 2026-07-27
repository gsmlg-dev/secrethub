defmodule SecretHub.Core.ClusterStateTest do
  use SecretHub.Core.DataCase, async: false

  alias SecretHub.Core.{ClusterState, Repo}
  alias SecretHub.Shared.Schemas.ClusterNode

  @node_id "cluster-state-test-node"
  @concurrent_names [
    :concurrent_cluster_state_1,
    :concurrent_cluster_state_2,
    :concurrent_cluster_state_3,
    :concurrent_cluster_state_4,
    :concurrent_cluster_state_5,
    :concurrent_cluster_state_6,
    :concurrent_cluster_state_7,
    :concurrent_cluster_state_8,
    :concurrent_cluster_state_9,
    :concurrent_cluster_state_10,
    :concurrent_cluster_state_11,
    :concurrent_cluster_state_12
  ]

  setup do
    case Process.whereis(SecretHub.Core.Vault.SealState) do
      nil -> start_supervised!(SecretHub.Core.Vault.SealState)
      _pid -> :ok
    end

    process_names =
      [
        ClusterState,
        :missing_identity_cluster_state,
        :old_cluster_state,
        :replacement_cluster_state
        | @concurrent_names
      ]

    for name <- process_names do
      case Process.whereis(name) do
        nil -> :ok
        pid -> GenServer.stop(pid, :normal)
      end
    end

    original_node_id = Application.get_env(:secrethub_core, :cluster_node_id)
    Repo.delete_all(ClusterNode)

    on_exit(fn ->
      restore_application_env(:cluster_node_id, original_node_id)

      for name <- process_names, pid = Process.whereis(name) do
        GenServer.stop(pid, :normal)
      end
    end)

    :ok
  end

  describe "ClusterState.start_link/1" do
    test "uses the explicitly injected stable node identity" do
      pid = start_cluster_state(node_id: @node_id)

      assert %{node_id: @node_id} = :sys.get_state(pid)
      assert %ClusterNode{node_id: @node_id} = Repo.get_by(ClusterNode, node_id: @node_id)
    end

    test "fails clearly when neither injected nor configured identity exists" do
      Application.delete_env(:secrethub_core, :cluster_node_id)
      previous_trap_exit = Process.flag(:trap_exit, true)

      result =
        try do
          ClusterState.start_link(name: :missing_identity_cluster_state)
        after
          Process.flag(:trap_exit, previous_trap_exit)
        end

      assert {:error, {%ArgumentError{message: message}, _stacktrace}} = result

      assert message =~ "SECRET_HUB_CLUSTER_NODE_ID"
    end

    test "uses the runtime-configured identity when no identity is injected" do
      Application.put_env(:secrethub_core, :cluster_node_id, "runtime-configured-node")

      pid = start_cluster_state([])

      assert %{node_id: "runtime-configured-node"} = :sys.get_state(pid)

      assert %ClusterNode{node_id: "runtime-configured-node"} =
               Repo.get_by(ClusterNode, node_id: "runtime-configured-node")
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

    test "preserves durable metadata and normalizes capabilities across re-registration" do
      start_cluster_state(
        node_id: @node_id,
        metadata: %{"operator_note" => "retain-me"}
      )

      stop_supervised(ClusterState)

      start_cluster_state(
        node_id: @node_id,
        metadata: %{
          "deployment" => "blue",
          "capabilities" => %{"upgrade_gates" => 0}
        }
      )

      node = Repo.get_by!(ClusterNode, node_id: @node_id)

      assert node.metadata == %{
               "operator_note" => "retain-me",
               "deployment" => "blue",
               "capabilities" => %{"upgrade_gates" => 1}
             }
    end

    test "concurrent replacements atomically retain all unrelated metadata" do
      start_cluster_state(
        node_id: @node_id,
        metadata: %{"operator_note" => "durable"}
      )

      stop_supervised(ClusterState)
      parent = self()

      tasks =
        @concurrent_names
        |> Enum.with_index(1)
        |> Enum.map(fn {name, index} ->
          Task.async(fn ->
            send(parent, {:ready, self()})

            receive do
              :register -> :ok
            end

            ClusterState.start_link(
              node_id: @node_id,
              name: name,
              metadata: %{
                "registration_#{index}" => index,
                "capabilities" => %{"upgrade_gates" => 0}
              }
            )
          end)
        end)

      task_pids =
        Enum.map(tasks, fn _task ->
          assert_receive {:ready, task_pid}
          task_pid
        end)

      Enum.each(task_pids, &send(&1, :register))

      incarnation_ids =
        tasks
        |> Task.await_many()
        |> Enum.map(fn {:ok, pid} -> :sys.get_state(pid).incarnation_id end)

      node = Repo.get_by!(ClusterNode, node_id: @node_id)

      assert Repo.aggregate(ClusterNode, :count) == 1
      assert node.incarnation_id in incarnation_ids
      assert node.metadata["operator_note"] == "durable"
      assert node.metadata["capabilities"] == %{"upgrade_gates" => 1}

      for index <- 1..length(@concurrent_names) do
        assert node.metadata["registration_#{index}"] == index
      end
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

    test "terminating an old incarnation cannot mark its replacement shutdown" do
      start_cluster_state(
        node_id: @node_id,
        name: :old_cluster_state,
        child_id: :old_cluster_state
      )

      start_cluster_state(
        node_id: @node_id,
        name: :replacement_cluster_state,
        child_id: :replacement_cluster_state
      )

      replacement = Repo.get_by!(ClusterNode, node_id: @node_id)
      fixed_heartbeat = ~U[2026-01-01 00:00:00Z]

      replacement
      |> Ecto.Changeset.change(last_seen_at: fixed_heartbeat)
      |> Repo.update!()

      stop_supervised(:old_cluster_state)

      persisted = Repo.get_by!(ClusterNode, node_id: @node_id)

      assert persisted.incarnation_id == replacement.incarnation_id
      assert persisted.status == "starting"
      assert persisted.last_seen_at == fixed_heartbeat
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

      assert :ok = ClusterState.update_status(:unsealed)
      :sys.get_state(pid)

      assert %ClusterNode{status: "unsealed"} =
               Repo.get_by(ClusterNode, node_id: @node_id)
    end

    test "rejects an invalid public status without changing state or evidence" do
      pid = start_cluster_state(node_id: @node_id)
      persisted_before = Repo.get_by!(ClusterNode, node_id: @node_id)

      assert {:error, :invalid_status} = ClusterState.update_status(:compromised)

      assert %{status: :starting} = :sys.get_state(pid)

      persisted_after = Repo.get_by!(ClusterNode, node_id: @node_id)
      assert persisted_after.status == persisted_before.status
      assert persisted_after.sealed == persisted_before.sealed
      assert persisted_after.initialized == persisted_before.initialized
      assert persisted_after.updated_at == persisted_before.updated_at
    end

    test "ignores a malformed direct status cast without changing state or evidence" do
      pid = start_cluster_state(node_id: @node_id)
      persisted_before = Repo.get_by!(ClusterNode, node_id: @node_id)

      GenServer.cast(pid, {:update_status, :compromised})

      assert %{status: :starting} = :sys.get_state(pid)

      persisted_after = Repo.get_by!(ClusterNode, node_id: @node_id)
      assert persisted_after.status == persisted_before.status
      assert persisted_after.sealed == persisted_before.sealed
      assert persisted_after.initialized == persisted_before.initialized
      assert persisted_after.updated_at == persisted_before.updated_at
    end
  end

  describe "stale node evidence" do
    test "retains stale evidence but excludes stale non-shutdown nodes from active cluster info" do
      start_cluster_state(node_id: @node_id)
      now = DateTime.utc_now() |> DateTime.truncate(:second)
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

      Repo.insert!(%ClusterNode{
        node_id: "active-node",
        hostname: "active-host",
        status: "sealed",
        sealed: true,
        initialized: true,
        last_seen_at: now,
        started_at: now
      })

      Repo.insert!(%ClusterNode{
        node_id: "shutdown-node",
        hostname: "shutdown-host",
        status: "shutdown",
        sealed: true,
        initialized: true,
        last_seen_at: stale_time,
        started_at: stale_time
      })

      assert %ClusterNode{id: id, last_seen_at: ^stale_time} =
               Repo.get(ClusterNode, stale_node.id)

      assert id == stale_node.id

      assert {:ok, info} = ClusterState.cluster_info()
      assert info.node_count == 3
      assert info.sealed_count == 3
      assert info.unsealed_count == 0

      assert ["active-node", @node_id, "shutdown-node"] ==
               info.nodes |> Enum.map(& &1.node_id) |> Enum.sort()

      refute Enum.any?(info.nodes, &(&1.node_id == "stale-node"))
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

  defp restore_application_env(key, nil), do: Application.delete_env(:secrethub_core, key)
  defp restore_application_env(key, value), do: Application.put_env(:secrethub_core, key, value)
end
