defmodule SecretHub.Agent.ConnectionTest do
  use ExUnit.Case, async: false

  alias SecretHub.Agent.Connection

  # Unit tests that verify Connection behavior without requiring a running Core.
  # Connection starts async and will fail to connect to invalid URLs gracefully.
  # Note: Connection registers with name: Connection, so we stop between tests.

  setup do
    # Stop any existing Connection process to avoid name conflicts
    case Process.whereis(Connection) do
      nil -> :ok
      pid -> GenServer.stop(pid, :normal, 1000)
    end

    :ok
  end

  describe "connection lifecycle" do
    test "starts and enters connecting state with invalid URL" do
      {:ok, pid} =
        Connection.start_link(agent_id: "agent-test-01", core_url: "ws://localhost:19999")

      # Allow async init to fire
      Process.sleep(300)

      # With an invalid URL, status should be :connecting (reconnect scheduled) or :disconnected
      assert Connection.status(pid) in [:disconnected, :connecting]

      GenServer.stop(pid)
    end
  end

  describe "secret requests when disconnected" do
    test "returns error for static secret when not connected" do
      {:ok, pid} =
        Connection.start_link(agent_id: "agent-test-02", core_url: "ws://localhost:19998")

      Process.sleep(300)

      assert {:error, :not_connected} = Connection.get_static_secret(pid, "test.secret.path")

      GenServer.stop(pid)
    end

    test "returns error for dynamic credentials when not connected" do
      {:ok, pid} =
        Connection.start_link(agent_id: "agent-test-03", core_url: "ws://localhost:19997")

      Process.sleep(300)

      assert {:error, :not_connected} =
               Connection.get_dynamic_secret(pid, "test.db.readonly", 3600)

      GenServer.stop(pid)
    end

    test "returns error for lease renewal when not connected" do
      {:ok, pid} =
        Connection.start_link(agent_id: "agent-test-04", core_url: "ws://localhost:19996")

      Process.sleep(300)

      lease_id = :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)
      assert {:error, :not_connected} = Connection.renew_lease(pid, lease_id)

      GenServer.stop(pid)
    end
  end

  describe "error handling" do
    test "returns error when not connected" do
      {:ok, pid} =
        Connection.start_link(agent_id: "agent-test-05", core_url: "ws://localhost:19995")

      Process.sleep(300)

      assert Connection.status(pid) in [:disconnected, :connecting]
      {:error, :not_connected} = Connection.get_static_secret(pid, "test.secret")

      GenServer.stop(pid)
    end
  end
end
