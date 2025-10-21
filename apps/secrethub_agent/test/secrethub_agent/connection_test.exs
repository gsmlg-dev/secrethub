defmodule SecretHub.Agent.ConnectionTest do
  use ExUnit.Case, async: false

  alias SecretHub.Agent.Connection

  @moduletag :skip

  # Note: These tests are skipped by default because they require
  # the Core service to be running. Enable them for integration testing.

  describe "connection lifecycle" do
    @tag :integration
    test "starts and connects to Core service" do
      opts = [
        agent_id: "agent-test-01",
        core_url: "ws://localhost:4000"
      ]

      {:ok, pid} = Connection.start_link(opts)

      # Wait for connection to establish
      Process.sleep(1000)

      assert Connection.status(pid) == :connected

      GenServer.stop(pid)
    end
  end

  describe "secret requests" do
    setup do
      opts = [
        agent_id: "agent-test-01",
        core_url: "ws://localhost:4000"
      ]

      {:ok, pid} = Connection.start_link(opts)
      Process.sleep(1000)

      on_exit(fn -> GenServer.stop(pid) end)

      {:ok, %{conn: pid}}
    end

    @tag :integration
    test "can request static secret", %{conn: conn} do
      {:ok, secret} = Connection.get_static_secret(conn, "test.secret.path")

      assert secret["value"] == "mock_secret_test.secret.path"
      assert secret["version"] == 1
    end

    @tag :integration
    test "can request dynamic credentials", %{conn: conn} do
      {:ok, creds} = Connection.get_dynamic_secret(conn, "test.db.readonly", 3600)

      assert creds["username"] =~ ~r/^v-agent-test-01-readonly-/
      assert is_binary(creds["password"])
      assert is_binary(creds["lease_id"])
      assert creds["lease_duration"] == 3600
    end

    @tag :integration
    test "can renew lease", %{conn: conn} do
      lease_id = Ecto.UUID.generate()

      {:ok, renewal} = Connection.renew_lease(conn, lease_id)

      assert renewal["lease_id"] == lease_id
      assert renewal["renewed_ttl"] == 3600
      assert is_binary(renewal["new_expires_at"])
    end
  end

  describe "error handling" do
    test "returns error when not connected" do
      opts = [
        agent_id: "agent-test-01",
        # Invalid port
        core_url: "ws://localhost:9999"
      ]

      {:ok, pid} = Connection.start_link(opts)

      assert Connection.status(pid) == :disconnected

      {:error, :not_connected} = Connection.get_static_secret(pid, "test.secret")

      GenServer.stop(pid)
    end
  end
end
