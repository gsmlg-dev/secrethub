defmodule SecretHub.Core.Agents.ConnectionManagerTest do
  use ExUnit.Case, async: false

  alias SecretHub.Core.Agents.ConnectionManager

  setup do
    start_supervised!({ConnectionManager, name: :connection_manager_test})
    :ok
  end

  test "registers and lists an active trusted connection" do
    socket_pid = self()

    assert :ok =
             ConnectionManager.register_connection(
               :connection_manager_test,
               "agent-123",
               "serial-abc",
               socket_pid,
               %{hostname: "build-01"}
             )

    assert ConnectionManager.connected?(:connection_manager_test, "agent-123")

    assert {:ok, connection} =
             ConnectionManager.get_connection(:connection_manager_test, "agent-123")

    assert connection.agent_id == "agent-123"
    assert connection.cert_serial == "serial-abc"
    assert connection.socket_pid == socket_pid
    assert connection.metadata.hostname == "build-01"
  end

  test "replaces an existing connection for the same agent" do
    first = spawn(fn -> Process.sleep(:infinity) end)
    second = self()

    assert :ok =
             ConnectionManager.register_connection(
               :connection_manager_test,
               "agent-123",
               "serial-old",
               first,
               %{}
             )

    assert :ok =
             ConnectionManager.register_connection(
               :connection_manager_test,
               "agent-123",
               "serial-new",
               second,
               %{}
             )

    assert {:ok, connection} =
             ConnectionManager.get_connection(:connection_manager_test, "agent-123")

    assert connection.cert_serial == "serial-new"
    refute Process.alive?(first)
  end

  test "disconnect_agent removes the connection and sends a disconnect message" do
    assert :ok =
             ConnectionManager.register_connection(
               :connection_manager_test,
               "agent-123",
               "serial-abc",
               self(),
               %{}
             )

    assert :ok =
             ConnectionManager.disconnect_agent(
               :connection_manager_test,
               "agent-123",
               :revoked
             )

    refute ConnectionManager.connected?(:connection_manager_test, "agent-123")
    assert_receive {:secrethub_agent_disconnect, :revoked}
  end
end
