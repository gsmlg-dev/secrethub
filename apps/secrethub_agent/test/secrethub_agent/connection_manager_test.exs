defmodule SecretHub.Agent.ConnectionManagerTest do
  use ExUnit.Case, async: false

  alias SecretHub.Agent.{Connection, ConnectionManager, EndpointManager}

  setup do
    stop_registered_process(ConnectionManager)
    stop_registered_process(Connection)
    stop_registered_process(EndpointManager)

    on_exit(fn ->
      stop_registered_process(ConnectionManager)
      stop_registered_process(Connection)
      stop_registered_process(EndpointManager)
    end)

    :ok
  end

  test "adopts an existing low-level connection when the manager restarts" do
    endpoint = "ws://localhost:19994"

    start_supervised!({EndpointManager, core_endpoints: [endpoint]})

    assert {:ok, connection_pid} =
             GenServer.start(
               Connection,
               [
                 agent_id: "agent-existing-connection",
                 core_url: endpoint
               ],
               name: Connection
             )

    assert {:ok, manager_pid} =
             ConnectionManager.start_link(
               agent_id: "agent-existing-connection",
               core_endpoints: [endpoint]
             )

    assert %{connection_pid: ^connection_pid, current_endpoint: ^endpoint} =
             :sys.get_state(manager_pid)
  end

  defp stop_registered_process(name) do
    case Process.whereis(name) do
      nil -> :ok
      pid -> GenServer.stop(pid, :normal, 1000)
    end
  catch
    :exit, _reason -> :ok
  end
end
