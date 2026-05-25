defmodule SecretHub.Agent.ConnectionProtocolTest do
  use ExUnit.Case, async: true

  alias SecretHub.Agent.Connection

  test "uses the normalized trusted runtime topic" do
    assert Connection.runtime_topic() == "agent:runtime"
  end

  test "uses the server runtime event vocabulary" do
    assert Connection.runtime_event(:get_static_secret) == "secret:read"
    assert Connection.runtime_event(:get_dynamic_secret) == "secret:read"
    assert Connection.runtime_event(:renew_lease) == "secret:lease_renew"
    assert Connection.runtime_event(:heartbeat) == "agent:heartbeat"
  end

  test "stores the accepted runtime callback in connection state" do
    callback = fn _payload -> :ok end

    assert {:ok, state} =
             Connection.init(
               agent_id: "agent-1",
               core_url: "ws://localhost:1",
               on_runtime_accepted: callback
             )

    assert state.on_runtime_accepted == callback
    assert_received :connect
  end

  test "notifies the accepted runtime callback with the join payload once" do
    test_pid = self()
    callback = fn payload -> send(test_pid, {:accepted, payload}) end
    payload = %{"agent_id" => "agent-1", "status" => "accepted"}

    assert %{on_runtime_accepted: nil} =
             state = Connection.notify_runtime_accepted(%{on_runtime_accepted: callback}, payload)

    assert_received {:accepted, ^payload}

    assert ^state = Connection.notify_runtime_accepted(state, payload)
    refute_received {:accepted, ^payload}
  end
end
