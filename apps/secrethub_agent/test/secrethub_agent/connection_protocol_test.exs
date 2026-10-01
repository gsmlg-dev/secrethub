defmodule SecretHub.Agent.ConnectionProtocolTest do
  use ExUnit.Case, async: true

  alias SecretHub.Agent.Connection
  alias SecretHub.Agent.IdentityStore

  @moduletag :tmp_dir

  test "runtime floor is durable before the accepted callback and cannot regress", %{tmp_dir: dir} do
    material = %{
      agent_id: "agent-1",
      certificate_pem: "certificate",
      private_key_pem: "key",
      ca_chain_pem: "ca",
      connect_info: %{},
      identity: %{"agent_id" => "agent-1"}
    }

    assert :ok = IdentityStore.write(dir, material)
    owner = self()
    callback = fn _ -> send(owner, {:persisted_at_acceptance, IdentityStore.load(dir)}) end

    state = %{
      agent_id: "agent-1",
      state_dir: dir,
      minimum_uds_auth_version: 1,
      on_runtime_accepted: callback
    }

    payload = %{"minimum_uds_auth_version" => 2}
    assert {:ok, next} = Connection.accept_runtime_floor(state, payload)
    Connection.notify_runtime_accepted(next, payload)

    assert_receive {:persisted_at_acceptance,
                    {:ok, %{identity: %{"minimum_uds_auth_version" => 2}}}}

    assert {:ok, %{minimum_uds_auth_version: 2}} =
             Connection.accept_runtime_floor(next, %{"minimum_uds_auth_version" => 1})

    assert :ok = IdentityStore.write(dir, material)

    assert {:ok, %{minimum_uds_auth_version: 2}} =
             Connection.accept_runtime_floor(state, %{"minimum_uds_auth_version" => 1})
  end

  test "runtime acceptance fails closed when the Core floor or durable identity is unavailable",
       %{tmp_dir: dir} do
    state = %{agent_id: "agent-1", state_dir: dir, minimum_uds_auth_version: 1}

    assert {:error, :trusted_state_unavailable} =
             Connection.accept_runtime_floor(state, %{"minimum_uds_auth_version" => 2})

    assert :ok =
             IdentityStore.write(dir, %{
               agent_id: "agent-1",
               certificate_pem: "certificate",
               private_key_pem: "key",
               ca_chain_pem: "ca",
               connect_info: %{},
               identity: %{"agent_id" => "agent-1"}
             })

    for payload <- [%{}, %{"minimum_uds_auth_version" => 0}, %{"minimum_uds_auth_version" => "2"}] do
      assert {:error, :trusted_state_unavailable} =
               Connection.accept_runtime_floor(state, payload)
    end

    assert {:error, :trusted_state_unavailable} =
             Connection.accept_runtime_floor(Map.delete(state, :state_dir), %{
               "minimum_uds_auth_version" => 2
             })
  end

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
