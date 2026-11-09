defmodule SecretHub.Agent.FakeRuntimeChannel do
  @moduledoc false
  # Answers Phoenix.SocketClient.Channel.push/4 calls like a joined channel.
  use GenServer

  def start_link(opts), do: GenServer.start_link(__MODULE__, Keyword.fetch!(opts, :owner))
  def hang(pid), do: GenServer.call(pid, :hang)

  @impl true
  def init(owner), do: {:ok, %{owner: owner, hang: false}}

  @impl true
  def handle_call(:hang, _from, state), do: {:reply, :ok, %{state | hang: true}}

  def handle_call({:push, _event, _payload}, _from, %{hang: true} = state),
    do: {:noreply, state}

  def handle_call({:push, event, payload}, _from, state) do
    send(state.owner, {:pushed, event, payload})
    {:reply, {:ok, %{"value" => "v"}}, state}
  end
end

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

    payload = %{
      "minimum_uds_auth_version" => 2,
      "runtime_capabilities" => ["uds_auth_v2", "local_socket_read_v1"]
    }

    assert {:ok, next} = Connection.accept_runtime_floor(state, payload)
    assert next.local_socket_read_capable
    Connection.notify_runtime_accepted(next, payload)

    assert_receive {:persisted_at_acceptance,
                    {:ok, %{identity: %{"minimum_uds_auth_version" => 2}}}}

    assert {:ok, %{minimum_uds_auth_version: 2, local_socket_read_capable: true}} =
             Connection.accept_runtime_floor(next, %{"minimum_uds_auth_version" => 1})

    assert {:ok, %{minimum_uds_auth_version: 2, local_socket_read_capable: false}} =
             Connection.accept_runtime_floor(next, %{
               "minimum_uds_auth_version" => 2,
               "runtime_capabilities" => ["uds_auth_v2"]
             })

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
    assert Connection.runtime_event(:get_static_secret_local) == "secret:read_local"
    assert Connection.runtime_event(:get_dynamic_secret) == "secret:read"
    assert Connection.runtime_event(:renew_lease) == "secret:lease_renew"
    assert Connection.runtime_event(:heartbeat) == "agent:heartbeat"
  end

  @tag :local_socket_read
  test "UDS synchronization shares only current connected runtime state" do
    state = %{
      connection_status: :connected,
      agent_id: "agent-current",
      minimum_uds_auth_version: 2,
      local_socket_read_capable: true
    }

    assert {:noreply, ^state} = Connection.handle_cast({:sync_uds_runtime, self()}, state)
    assert_receive {:configure_runtime, "agent-current", 2, ["local_socket_read_v1"]}

    state = %{state | local_socket_read_capable: false}
    assert {:noreply, ^state} = Connection.handle_cast({:sync_uds_runtime, self()}, state)
    assert_receive {:configure_runtime, "agent-current", 2, []}

    for status <- [:connecting, :disconnected] do
      state = %{state | connection_status: status, local_socket_read_capable: true}
      assert {:noreply, ^state} = Connection.handle_cast({:sync_uds_runtime, self()}, state)
    end

    refute_receive {:configure_runtime, _, _, _}
  end

  @tag :local_socket_read
  test "local reads refuse absent capability or a disconnected Core" do
    state = %{connection_status: :connected, local_socket_read_capable: false}

    assert {:reply, {:error, %{"reason" => "INCOMPATIBLE_VERSION"}}, ^state} =
             Connection.handle_call(
               {:get_static_secret_local, "prod.db.password", nil, %{}},
               nil,
               state
             )

    for status <- [:connecting, :disconnected] do
      state = %{connection_status: status, local_socket_read_capable: true}

      assert {:reply, {:error, :not_connected}, ^state} =
               Connection.handle_call(
                 {:get_static_secret_local, "prod.db.password", nil, %{}},
                 nil,
                 state
               )
    end
  end

  describe "host credentials" do
    setup do
      tasks =
        start_supervised!(
          {Task.Supervisor, name: :"hc_tasks_#{System.unique_integer([:positive])}"}
        )

      channel = start_supervised!({SecretHub.Agent.FakeRuntimeChannel, owner: self()})
      generation = make_ref()

      state = %{
        connection_status: :connected,
        host_credentials_capable: true,
        channel: channel,
        channel_ref: generation,
        credential_task_supervisor: tasks,
        agent_id: "agent-current",
        minimum_uds_auth_version: 2,
        local_socket_read_capable: false
      }

      %{state: state}
    end

    test "uses the credential runtime event vocabulary" do
      assert Connection.runtime_event({:credential, "get"}) == "credential:get"
      assert Connection.runtime_event({:credential, "list"}) == "credential:list"
    end

    test "requests are pushed outside the connection process and replied to the caller",
         %{state: state} do
      from = {self(), make_ref()}
      payload = %{"namespace" => "generic", "service" => "svc", "account" => "u"}

      assert {:noreply, ^state} =
               Connection.handle_call({:credential_request, "get", payload, 1_000}, from, state)

      assert_receive {:pushed, "credential:get", ^payload}
      assert_receive {:credential_result, _, _, ^from, {:ok, %{"value" => "v"}}} = result, 1_000

      assert {:noreply, ^state} = Connection.handle_info(result, state)
      {_pid, ref} = from
      assert_receive {^ref, {:ok, %{"value" => "v"}}}
    end

    test "a reply from a replaced channel is not delivered as a result", %{state: state} do
      from = {self(), make_ref()}

      {:noreply, _} =
        Connection.handle_call({:credential_request, "put", %{}, 1_000}, from, state)

      assert_receive {:credential_result, _, _, ^from, _} = result, 1_000
      reconnected = %{state | channel_ref: make_ref()}
      Connection.handle_info(result, reconnected)
      {_pid, ref} = from
      assert_receive {^ref, {:error, :not_connected}}
    end

    test "a Core timeout is reported as a timeout, never as success", %{state: state} do
      SecretHub.Agent.FakeRuntimeChannel.hang(state.channel)
      from = {self(), make_ref()}

      {:noreply, _} =
        Connection.handle_call({:credential_request, "delete", %{}, 100}, from, state)

      assert_receive {:credential_result, _, _, ^from, {:error, :timeout}}, 2_000
    end

    test "requests refuse an unnegotiated capability or a disconnected Core", %{state: state} do
      incapable = %{state | host_credentials_capable: false}

      assert {:reply, {:error, %{"reason" => "INCOMPATIBLE_VERSION"}}, _} =
               Connection.handle_call({:credential_request, "get", %{}, 1_000}, nil, incapable)

      for status <- [:connecting, :disconnected] do
        assert {:reply, {:error, :not_connected}, _} =
                 Connection.handle_call(
                   {:credential_request, "get", %{}, 1_000},
                   nil,
                   %{state | connection_status: status}
                 )
      end

      refute_receive {:pushed, _, _}
    end

    test "negotiation enables the UDS capability only when Core accepts it",
         %{state: state, tmp_dir: dir} do
      :ok =
        IdentityStore.write(dir, %{
          agent_id: "agent-current",
          certificate_pem: "certificate",
          private_key_pem: "key",
          ca_chain_pem: "ca",
          connect_info: %{},
          identity: %{"agent_id" => "agent-current"}
        })

      state = Map.put(state, :state_dir, dir)

      assert {:ok, %{host_credentials_capable: true}} =
               Connection.accept_runtime_floor(state, %{
                 "minimum_uds_auth_version" => 2,
                 "runtime_capabilities" => ["uds_auth_v2", "host_credentials_v1"]
               })

      assert {:ok, %{host_credentials_capable: false} = older} =
               Connection.accept_runtime_floor(state, %{
                 "minimum_uds_auth_version" => 2,
                 "runtime_capabilities" => ["uds_auth_v2"]
               })

      assert {:noreply, _} = Connection.handle_cast({:sync_uds_runtime, self()}, older)
      assert_receive {:configure_runtime, "agent-current", 2, []}

      assert {:noreply, _} = Connection.handle_cast({:sync_uds_runtime, self()}, state)
      assert_receive {:configure_runtime, "agent-current", 2, ["host_credentials_v1"]}
    end
  end

  test "older Core capability absence never uploads or acknowledges pending evidence" do
    state = %{connection_status: :connected, access_audit_capable: false}

    assert {:reply, {:error, :unsupported}, ^state} =
             Connection.handle_call({:submit_audit_batch, [], 1_000}, nil, state)

    assert [] = Connection.negotiated_ssh_capabilities(["access_audit_v1"], %{})

    assert ["access_audit_v1"] =
             Connection.negotiated_ssh_capabilities(
               ["access_audit_v1"],
               %{"runtime_capabilities" => ["uds_auth_v2", "access_audit_v1"]}
             )
  end

  test "disconnected audit upload reports outage while retaining capability semantics" do
    for status <- [:connecting, :disconnected] do
      state = %{connection_status: status, access_audit_capable: true}

      assert {:reply, {:error, :audit_unavailable}, ^state} =
               Connection.handle_call({:submit_audit_batch, [], 1_000}, nil, state)
    end
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
