defmodule SecretHub.Agent.RuntimeChannelTest do
  use ExUnit.Case, async: false

  alias Phoenix.SocketClient
  alias Phoenix.SocketClient.Channel.State
  alias Phoenix.SocketClient.Message
  alias SecretHub.Agent.Connection
  alias SecretHub.Agent.PKI.TrustBundleManager

  defmodule BundleConnection do
    use GenServer

    def start_link(owner), do: GenServer.start_link(__MODULE__, owner, name: __MODULE__)
    def pull_trust_bundle, do: GenServer.call(__MODULE__, :pull)
    def init(owner), do: {:ok, owner}

    def handle_call(:pull, _from, owner) do
      send(owner, :bundle_pull_observed)
      {:reply, {:error, :not_connected}, owner}
    end
  end

  setup do
    {:ok, _} = Application.ensure_all_started(:phoenix_socket_client)
    agent_id = "runtime-push-fixture-#{System.unique_integer([:positive])}"

    connection =
      start_supervised!({Connection, agent_id: agent_id, core_url: "ws://127.0.0.1:1"})

    socket = await_socket(connection)
    topic = Connection.runtime_topic()

    channel =
      Map.get(
        SocketClient.get_state(socket, :topic_channel_map) || %{},
        topic,
        SocketClient.get_state(socket, :default_channel_module)
      )

    on_exit(fn ->
      ref = Process.monitor(socket)

      try do
        if Process.alive?(socket), do: Supervisor.stop(socket, :normal, 10_000)
      catch
        :exit, _reason -> :ok
      end

      receive do
        {:DOWN, ^ref, :process, ^socket, _reason} -> :ok
      after
        10_000 -> flunk("owned runtime socket did not stop")
      end
    end)

    {:ok, connection: connection, channel: channel, topic: topic, agent_id: agent_id}
  end

  test "configured runtime channel preserves server push envelopes", %{
    channel: channel,
    topic: topic
  } do
    state = %State{caller: self(), topic: topic, join_ref: "join-fixture"}

    for event <- [
          "pki:client_auth_bundle:updated",
          "agent:uds_auth_floor",
          "secret:rotated",
          "policy:updated"
        ] do
      message = %Message{
        topic: topic,
        event: event,
        payload: %{"generation" => 5, "crl_number" => 5},
        ref: "push-fixture",
        join_ref: "join-fixture"
      }

      assert {:noreply, ^state} = channel.handle_info(message, state)
      assert_receive ^message
    end
  end

  @tag :tmp_dir
  test "CRL refresh push immediately triggers a bundle pull through Connection", %{
    connection: connection,
    channel: channel,
    topic: topic,
    agent_id: agent_id,
    tmp_dir: tmp_dir
  } do
    start_supervised!({BundleConnection, self()})

    start_supervised!(
      {TrustBundleManager,
       bundle_dir: tmp_dir,
       state_dir: tmp_dir,
       agent_id: agent_id,
       connection_mod: BundleConnection}
    )

    # Consume startup reconciliation so it cannot satisfy the refresh assertion.
    assert_receive :bundle_pull_observed, 1_000
    assert %{status: "initializing"} = TrustBundleManager.status()

    message = %Message{
      topic: topic,
      event: "pki:client_auth_bundle:updated",
      payload: %{"generation" => 5, "crl_number" => 5}
    }

    state = %State{caller: connection, topic: topic}
    assert {:noreply, ^state} = channel.handle_info(message, state)
    assert_receive :bundle_pull_observed, 1_000
  end

  test "runtime request replies retain library correlation behavior", %{
    channel: channel,
    topic: topic
  } do
    caller_ref = make_ref()
    request = %Message{event: "agent:heartbeat", topic: topic, ref: "request-fixture"}

    state = %State{
      caller: self(),
      topic: topic,
      join_ref: "join-fixture",
      pushes: [{{self(), caller_ref}, request}]
    }

    reply = %Message{
      topic: topic,
      event: "phx_reply",
      ref: request.ref,
      payload: %{"status" => "ok", "response" => %{"status" => "alive"}}
    }

    assert {:noreply, %State{pushes: []}} = channel.handle_info(reply, state)
    assert_receive {^caller_ref, {:ok, %{"status" => "alive"}}}
    refute_receive %Message{}, 20
  end

  defp await_socket(connection, attempts \\ 100)
  defp await_socket(_connection, 0), do: flunk("runtime socket did not start")

  defp await_socket(connection, attempts) do
    case :sys.get_state(connection) do
      %{socket: socket} when is_pid(socket) ->
        socket

      _ ->
        Process.sleep(10)
        await_socket(connection, attempts - 1)
    end
  end
end
