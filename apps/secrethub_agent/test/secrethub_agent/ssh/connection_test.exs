defmodule SecretHub.Agent.SSH.ConnectionTest do
  use ExUnit.Case, async: true
  alias SecretHub.Agent.Connection

  test "SSH runtime RPCs leave Connection available while the channel replies", _context do
    tasks = start_supervised!({Task.Supervisor, []})
    parent = self()

    channel =
      spawn(fn ->
        receive do
          {:"$gen_call", from, {:push, "ssh:identities", %{}}} ->
            send(parent, {:channel_pending, from})

            receive do
              :complete -> GenServer.reply(from, {:ok, %{"identities" => []}})
            end
        end
      end)

    on_exit(fn -> if Process.alive?(channel), do: Process.exit(channel, :kill) end)

    state = %{
      connection_status: :connected,
      channel: channel,
      ssh_capabilities: ["ssh_signing_v1"],
      ssh_task_supervisor: tasks
    }

    reference = make_ref()

    assert {:noreply, ^state} =
             Connection.handle_call(
               {:ssh_request, "identities", %{}, 50},
               {self(), reference},
               state
             )

    assert_receive {:channel_pending, _}
    assert {:reply, :connected, ^state} = Connection.handle_call(:status, nil, state)
    send(channel, :complete)
    assert_receive {:ssh_result, ^channel, nil, "ssh_signing_v1", from, result}

    assert {:noreply, ^state} =
             Connection.handle_info(
               {:ssh_result, channel, nil, "ssh_signing_v1", from, result},
               state
             )

    assert_receive {^reference, {:ok, %{"identities" => []}}}
  end

  test "unresponsive runtime calls return a bounded unavailable error" do
    unresponsive =
      spawn(fn ->
        receive do
          :stop -> :ok
        end
      end)

    on_exit(fn -> if Process.alive?(unresponsive), do: send(unresponsive, :stop) end)

    assert {:error, :ssh_unavailable} =
             Connection.ssh_request(unresponsive, "identities", %{}, 10)
  end

  test "a delayed signing response cannot cross a disconnect or a new runtime generation" do
    old_channel = self()
    generation = make_ref()
    reply = {:ok, %{"private_key" => "private-material-sentinel"}}

    for state <- [
          %{
            connection_status: :disconnected,
            channel: nil,
            channel_ref: nil,
            ssh_capabilities: []
          },
          %{
            connection_status: :connected,
            channel: old_channel,
            channel_ref: make_ref(),
            ssh_capabilities: ["ssh_signing_v1"]
          }
        ] do
      tag = make_ref()

      assert {:noreply, ^state} =
               Connection.handle_info(
                 {:ssh_result, old_channel, generation, "ssh_signing_v1", {self(), tag}, reply},
                 state
               )

      assert_receive {^tag, {:error, :ssh_unavailable}}
      refute_receive {^tag, {:ok, _}}
    end
  end

  test "capabilities are explicitly negotiated and absent peers provide no SSH" do
    assert [] = Connection.negotiated_ssh_capabilities(["ssh_lookup_v1"], %{})

    assert [] =
             Connection.negotiated_ssh_capabilities(["ssh_lookup_v1"], %{
               "runtime_capabilities" => ["ssh_signing_v1"]
             })

    assert ["ssh_lookup_v1"] =
             Connection.negotiated_ssh_capabilities(["ssh_lookup_v1"], %{
               "runtime_capabilities" => ["ssh_lookup_v1", "ssh_signing_v1"]
             })

    state = %{connection_status: :connected, ssh_capabilities: []}

    assert {:reply, {:error, :ssh_unavailable}, ^state} =
             Connection.handle_call({:ssh_request, "authorize_sign", %{}, 5000}, nil, state)

    assert {:error, :ssh_unavailable} = Connection.ssh_request(self(), "identities", %{}, 5)
  end
end
