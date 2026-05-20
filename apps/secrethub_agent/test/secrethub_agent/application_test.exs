defmodule SecretHub.Agent.ApplicationTest do
  use ExUnit.Case, async: false

  alias SecretHub.Agent.{Connection, ConnectionManager, EndpointManager, UDSServer}

  @localhost_core_url "ws://localhost:4664"

  setup do
    old_env = Application.get_all_env(:secrethub_agent)

    stop_registered_process(Connection)
    stop_registered_process(ConnectionManager)
    stop_registered_process(EndpointManager)
    stop_registered_process(UDSServer)
    stop_registered_process(SecretHub.Agent.Supervisor)

    on_exit(fn ->
      stop_registered_process(Connection)
      stop_registered_process(ConnectionManager)
      stop_registered_process(EndpointManager)
      stop_registered_process(UDSServer)
      stop_registered_process(SecretHub.Agent.Supervisor)

      :secrethub_agent
      |> Application.get_all_env()
      |> Keyword.keys()
      |> Enum.each(&Application.delete_env(:secrethub_agent, &1))

      Enum.each(old_env, fn {key, value} ->
        Application.put_env(:secrethub_agent, key, value)
      end)
    end)

    :ok
  end

  test "starts the agent and targets localhost core by default" do
    socket_path =
      Path.join(System.tmp_dir!(), "secrethub_agent_#{System.unique_integer([:positive])}.sock")

    Application.put_env(:secrethub_agent, :enabled, true)
    Application.put_env(:secrethub_agent, :agent_id, "agent-test-localhost")
    Application.put_env(:secrethub_agent, :core_url, @localhost_core_url)
    Application.delete_env(:secrethub_agent, :core_endpoints)
    Application.put_env(:secrethub_agent, :endpoint_health_check_interval, 60_000)
    Application.put_env(:secrethub_agent, :socket_path, socket_path)
    Application.put_env(:secrethub_agent, :cert_path, nil)
    Application.put_env(:secrethub_agent, :key_path, nil)
    Application.put_env(:secrethub_agent, :ca_path, nil)

    assert {:ok, supervisor} = SecretHub.Agent.Application.start(:normal, [])
    assert Process.alive?(supervisor)
    assert Process.whereis(SecretHub.Agent.Supervisor) == supervisor

    assert Process.whereis(EndpointManager)
    assert Process.whereis(ConnectionManager)
    assert Process.whereis(UDSServer)

    assert [%{url: @localhost_core_url}] = EndpointManager.get_health_status()
    assert ConnectionManager.status() in [:connecting, :disconnected]

    assert File.exists?(socket_path)
  end

  defp stop_registered_process(name) do
    try do
      case Process.whereis(name) do
        nil -> :ok
        pid -> GenServer.stop(pid, :normal, 1000)
      end
    catch
      :exit, _reason -> :ok
    end
  end
end
