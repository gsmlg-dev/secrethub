defmodule SecretHub.Agent.ApplicationTest do
  use ExUnit.Case, async: false

  alias SecretHub.Agent.{
    Connection,
    EndpointManager,
    IdentityStore,
    RuntimeBootstrapper,
    UDSServer
  }

  @localhost_core_url "https://localhost:4664"

  setup do
    old_env = Application.get_all_env(:secrethub_agent)
    old_system_env = agent_system_env()

    stop_agent_processes()

    on_exit(fn ->
      stop_agent_processes()

      :secrethub_agent
      |> Application.get_all_env()
      |> Keyword.keys()
      |> Enum.each(&Application.delete_env(:secrethub_agent, &1))

      Enum.each(old_env, fn {key, value} ->
        Application.put_env(:secrethub_agent, key, value)
      end)

      restore_system_env(old_system_env)
    end)

    :ok
  end

  test "starts the agent from configured core URL" do
    socket_path =
      Path.join(System.tmp_dir!(), "secrethub_agent_#{System.unique_integer([:positive])}.sock")

    home_dir =
      Path.join(System.tmp_dir!(), "secrethub_agent_home_#{System.unique_integer([:positive])}")

    System.put_env("HOME", home_dir)

    Application.put_env(:secrethub_agent, :enabled, true)
    Application.put_env(:secrethub_agent, :core_url, @localhost_core_url)

    state_dir = Path.join(home_dir, ".local/state/secrethub/agent")
    Application.put_env(:secrethub_agent, :endpoint_health_check_interval, 60_000)
    Application.put_env(:secrethub_agent, :socket_path, socket_path)

    assert :ok = IdentityStore.write(state_dir, trusted_material())

    assert {:ok, supervisor} = SecretHub.Agent.Application.start(:normal, [])
    assert Process.alive?(supervisor)
    assert Process.whereis(SecretHub.Agent.Supervisor) == supervisor

    assert Process.whereis(EndpointManager)
    assert Process.whereis(RuntimeBootstrapper)
    assert Process.whereis(UDSServer)

    assert [%{url: @localhost_core_url}] = EndpointManager.get_health_status()

    assert File.exists?(socket_path)
  end

  test "starts the agent from only SECRET_HUB_AGENT_CORE_URL" do
    socket_path =
      Path.join(System.tmp_dir!(), "secrethub_agent_#{System.unique_integer([:positive])}.sock")

    home_dir =
      Path.join(System.tmp_dir!(), "secrethub_agent_home_#{System.unique_integer([:positive])}")

    core_url = "https://core-env.example.com"

    System.put_env("HOME", home_dir)
    System.put_env("SECRET_HUB_AGENT_CORE_URL", core_url)

    Application.put_env(:secrethub_agent, :enabled, true)
    Application.delete_env(:secrethub_agent, :core_url)
    Application.put_env(:secrethub_agent, :endpoint_health_check_interval, 60_000)
    Application.put_env(:secrethub_agent, :socket_path, socket_path)

    state_dir = Path.join(home_dir, ".local/state/secrethub/agent")

    assert :ok =
             IdentityStore.write(
               state_dir,
               trusted_material(agent_id: "agent-env-start", endpoint: "wss://127.0.0.1:1")
             )

    assert {:ok, _supervisor} = SecretHub.Agent.Application.start(:normal, [])

    assert Process.whereis(EndpointManager)
    assert Process.whereis(RuntimeBootstrapper)

    assert [%{url: ^core_url}] = EndpointManager.get_health_status()

    assert File.exists?(socket_path)
  end

  test "requires a core URL when the agent is enabled" do
    Application.put_env(:secrethub_agent, :enabled, true)
    Application.delete_env(:secrethub_agent, :core_url)
    System.delete_env("SECRET_HUB_AGENT_CORE_URL")

    assert_raise RuntimeError, ~r/SECRET_HUB_AGENT_CORE_URL is required/, fn ->
      SecretHub.Agent.Application.start(:normal, [])
    end
  end

  defp trusted_material(overrides \\ []) do
    agent_id = Keyword.get(overrides, :agent_id, "agent-test-localhost")
    endpoint = Keyword.get(overrides, :endpoint, "wss://127.0.0.1:1")

    private_key = :public_key.generate_key({:rsa, 2048, 65_537})
    private_key_pem = X509.PrivateKey.to_pem(private_key, wrap: true)

    certificate_pem =
      private_key
      |> X509.Certificate.self_signed("/CN=#{agent_id}")
      |> X509.Certificate.to_pem()

    %{
      agent_id: agent_id,
      certificate_pem: certificate_pem,
      private_key_pem: private_key_pem,
      ca_chain_pem: certificate_pem,
      connect_info: %{
        "trusted_websocket_endpoint" => endpoint,
        "expected_core_server_name" => "localhost"
      },
      identity: %{
        "agent_id" => agent_id,
        "enrollment_id" => "enrollment-test",
        "certificate_fingerprint" => "SHA256:certificate"
      }
    }
  end

  defp stop_registered_process(name) do
    case Process.whereis(name) do
      nil -> :ok
      pid -> GenServer.stop(pid, :normal, 1000)
    end
  catch
    :exit, _reason -> :ok
  end

  defp stop_agent_processes do
    stop_registered_process(SecretHub.Agent.Supervisor)
    stop_registered_process(Connection)
    stop_registered_process(EndpointManager)
    stop_registered_process(RuntimeBootstrapper)
    stop_registered_process(UDSServer)
  end

  defp agent_system_env do
    [
      "HOME",
      "SECRET_HUB_AGENT_CORE_URL"
    ]
    |> Map.new(fn key -> {key, System.get_env(key)} end)
  end

  defp restore_system_env(old_system_env) do
    Enum.each(old_system_env, fn
      {key, nil} -> System.delete_env(key)
      {key, value} -> System.put_env(key, value)
    end)
  end
end
