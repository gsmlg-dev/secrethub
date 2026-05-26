defmodule SecretHub.Agent.ApplicationTest do
  use ExUnit.Case, async: false

  alias SecretHub.Agent.{
    Connection,
    ConnectionManager,
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

  test "starts the agent and targets localhost core by default" do
    socket_path =
      Path.join(System.tmp_dir!(), "secrethub_agent_#{System.unique_integer([:positive])}.sock")

    Application.put_env(:secrethub_agent, :enabled, true)
    Application.put_env(:secrethub_agent, :agent_id, "agent-test-localhost")
    Application.put_env(:secrethub_agent, :core_url, @localhost_core_url)
    Application.delete_env(:secrethub_agent, :core_endpoints)

    state_dir =
      Path.join(System.tmp_dir!(), "secrethub_agent_state_#{System.unique_integer([:positive])}")

    Application.put_env(:secrethub_agent, :state_dir, state_dir)
    Application.put_env(:secrethub_agent, :endpoint_health_check_interval, 60_000)
    Application.put_env(:secrethub_agent, :socket_path, socket_path)
    Application.put_env(:secrethub_agent, :cert_path, nil)
    Application.put_env(:secrethub_agent, :key_path, nil)
    Application.put_env(:secrethub_agent, :ca_path, nil)

    assert :ok = IdentityStore.write(state_dir, trusted_material())

    assert {:ok, supervisor} = SecretHub.Agent.Application.start(:normal, [])
    assert Process.alive?(supervisor)
    assert Process.whereis(SecretHub.Agent.Supervisor) == supervisor

    assert Process.whereis(EndpointManager)
    assert Process.whereis(RuntimeBootstrapper)
    refute Process.whereis(ConnectionManager)
    assert Process.whereis(UDSServer)

    assert [%{url: @localhost_core_url}] = EndpointManager.get_health_status()

    assert File.exists?(socket_path)
  end

  test "starts the agent from SECRET_HUB_AGENT environment variables" do
    socket_path =
      Path.join(System.tmp_dir!(), "secrethub_agent_#{System.unique_integer([:positive])}.sock")

    state_dir =
      Path.join(System.tmp_dir!(), "secrethub_agent_state_#{System.unique_integer([:positive])}")

    core_url = "https://core-env.example.com"

    System.put_env("SECRET_HUB_AGENT_CORE_URL", core_url)

    System.put_env(
      "SECRET_HUB_AGENT_CORE_ENDPOINTS",
      "#{core_url}, https://core-env-secondary.example.com "
    )

    System.put_env("SECRET_HUB_AGENT_STATE_DIR", state_dir)
    System.put_env("SECRET_HUB_AGENT_ID", "agent-env-start")

    Application.put_env(:secrethub_agent, :enabled, true)
    Application.delete_env(:secrethub_agent, :agent_id)
    Application.delete_env(:secrethub_agent, :core_url)
    Application.delete_env(:secrethub_agent, :core_endpoints)
    Application.delete_env(:secrethub_agent, :state_dir)
    Application.put_env(:secrethub_agent, :endpoint_health_check_interval, 60_000)
    Application.put_env(:secrethub_agent, :socket_path, socket_path)
    Application.put_env(:secrethub_agent, :cert_path, nil)
    Application.put_env(:secrethub_agent, :key_path, nil)
    Application.put_env(:secrethub_agent, :ca_path, nil)

    assert :ok =
             IdentityStore.write(
               state_dir,
               trusted_material(agent_id: "agent-env-start", endpoint: "wss://127.0.0.1:1")
             )

    assert {:ok, _supervisor} = SecretHub.Agent.Application.start(:normal, [])

    assert Process.whereis(EndpointManager)
    assert Process.whereis(RuntimeBootstrapper)

    assert Enum.sort([core_url, "https://core-env-secondary.example.com"]) ==
             EndpointManager.get_health_status()
             |> Enum.map(& &1.url)
             |> Enum.sort()

    assert File.exists?(socket_path)
  end

  test "preserves legacy certificate path startup when trusted state is missing" do
    socket_path =
      Path.join(System.tmp_dir!(), "secrethub_agent_#{System.unique_integer([:positive])}.sock")

    state_dir =
      Path.join(System.tmp_dir!(), "secrethub_agent_state_#{System.unique_integer([:positive])}")

    cert_dir =
      Path.join(System.tmp_dir!(), "secrethub_agent_certs_#{System.unique_integer([:positive])}")

    File.mkdir_p!(cert_dir)

    material = trusted_material()
    cert_path = Path.join(cert_dir, "agent-cert.pem")
    key_path = Path.join(cert_dir, "agent-key.pem")
    ca_path = Path.join(cert_dir, "ca-chain.pem")

    File.write!(cert_path, material.certificate_pem)
    File.write!(key_path, material.private_key_pem)
    File.write!(ca_path, material.ca_chain_pem)

    Application.put_env(:secrethub_agent, :enabled, true)
    Application.put_env(:secrethub_agent, :agent_id, "agent-test-localhost")
    Application.put_env(:secrethub_agent, :core_url, "wss://127.0.0.1:1")
    Application.put_env(:secrethub_agent, :core_endpoints, ["wss://127.0.0.1:1"])
    Application.put_env(:secrethub_agent, :state_dir, state_dir)
    Application.put_env(:secrethub_agent, :endpoint_health_check_interval, 60_000)
    Application.put_env(:secrethub_agent, :socket_path, socket_path)
    Application.put_env(:secrethub_agent, :cert_path, cert_path)
    Application.put_env(:secrethub_agent, :key_path, key_path)
    Application.put_env(:secrethub_agent, :ca_path, ca_path)

    assert {:ok, _supervisor} = SecretHub.Agent.Application.start(:normal, [])

    assert Process.whereis(RuntimeBootstrapper)
    assert wait_for_process(ConnectionManager)
    assert Process.whereis(UDSServer)
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
    try do
      case Process.whereis(name) do
        nil -> :ok
        pid -> GenServer.stop(pid, :normal, 1000)
      end
    catch
      :exit, _reason -> :ok
    end
  end

  defp stop_agent_processes do
    stop_registered_process(SecretHub.Agent.Supervisor)
    stop_registered_process(Connection)
    stop_registered_process(ConnectionManager)
    stop_registered_process(EndpointManager)
    stop_registered_process(RuntimeBootstrapper)
    stop_registered_process(UDSServer)
  end

  defp wait_for_process(name, attempts \\ 20)

  defp wait_for_process(name, attempts) when attempts > 0 do
    case Process.whereis(name) do
      nil ->
        Process.sleep(50)
        wait_for_process(name, attempts - 1)

      pid ->
        pid
    end
  end

  defp wait_for_process(_name, 0), do: nil

  defp agent_system_env do
    [
      "SECRET_HUB_AGENT_CORE_URL",
      "SECRET_HUB_AGENT_CORE_ENDPOINTS",
      "SECRET_HUB_AGENT_STATE_DIR",
      "SECRET_HUB_AGENT_ID",
      "SECRET_HUB_AGENT_CERT_PATH",
      "SECRET_HUB_AGENT_KEY_PATH",
      "SECRET_HUB_AGENT_CA_PATH"
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
