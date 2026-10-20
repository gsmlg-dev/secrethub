defmodule SecretHub.Core.AgentListenerRuntimeConfigTest do
  use ExUnit.Case, async: false

  @moduletag :tmp_dir
  @runtime Path.expand("../../../../config/core_runtime.exs", __DIR__)
  @variables ~w(SECRET_HUB_AGENT_ENDPOINT_SERVER SECRET_HUB_AGENT_ENDPOINT_HOST
    SECRET_HUB_AGENT_ENDPOINT_PORT SECRET_HUB_AGENT_ENDPOINT_CERT_PATH
    SECRET_HUB_AGENT_ENDPOINT_KEY_PATH SECRET_HUB_AGENT_ENDPOINT_CA_CERT_PATH
    SECRET_HUB_MACHINE_ENDPOINT_SERVER)

  setup do
    saved = Map.new(@variables, &{&1, System.get_env(&1)})
    Enum.each(@variables, &System.delete_env/1)

    on_exit(fn ->
      Enum.each(saved, fn
        {name, nil} -> System.delete_env(name)
        {name, value} -> System.put_env(name, value)
      end)
    end)

    :ok
  end

  test "one HTTPS Agent listener permits enrollment and verifies presented certificates",
       context do
    System.put_env(%{
      "SECRET_HUB_AGENT_ENDPOINT_SERVER" => "true",
      "SECRET_HUB_AGENT_ENDPOINT_HOST" => "core.example.net",
      "SECRET_HUB_AGENT_ENDPOINT_CERT_PATH" => "/fixture/server.pem",
      "SECRET_HUB_AGENT_ENDPOINT_KEY_PATH" => "/fixture/server-key.pem",
      "SECRET_HUB_AGENT_ENDPOINT_CA_CERT_PATH" => "/fixture/ca.pem"
    })

    web = read_fragment(context.tmp_dir, agent_fragment())[:secrethub_web]
    endpoint = web[SecretHub.Web.AgentEndpoint]
    assert endpoint[:server]
    assert endpoint[:http] == false
    assert endpoint[:https][:port] == 4665

    assert [
             cacertfile: ~c"/fixture/ca.pem",
             verify: :verify_peer,
             fail_if_no_peer_cert: false,
             versions: [:"tlsv1.2", :"tlsv1.3"],
             ipv6_v6only: false
           ] = endpoint[:https][:thousand_island_options][:transport_options]

    assert web[:agent_trusted_endpoint] ==
             "wss://core.example.net:4665/agent/socket/websocket"
  end

  test "disabled Agent listener does not require TLS material", context do
    assert [] = read_fragment(context.tmp_dir, agent_fragment())
  end

  test "enabled Agent listener requires configured server material", context do
    System.put_env("SECRET_HUB_AGENT_ENDPOINT_SERVER", "true")

    assert_raise RuntimeError, ~r/SECRET_HUB_AGENT_ENDPOINT_CERT_PATH is required/, fn ->
      read_fragment(context.tmp_dir, agent_fragment())
    end
  end

  test "legacy machine enable setting cannot create a third listener", context do
    System.put_env("SECRET_HUB_MACHINE_ENDPOINT_SERVER", "true")

    fragment =
      @runtime
      |> File.stream!()
      |> Enum.drop_while(
        &(not String.starts_with?(&1, "  config :secrethub_web, SecretHub.Web.MachineEndpoint,"))
      )
      |> Enum.take_while(&(not String.starts_with?(&1, "    secret_key_base:")))
      |> Enum.join()

    config =
      read_fragment(
        context.tmp_dir,
        "alias SecretHub.Shared.RuntimeConfig\nagent_port = 4665\n" <>
          fragment <> "    secret_key_base: \"fixture\"\n"
      )

    assert config[:secrethub_web][SecretHub.Web.MachineEndpoint][:server] == false
    assert config[:secrethub_web][SecretHub.Web.MachineEndpoint][:http] == false
  end

  defp agent_fragment do
    @runtime
    |> File.stream!()
    |> Enum.drop_while(
      &(not String.starts_with?(&1, "if System.get_env(\"SECRET_HUB_AGENT_ENDPOINT_SERVER\")"))
    )
    |> Enum.take_while(&(&1 != "end\n"))
    |> Enum.join()
    |> Kernel.<>("end\n")
  end

  defp read_fragment(tmp_dir, fragment) do
    path = Path.join(tmp_dir, "listener.exs")
    File.write!(path, "import Config\n" <> fragment)
    Config.Reader.read!(path, env: :prod)
  end
end
