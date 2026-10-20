defmodule SecretHub.Agent.DevConfigIntegrationTest do
  use ExUnit.Case, async: true

  @project_root Path.expand("../../../..", __DIR__)
  @dev_config Path.join(@project_root, "config/dev.exs")
  @result_prefix "SECRET_HUB_DEV_CONFIG="

  @probe """
  config = Config.Reader.read!(#{inspect(@dev_config)}, env: :dev)
  web = Keyword.fetch!(config, :secrethub_web)
  payload = %{
    agent:
      config
      |> Keyword.fetch!(:secrethub_agent)
      |> Keyword.take([:enabled, :core_url, :state_dir, :socket_path]),
    endpoint: Keyword.take(Keyword.fetch!(web, SecretHub.Web.Endpoint), [:http]),
    trusted_endpoint: Keyword.get(web, :agent_trusted_endpoint)
  }
  IO.puts(#{inspect(@result_prefix)} <> Base.encode64(:erlang.term_to_binary(payload)))
  """

  test "default enrollment URL uses the Agent HTTPS listener without enabling Agent" do
    %{agent: agent, endpoint: endpoint, trusted_endpoint: trusted_endpoint} = read_dev_config()

    assert endpoint[:http][:port] == 4664
    assert agent[:core_url] == "https://localhost:4665"
    assert agent[:enabled] == false
    assert agent[:socket_path] == "/tmp/secrethub_dev_agent.sock"
    assert trusted_endpoint == "wss://localhost:4665/agent/socket/websocket"
  end

  test "PORT takes precedence over PHX_PORT for Core without changing Agent enrollment" do
    %{agent: agent, endpoint: endpoint} =
      read_dev_config([{"PORT", "4774"}, {"PHX_PORT", "4884"}])

    assert endpoint[:http][:port] == 4774
    assert agent[:core_url] == "https://localhost:4665"
  end

  test "PHX_PORT configures Core without changing Agent enrollment when PORT is absent" do
    %{agent: agent, endpoint: endpoint} = read_dev_config([{"PHX_PORT", "4884"}])

    assert endpoint[:http][:port] == 4884
    assert agent[:core_url] == "https://localhost:4665"
  end

  test "an explicit Agent enrollment URL overrides the local Core URL" do
    %{agent: agent, endpoint: endpoint} =
      read_dev_config([
        {"PORT", "4774"},
        {"SECRET_HUB_AGENT_CORE_URL", "https://core.example.test:4994"}
      ])

    assert endpoint[:http][:port] == 4774
    assert agent[:core_url] == "https://core.example.test:4994"
  end

  test "Agent state and consumer socket paths honor their environment overrides" do
    %{agent: agent} =
      read_dev_config([
        {"SECRET_HUB_AGENT_STATE_DIR", "/fixture/agent-state"},
        {"SECRET_HUB_AGENT_SOCKET_PATH", "/fixture/run/agent.sock"}
      ])

    assert agent[:state_dir] == "/fixture/agent-state"
    assert agent[:socket_path] == "/fixture/run/agent.sock"
    assert agent[:enabled] == false
  end

  test "trusted runtime discovery honors endpoint overrides and Agent remains opt-in" do
    %{agent: agent, trusted_endpoint: trusted_endpoint} =
      read_dev_config([
        {"SECRET_HUB_AGENT_ENDPOINT_HOST", "core.dev.test"},
        {"SECRET_HUB_AGENT_ENDPOINT_PORT", "4775"},
        {"SECRET_HUB_AGENT_ENABLED", "true"}
      ])

    assert trusted_endpoint == "wss://core.dev.test:4775/agent/socket/websocket"
    assert agent[:enabled] == true
  end

  defp read_dev_config(overrides \\ []) do
    environment =
      overrides
      |> Map.new()
      |> Map.put("PATH", System.fetch_env!("PATH"))
      |> Enum.map(fn {key, value} -> "#{key}=#{value}" end)

    {output, status} =
      System.cmd(
        System.find_executable("env"),
        ["-i" | environment] ++
          [System.find_executable("elixir"), "--erl", "+S 2:2", "-e", @probe],
        cd: @project_root,
        stderr_to_stdout: true
      )

    assert status == 0, output
    assert [_, encoded] = String.split(output, @result_prefix, parts: 2)
    assert {:ok, payload} = encoded |> String.trim() |> Base.decode64()
    :erlang.binary_to_term(payload, [:safe])
  end
end
