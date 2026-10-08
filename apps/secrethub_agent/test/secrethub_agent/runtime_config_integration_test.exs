defmodule SecretHub.Agent.RuntimeConfigIntegrationTest do
  use ExUnit.Case, async: true

  alias SecretHub.Shared.RuntimeSecrets

  @project_root Path.expand("../../../..", __DIR__)
  @runtime_config Path.join(@project_root, "config/agent_runtime.exs")
  @result_prefix "SECRET_HUB_AGENT_RUNTIME_CONFIG="
  @path_inputs ~w(SECRET_HUB_AGENT_HOST_KEY_PATH SECRET_HUB_AGENT_STATE_DIR SECRET_HUB_AGENT_SOCKET_PATH SECRET_HUB_CLIENT_AUTH_BUNDLE_DIR)
  @base_env [
    {"RELEASE_DISTRIBUTION", "none"},
    {"SECRET_HUB_AGENT_CORE_URL", "https://core.example.test"},
    {"SECRET_HUB_AGENT_HOST_KEY_PATH", "/fixture/host-key"},
    {"SECRET_HUB_AGENT_STATE_DIR", "/fixture/state"},
    {"SECRET_HUB_AGENT_SOCKET_PATH", "/fixture/run/agent.sock"},
    {"SECRET_HUB_CLIENT_AUTH_BUNDLE_DIR", "/fixture/bundle"}
  ]

  @probe """
  config = Config.Reader.read!(#{inspect(@runtime_config)}, env: :prod)
  payload = %{
    agent: Keyword.fetch!(config, :secrethub_agent),
    core?: Keyword.has_key?(config, :secrethub_core),
    human?: Keyword.has_key?(config, :secrethub_human),
    web?: Keyword.has_key?(config, :secrethub_web)
  }
  IO.puts(#{inspect(@result_prefix)} <> Base.encode64(:erlang.term_to_binary(payload)))
  """

  test "standalone Agent config needs only its role-specific runtime inputs" do
    assert %{agent: agent, core?: false, human?: false, web?: false} = read_runtime_config()
    assert agent[:core_url] == "https://core.example.test"
    assert agent[:launch_profile] == :single_operator
    assert agent[:state_dir] == "/fixture/state"
    assert agent[:socket_path] == "/fixture/run/agent.sock"
    assert agent[:client_auth_bundle_dir] == "/fixture/bundle"

    assert agent[:enrollment_opts][:paths] == [
             ecdsa: "/fixture/host-key",
             rsa: "/fixture/host-key"
           ]

    assert agent[:enrollment_req_options] == []
  end

  test "standalone Agent config rejects a missing or blank Core URL" do
    for {core_url, reason} <- [{nil, "missing"}, {"", "empty"}] do
      {output, status} = run_runtime_config([{"SECRET_HUB_AGENT_CORE_URL", core_url}])
      assert status != 0
      assert output =~ "SECRET_HUB_AGENT_CORE_URL: #{reason}"
    end
  end

  test "standalone Agent config rejects insecure enrollment URLs" do
    {output, status} =
      run_runtime_config([{"SECRET_HUB_AGENT_CORE_URL", "http://core.example.test"}])

    assert status != 0
    assert output =~ "SECRET_HUB_AGENT_CORE_URL: invalid_https_url"
  end

  test "standalone Agent config requires every persistent identity and consumer path" do
    for input <- @path_inputs, {value, reason} <- [{nil, "missing"}, {"", "empty"}] do
      {output, status} = run_runtime_config([{input, value}])
      assert status != 0
      assert output =~ "#{input}: #{reason}"
    end
  end

  test "an optional private enrollment CA retains peer verification" do
    %{agent: agent} =
      read_runtime_config([
        {"SECRET_HUB_AGENT_ENROLLMENT_CA_PATH", "/fixture/enrollment-ca.pem"}
      ])

    transport = agent[:enrollment_req_options][:connect_options][:transport_opts]
    assert transport[:cacertfile] == "/fixture/enrollment-ca.pem"
    assert transport[:verify] == :verify_peer
  end

  defp read_runtime_config(overrides \\ []) do
    {output, status} = run_runtime_config(overrides)
    assert status == 0, output
    assert [_, encoded] = String.split(output, @result_prefix, parts: 2)
    assert {:ok, payload} = encoded |> String.trim() |> Base.decode64()
    :erlang.binary_to_term(payload, [:safe])
  end

  defp run_runtime_config(overrides) do
    Code.ensure_loaded!(RuntimeSecrets)
    shared_ebin = RuntimeSecrets |> :code.which() |> List.to_string() |> Path.dirname()

    runtime_env =
      @base_env
      |> Map.new()
      |> Map.merge(Map.new(overrides))
      |> Map.put("PATH", System.fetch_env!("PATH"))
      |> Enum.reject(fn {_key, value} -> is_nil(value) end)
      |> Enum.map(fn {key, value} -> "#{key}=#{value}" end)

    System.cmd(
      System.find_executable("env"),
      ["-i" | runtime_env] ++
        [System.find_executable("elixir"), "--erl", "+S 2:2", "-pa", shared_ebin, "-e", @probe],
      cd: @project_root,
      stderr_to_stdout: true
    )
  end
end
