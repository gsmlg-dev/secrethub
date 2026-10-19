defmodule SecretHub.Agent.RuntimeConfigIntegrationTest do
  use ExUnit.Case, async: true

  @project_root Path.expand("../../../..", __DIR__)
  @runtime_config Path.join(@project_root, "config/agent_runtime.exs")
  @result_prefix "SECRET_HUB_AGENT_RUNTIME_CONFIG="
  @path_inputs ~w(SECRET_HUB_AGENT_HOST_KEY_PATH SECRET_HUB_AGENT_STATE_DIR SECRET_HUB_AGENT_SOCKET_PATH SECRET_HUB_CLIENT_AUTH_BUNDLE_DIR)
  @base_env [
    {"RELEASE_DISTRIBUTION", "none"},
    {"SECRET_HUB_AGENT_CONFIG_FILE",
     Path.join(@project_root, "apps/secrethub_agent/test/fixtures/empty-agent.toml")},
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

  @startup_probe """
  config = Config.Reader.read!(#{inspect(@runtime_config)}, env: :prod)
  Application.put_all_env(config, persistent: true)
  {:ok, _apps} = Application.ensure_all_started(:secrethub_agent)
  true = is_pid(Process.whereis(SecretHub.Agent.Supervisor))
  true = is_pid(Process.whereis(SecretHub.Agent.UDSServer))
  true = is_pid(Process.whereis(SecretHub.Agent.PKI.TrustBundleManager))
  IO.puts("SECRET_HUB_AGENT_FILE_STARTUP_OK")
  """

  test "standalone Agent config needs only its role-specific runtime inputs" do
    assert %{agent: agent, core?: false, human?: false, web?: false} = read_runtime_config()
    assert agent[:core_url] == "https://core.example.test"
    assert agent[:enabled] == true
    assert agent[:launch_profile] == :single_operator
    assert agent[:enabled_features] == [:static_secrets, :client_auth_pki]
    assert agent[:client_auth_pki_enabled] == true
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

  @tag :tmp_dir
  test "standalone Agent config loads from TOML without option environment variables", %{
    tmp_dir: dir
  } do
    path = write_config!(dir)

    %{agent: agent, core?: false, human?: false, web?: false} =
      read_runtime_config(file_environment(path))

    assert agent[:core_url] == "https://file.example.test:4668"
    assert agent[:state_dir] == Path.join(dir, "state")
    assert agent[:socket_path] == Path.join(dir, "run/agent.sock")
    assert agent[:client_auth_bundle_dir] == Path.join(dir, "state/client-auth")

    assert agent[:enrollment_opts][:paths] ==
             [ecdsa: Path.join(dir, "host-key"), rsa: Path.join(dir, "host-key")]

    assert agent[:enrollment_req_options][:connect_options][:transport_opts] ==
             [cacertfile: Path.join(dir, "ca.pem"), verify: :verify_peer]
  end

  @tag :tmp_dir
  test "standalone Agent config honors direct and value-file overrides over TOML", %{tmp_dir: dir} do
    path = write_config!(dir)
    value_path = Path.join(dir, "state.value")
    File.write!(value_path, "/override/state\n")

    %{agent: agent} =
      read_runtime_config(
        file_environment(path) ++
          [
            {"SECRET_HUB_AGENT_CORE_URL", "https://override.example.test"},
            {"SECRET_HUB_AGENT_STATE_DIR_FILE", value_path}
          ]
      )

    assert agent[:core_url] == "https://override.example.test"
    assert agent[:state_dir] == "/override/state"
    assert agent[:socket_path] == Path.join(dir, "run/agent.sock")
  end

  @tag :tmp_dir
  test "standalone Agent config fails on an explicit missing or malformed file", %{tmp_dir: dir} do
    path = Path.join(dir, "private-config.toml")

    {output, status} = run_runtime_config([{"SECRET_HUB_AGENT_CONFIG_FILE", path}])
    assert status != 0
    assert output =~ "SECRET_HUB_AGENT_CONFIG_FILE: invalid_file"
    refute output =~ path

    File.write!(path, "private-value = \"must-not-disclose\n")
    {output, status} = run_runtime_config([{"SECRET_HUB_AGENT_CONFIG_FILE", path}])
    assert status != 0
    assert output =~ "SECRET_HUB_AGENT_CONFIG_FILE: invalid_toml"
    refute output =~ "must-not-disclose"
    refute output =~ path
  end

  @tag :tmp_dir
  test "standalone Agent starts from a file without HOME or option environment variables", %{
    tmp_dir: dir
  } do
    host_key = Path.join(dir, "host-key")

    socket_path =
      Path.join(System.tmp_dir!(), "sh-config-#{System.unique_integer([:positive])}.sock")

    on_exit(fn -> File.rm(socket_path) end)

    for name <- ["state", "bundle"], do: File.mkdir_p!(Path.join(dir, name))

    {_, 0} =
      System.cmd("ssh-keygen", ["-q", "-t", "rsa", "-b", "2048", "-N", "", "-f", host_key])

    path = Path.join(dir, "startup.toml")

    File.write!(path, """
    core_url = "https://127.0.0.1:1"
    host_key_path = "host-key"
    state_dir = "state"
    socket_path = "#{socket_path}"
    client_auth_bundle_dir = "bundle"
    """)

    {output, status} = run_runtime_config(file_environment(path), @startup_probe)
    assert status == 0, output
    assert output =~ "SECRET_HUB_AGENT_FILE_STARTUP_OK"
  end

  defp write_config!(dir) do
    path = Path.join(dir, "agent.toml")

    File.write!(path, """
    core_url = "https://file.example.test:4668"
    host_key_path = "host-key"
    state_dir = "state"
    socket_path = "run/agent.sock"
    client_auth_bundle_dir = "state/client-auth"
    enrollment_ca_path = "ca.pem"
    """)

    path
  end

  defp file_environment(path) do
    [{"SECRET_HUB_AGENT_CONFIG_FILE", path}] ++
      Enum.map(["SECRET_HUB_AGENT_CORE_URL" | @path_inputs], &{&1, nil})
  end

  defp read_runtime_config(overrides \\ []) do
    {output, status} = run_runtime_config(overrides)
    assert status == 0, output
    assert [_, encoded] = String.split(output, @result_prefix, parts: 2)
    assert {:ok, payload} = encoded |> String.trim() |> Base.decode64()
    :erlang.binary_to_term(payload, [:safe])
  end

  defp run_runtime_config(overrides, probe \\ @probe) do
    code_paths =
      :secrethub_agent
      |> Application.app_dir()
      |> Path.dirname()
      |> Path.join("*/ebin")
      |> Path.wildcard()
      |> Enum.flat_map(&["-pa", &1])

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
        [System.find_executable("elixir"), "--erl", "+S 2:2"] ++ code_paths ++ ["-e", probe],
      cd: @project_root,
      stderr_to_stdout: true
    )
  end
end
