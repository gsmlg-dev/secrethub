defmodule SecretHub.Web.RuntimeConfigIntegrationTest do
  use ExUnit.Case, async: true

  alias SecretHub.Human.RuntimeRole
  alias SecretHub.Shared.RuntimeSecrets

  @project_root Path.expand("../../../..", __DIR__)
  @compile_config Path.join(@project_root, "config/config.exs")
  @runtime_config Path.join(@project_root, "config/core_runtime.exs")
  @result_prefix "SECRET_HUB_WEB_RUNTIME_CONFIG="

  @base_env [
    {"DATABASE_URL", "postgresql://core:core@localhost/secrethub_runtime_config"},
    {"RELEASE_DISTRIBUTION", "none"},
    {"AUDIT_HMAC_KEY", Base.encode64(String.duplicate("a", 32))},
    {"AUDIT_HMAC_KEY_ID", "runtime-config-test"},
    {"SECRET_HUB_MANAGEMENT_ORIGIN", "https://admin.example.test"},
    {"SECRET_HUB_CLUSTER_NODE_ID", "runtime-config-test"},
    {"SECRET_KEY_BASE", String.duplicate("c", 64)},
    {"SECRETHUB_ROLE", "core"}
  ]

  @probe """
  config = Config.Reader.read!(#{inspect(@runtime_config)}, env: :prod)
  web_config = Keyword.fetch!(config, :secrethub_web)
  endpoint_config = Keyword.fetch!(web_config, SecretHub.Web.Endpoint)
  agent_endpoint_config = Keyword.get(web_config, SecretHub.Web.AgentEndpoint, [])

  payload = %{
    admin_cert_fingerprints: Keyword.get(web_config, :ADMIN_CERT_FINGERPRINTS),
    endpoint: endpoint_config,
    agent_endpoint: agent_endpoint_config
  }

  IO.puts(#{inspect(@result_prefix)} <> Base.encode64(:erlang.term_to_binary(payload)))
  """

  test "management uses private HTTP behind the canonical HTTPS proxy origin" do
    assert %{admin_cert_fingerprints: nil, endpoint: endpoint} = read_runtime_config()
    assert endpoint[:https] == nil
    assert endpoint[:server] == nil
    assert endpoint[:http] == [ip: {127, 0, 0, 1}, port: 4664]
    assert endpoint[:url] == [scheme: "https", host: "admin.example.test", port: 443, path: ""]
    assert endpoint[:trusted_proxy_ips] == [{127, 0, 0, 1}]
    assert endpoint[:check_origin] == ["https://admin.example.test"]
  end

  test "production admin sessions use secure cookies" do
    config = Config.Reader.read!(@compile_config, env: :prod)

    assert config
           |> Keyword.fetch!(:secrethub_web)
           |> Keyword.fetch!(SecretHub.Web.Endpoint)
           |> Keyword.fetch!(:session_options)
           |> Keyword.fetch!(:secure)
  end

  test "the former native admin mTLS listener is refused even with complete TLS inputs" do
    {output, status} =
      run_runtime_config([
        {"SECRET_HUB_ADMIN_CERT_FINGERPRINTS", String.duplicate("a", 64)},
        {"SECRET_HUB_ADMIN_ENDPOINT_CA_CERT_PATH", "/run/secrethub/admin/ca.pem"},
        {"SECRET_HUB_ADMIN_ENDPOINT_CERT_PATH", "/run/secrethub/admin/server.pem"},
        {"SECRET_HUB_ADMIN_ENDPOINT_KEY_PATH", "/run/secrethub/admin/server-key.pem"},
        {"SECRET_HUB_ADMIN_ENDPOINT_SERVER", "true"}
      ])

    assert status != 0
    assert output =~ "SECRET_HUB_ADMIN_ENDPOINT_SERVER: unsupported_duplicate_authentication"
  end

  test "the separate Agent mTLS listener requires peer certificates" do
    %{agent_endpoint: endpoint} = read_runtime_config(agent_endpoint_env())
    https = endpoint[:https]
    transport = https[:thousand_island_options][:transport_options]

    assert endpoint[:server] == true
    assert https[:port] == 4665
    assert https[:certfile] == "/run/secrethub/agent/server.pem"
    assert https[:keyfile] == "/run/secrethub/agent/server-key.pem"
    assert transport[:cacertfile] == ~c"/run/secrethub/agent/ca.pem"
    assert transport[:fail_if_no_peer_cert] == true
    assert transport[:verify] == :verify_peer
    assert transport[:versions] == [:"tlsv1.2", :"tlsv1.3"]
  end

  test "the separate Agent mTLS listener requires every TLS file path" do
    for key <- [
          "SECRET_HUB_AGENT_ENDPOINT_CA_CERT_PATH",
          "SECRET_HUB_AGENT_ENDPOINT_CERT_PATH",
          "SECRET_HUB_AGENT_ENDPOINT_KEY_PATH"
        ] do
      overrides = List.keydelete(agent_endpoint_env(), key, 0)
      {output, status} = run_runtime_config(overrides)

      assert status != 0
      assert output =~ key
    end
  end

  test "management, machine and Agent listeners cannot reuse each other's ports" do
    for overrides <- [
          [{"SECRET_HUB_MACHINE_PORT", "4664"}],
          [{"SECRET_HUB_AGENT_ENDPOINT_PORT", "4664"}],
          [{"SECRET_HUB_MACHINE_PORT", "4665"}]
        ] do
      {output, status} = run_runtime_config(overrides)
      assert status != 0
      assert output =~ "listeners: conflicting_ports"
    end
  end

  defp agent_endpoint_env do
    [
      {"SECRET_HUB_AGENT_ENDPOINT_CA_CERT_PATH", "/run/secrethub/agent/ca.pem"},
      {"SECRET_HUB_AGENT_ENDPOINT_CERT_PATH", "/run/secrethub/agent/server.pem"},
      {"SECRET_HUB_AGENT_ENDPOINT_KEY_PATH", "/run/secrethub/agent/server-key.pem"},
      {"SECRET_HUB_AGENT_ENDPOINT_SERVER", "true"}
    ]
  end

  defp read_runtime_config(overrides \\ []) do
    {output, status} = run_runtime_config(overrides)
    assert status == 0, output

    assert [_, encoded] = String.split(output, @result_prefix, parts: 2)
    assert {:ok, payload} = encoded |> String.trim() |> Base.decode64()

    :erlang.binary_to_term(payload, [:safe])
  end

  defp run_runtime_config(overrides) do
    runtime_ebins =
      for module <- [RuntimeRole, RuntimeSecrets, Ecto.Repo.Supervisor] do
        Code.ensure_loaded!(module)
        module |> :code.which() |> List.to_string() |> Path.dirname()
      end

    runtime_paths = Enum.flat_map(runtime_ebins, &["-pa", &1])

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
        [System.find_executable("elixir"), "--erl", "+S 2:2"] ++ runtime_paths ++ ["-e", @probe],
      cd: @project_root,
      stderr_to_stdout: true
    )
  end
end
