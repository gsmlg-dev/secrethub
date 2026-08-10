defmodule SecretHub.Human.RuntimeConfigIntegrationTest do
  use ExUnit.Case, async: true

  alias SecretHub.Human.RuntimeRole

  @project_root Path.expand("../../../..", __DIR__)
  @runtime_config Path.join(@project_root, "config/runtime.exs")
  @result_prefix "SECRET_HUB_RUNTIME_CONFIG="

  @base_env [
    {"DATABASE_URL", "ecto://core:core@localhost/secrethub_runtime_config"},
    {"ECTO_IPV6", nil},
    {"HUMAN_DATABASE_URL", nil},
    {"HUMAN_DB_POOL_SIZE", nil},
    {"HUMAN_ENDPOINT_HOST", nil},
    {"HUMAN_ENDPOINT_PORT", nil},
    {"HUMAN_SECRET_KEY_BASE", nil},
    {"MIX_ENV", nil},
    {"PHX_HOST", nil},
    {"PHX_SERVER", nil},
    {"PORT", nil},
    {"SECRET_HUB_AGENT_ENDPOINT_SERVER", nil},
    {"SECRET_HUB_CLUSTER_NODE_ID", "runtime-config-test"},
    {"SECRET_KEY_BASE", String.duplicate("c", 64)},
    {"SECRETHUB_ROLE", nil}
  ]

  @probe """
  config = Config.Reader.read!(#{inspect(@runtime_config)}, env: :prod)
  core_config = Keyword.fetch!(config, :secrethub_core)
  human_config = Keyword.fetch!(config, :secrethub_human)
  web_config = Keyword.fetch!(config, :secrethub_web)
  core_repo_config = Keyword.get(core_config, SecretHub.Core.Repo, [])
  repo_config = Keyword.get(human_config, SecretHub.Human.Repo, [])
  endpoint_config = Keyword.get(human_config, SecretHub.HumanWeb.Endpoint, [])

  started_apps =
    Application.started_applications()
    |> Enum.map(&elem(&1, 0))
    |> Enum.filter(&(&1 in [:secrethub_core, :secrethub_web, :secrethub_human]))

  payload = %{
    check_origin: endpoint_config[:check_origin],
    core_pool_size: core_repo_config[:pool_size],
    dns_cluster_query: Keyword.get(web_config, :dns_cluster_query),
    enabled: Keyword.fetch!(human_config, :enabled),
    endpoint_configured?:
      Keyword.has_key?(human_config, SecretHub.HumanWeb.Endpoint),
    endpoint_http_port: endpoint_config |> Keyword.get(:http, []) |> Keyword.get(:port),
    endpoint_url_port: endpoint_config |> Keyword.get(:url, []) |> Keyword.get(:port),
    pool_size: repo_config[:pool_size],
    repo_configured?: Keyword.has_key?(human_config, SecretHub.Human.Repo),
    repo_url_configured?: is_binary(repo_config[:url]),
    secret_key_base_configured?: is_binary(endpoint_config[:secret_key_base]),
    server: endpoint_config[:server],
    started_apps: started_apps
  }

  IO.puts(#{inspect(@result_prefix)} <> Base.encode64(:erlang.term_to_binary(payload)))
  """

  test "production defaults to the disabled Core role without Human variables" do
    assert %{
             enabled: false,
             endpoint_configured?: false,
             repo_configured?: false,
             server: nil,
             started_apps: []
           } = read_runtime_config()
  end

  test "runtime configuration ignores unrelated caller environment" do
    assert %{
             core_pool_size: 10,
             dns_cluster_query: nil,
             enabled: false,
             started_apps: []
           } =
             read_runtime_config([], [
               {"DNS_CLUSTER_QUERY", "ambient.example"},
               {"POOL_SIZE", "not-a-number"}
             ])
  end

  test "production all role applies independent Human runtime configuration" do
    assert %{
             check_origin: :conn,
             enabled: true,
             endpoint_configured?: true,
             endpoint_http_port: 4666,
             endpoint_url_port: 4666,
             pool_size: 17,
             repo_configured?: true,
             repo_url_configured?: true,
             secret_key_base_configured?: true,
             server: nil,
             started_apps: []
           } = read_runtime_config(human_env())
  end

  test "Human endpoint server starts only when PHX_SERVER is present" do
    assert %{server: nil} = read_runtime_config(human_env())
    assert %{server: true} = read_runtime_config([{"PHX_SERVER", "true"} | human_env()])
  end

  test "production all role explicitly requires HUMAN_DATABASE_URL" do
    {output, status} =
      run_runtime_config([
        {"HUMAN_SECRET_KEY_BASE", String.duplicate("h", 64)},
        {"SECRETHUB_ROLE", "all"}
      ])

    assert status != 0
    assert output =~ "environment variable HUMAN_DATABASE_URL is missing"
  end

  test "invalid roles fail explicitly" do
    {output, status} = run_runtime_config([{"SECRETHUB_ROLE", "invalid"}])

    assert status != 0
    assert output =~ ~s(invalid SECRETHUB_ROLE "invalid")
    assert output =~ "expected all, core, human, or agent"
  end

  defp human_env do
    [
      {"HUMAN_DATABASE_URL", "ecto://human:human@localhost/secrethub_human_runtime_config"},
      {"HUMAN_DB_POOL_SIZE", "17"},
      {"HUMAN_SECRET_KEY_BASE", String.duplicate("h", 64)},
      {"SECRETHUB_ROLE", "all"}
    ]
  end

  defp read_runtime_config(env \\ [], caller_env \\ []) do
    {output, status} = run_runtime_config(env, caller_env)
    assert status == 0, output

    assert [_, encoded] = String.split(output, @result_prefix, parts: 2)
    assert {:ok, payload} = encoded |> String.trim() |> Base.decode64()

    :erlang.binary_to_term(payload, [:safe])
  end

  defp run_runtime_config(overrides, caller_env \\ []) do
    Code.ensure_loaded!(RuntimeRole)
    runtime_role_ebin = RuntimeRole |> :code.which() |> List.to_string() |> Path.dirname()
    elixir = System.find_executable("elixir")
    env = System.find_executable("env")

    runtime_env =
      @base_env
      |> Map.new()
      |> Map.merge(Map.new(overrides))
      |> Enum.reject(fn {_key, value} -> is_nil(value) end)
      |> Enum.map(fn {key, value} -> "#{key}=#{value}" end)

    System.cmd(
      env,
      ["-i" | runtime_env] ++ [elixir, "--erl", "+S 2:2", "-pa", runtime_role_ebin, "-e", @probe],
      cd: @project_root,
      env: caller_env,
      stderr_to_stdout: true
    )
  end
end
