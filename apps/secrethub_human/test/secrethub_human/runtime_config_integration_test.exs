defmodule SecretHub.Human.RuntimeConfigIntegrationTest do
  use ExUnit.Case, async: true

  alias SecretHub.Human.RuntimeRole

  @project_root Path.expand("../../../..", __DIR__)
  @runtime_config Path.join(@project_root, "config/core_runtime.exs")
  @result_prefix "SECRET_HUB_RUNTIME_CONFIG="

  @base_env [
    {"AUDIT_HMAC_KEY", Base.encode64(String.duplicate("a", 32))},
    {"AUDIT_HMAC_KEY_ID", "runtime-config-test"},
    {"DATABASE_URL", "postgresql://core:core@localhost/secrethub_runtime_config"},
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
    {"RELEASE_DISTRIBUTION", "none"},
    {"SECRET_HUB_AGENT_ENDPOINT_SERVER", nil},
    {"SECRET_HUB_CLUSTER_NODE_ID", "runtime-config-test"},
    {"SECRET_HUB_MANAGEMENT_ORIGIN", "https://management.example.test"},
    {"SECRET_KEY_BASE", String.duplicate("c", 64)},
    {"SECRETHUB_ROLE", nil}
  ]

  @probe """
  Application.put_env(:secrethub_core, :human_mounts, %{"stale-in-memory-mount" => %{}})
  config = Config.Reader.read!(#{inspect(@runtime_config)}, env: :prod)
  core_config = Keyword.fetch!(config, :secrethub_core)
  human_config = Keyword.fetch!(config, :secrethub_human)
  web_config = Keyword.fetch!(config, :secrethub_web)
  core_repo_config = Keyword.get(core_config, SecretHub.Core.Repo, [])
  endpoint_config = Keyword.get(human_config, SecretHub.HumanWeb.Endpoint, [])
  mounts = Keyword.get(core_config, :human_mounts, %{})
  Application.put_env(:secrethub_core, :human_mounts, %{})
  second_config = Config.Reader.read!(#{inspect(@runtime_config)}, env: :prod)
  second_mounts = second_config |> Keyword.fetch!(:secrethub_core) |> Keyword.get(:human_mounts, %{})

  started_apps =
    Application.started_applications()
    |> Enum.map(&elem(&1, 0))
    |> Enum.filter(&(&1 in [:secrethub_core, :secrethub_web, :secrethub_human]))

  payload = %{
    core_pool_size: core_repo_config[:pool_size],
    dns_cluster_query: Keyword.get(web_config, :dns_cluster_query),
    enabled: Keyword.fetch!(human_config, :enabled),
    launch_profile: Keyword.fetch!(core_config, :launch_profile),
    endpoint_configured?:
      Keyword.has_key?(human_config, SecretHub.HumanWeb.Endpoint),
    repo_configured?: Keyword.has_key?(human_config, SecretHub.Human.Repo),
    server: endpoint_config[:server],
    started_apps: started_apps,
    mount_names: Enum.sort(Map.keys(mounts)),
    catalog_restored: mounts == second_mounts
  }

  IO.puts(#{inspect(@result_prefix)} <> Base.encode64(:erlang.term_to_binary(payload)))
  """

  test "production defaults to single-operator Core with Human disabled" do
    assert %{
             enabled: false,
             endpoint_configured?: false,
             launch_profile: :single_operator,
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

  test "single-operator production rejects all even with complete Human variables" do
    {output, status} = run_runtime_config(human_env())

    assert status != 0
    assert output =~ "SECRETHUB_ROLE: single_operator_requires_core"
  end

  test "PHX_SERVER cannot enable Human under the single-operator Core profile" do
    assert %{enabled: false, endpoint_configured?: false, server: nil} =
             read_runtime_config([{"PHX_SERVER", "true"}, {"SECRETHUB_ROLE", "core"}])
  end

  test "single-operator production rejects Human before reading Human secrets" do
    {output, status} = run_runtime_config([{"SECRETHUB_ROLE", "human"}])

    assert status != 0
    assert output =~ "SECRETHUB_ROLE: single_operator_requires_core"
  end

  test "explicit co-hosted opt-in configures independent Human runtime" do
    env =
      human_env() ++
        [
          {"HUMAN_ENABLED", "true"},
          {"HUMAN_ENDPOINT_ORIGIN", "https://vault.example.test"},
          {"HUMAN_ATTACHMENT_DIRECTORY", "/tmp/human-runtime-attachments"}
        ]

    assert %{
             enabled: true,
             launch_profile: :human_operator,
             repo_configured?: true,
             endpoint_configured?: true,
             started_apps: []
           } = read_runtime_config(env)
  end

  test "co-hosted opt-in rejects reused keys, public bind and out-of-range TTL" do
    env =
      human_env() ++
        [
          {"HUMAN_ENABLED", "true"},
          {"HUMAN_ENDPOINT_ORIGIN", "https://vault.example.test"},
          {"HUMAN_ATTACHMENT_DIRECTORY", "/tmp/human-runtime-attachments"}
        ]

    for override <- [
          [{"HUMAN_SECRET_KEY_BASE", String.duplicate("c", 64)}],
          [{"HUMAN_ENDPOINT_BIND_IP", "0.0.0.0"}],
          [{"HUMAN_REVEAL_TTL", "61"}],
          [{"HUMAN_DATABASE_URL", "postgresql://core:core@localhost/secrethub_human"}]
        ] do
      {_output, status} = run_runtime_config(env ++ override)
      assert status != 0
    end
  end

  test "invalid roles fail explicitly" do
    {output, status} = run_runtime_config([{"SECRETHUB_ROLE", "invalid"}])

    assert status != 0
    assert output =~ ~s(invalid SECRETHUB_ROLE "invalid")
    assert output =~ "expected all, core, human, or agent"
  end

  @tag :tmp_dir
  test "dynamic production boot reloads validated mounts independently of VM memory", %{
    tmp_dir: dir
  } do
    path = Path.join(dir, "mounts.json")

    input = %{
      "postgres-runtime" => %{
        "engine" => "postgresql",
        "connection" => %{
          "database" => "runtime_database",
          "username" => "runtime_operator",
          "hostname" => "database.example.test",
          "ssl" => true
        },
        "roles" => %{"reader" => %{"schema" => "public", "privileges" => ["select"]}}
      }
    }

    File.write!(path, Jason.encode!(input))

    assert %{mount_names: ["postgres-runtime"], catalog_restored: true, started_apps: []} =
             read_runtime_config(dynamic_env() ++ [{"HUMAN_DYNAMIC_MOUNTS_FILE", path}])
  end

  @tag :tmp_dir
  test "enabled dynamic production rejects missing and malformed mount files without leaking contents",
       %{tmp_dir: dir} do
    {output, status} = run_runtime_config(dynamic_env())
    assert status != 0
    assert output =~ "HUMAN_DYNAMIC_MOUNTS_FILE: missing"
    canary = "MOUNT-CONFIG-SECRET-CANARY"
    path = Path.join(dir, canary <> ".json")
    File.write!(path, "{\"password\":\"#{canary}\"")
    {output, status} = run_runtime_config(dynamic_env() ++ [{"HUMAN_DYNAMIC_MOUNTS_FILE", path}])
    assert status != 0
    assert output =~ "HUMAN_DYNAMIC_MOUNTS_FILE: invalid_mount_config"
    refute output =~ canary
  end

  defp dynamic_env do
    human_env() ++
      [
        {"HUMAN_ENABLED", "true"},
        {"HUMAN_DYNAMIC_ENABLED", "true"},
        {"HUMAN_ENDPOINT_ORIGIN", "https://vault.example.test"},
        {"HUMAN_ATTACHMENT_DIRECTORY", "/tmp/human-runtime-attachments"}
      ]
  end

  defp human_env do
    [
      {"HUMAN_DATABASE_URL", "postgresql://human:human@localhost/secrethub_human_runtime_config"},
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
    runtime_paths =
      [
        RuntimeRole,
        SecretHub.Human.RuntimeConfig,
        SecretHub.Shared.RuntimeConfig,
        SecretHub.Core.HumanAccess.PostgreSQLBackend,
        Jason,
        Ecto.Repo.Supervisor
      ]
      |> Enum.map(fn module ->
        Code.ensure_loaded!(module)

        path =
          case :code.which(module) do
            :cover_compiled ->
              {:file, beam_path} = :cover.is_compiled(module)
              beam_path

            beam_path ->
              beam_path
          end

        path |> List.to_string() |> Path.dirname()
      end)
      |> Enum.uniq()
      |> Enum.flat_map(&["-pa", &1])

    elixir = System.find_executable("elixir")
    env = System.find_executable("env")

    runtime_env =
      @base_env
      |> Map.new()
      |> Map.merge(Map.new(overrides))
      |> Map.put("PATH", System.fetch_env!("PATH"))
      |> Enum.reject(fn {_key, value} -> is_nil(value) end)
      |> Enum.map(fn {key, value} -> "#{key}=#{value}" end)

    System.cmd(
      env,
      ["-i" | runtime_env] ++ [elixir, "--erl", "+S 2:2"] ++ runtime_paths ++ ["-e", @probe],
      cd: @project_root,
      env: caller_env,
      stderr_to_stdout: true
    )
  end
end
