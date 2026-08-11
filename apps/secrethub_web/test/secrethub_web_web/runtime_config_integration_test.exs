defmodule SecretHub.Web.RuntimeConfigIntegrationTest do
  use ExUnit.Case, async: true

  alias SecretHub.Human.RuntimeRole

  @project_root Path.expand("../../../..", __DIR__)
  @compile_config Path.join(@project_root, "config/config.exs")
  @runtime_config Path.join(@project_root, "config/runtime.exs")
  @result_prefix "SECRET_HUB_WEB_RUNTIME_CONFIG="

  @base_env [
    {"DATABASE_URL", "ecto://core:core@localhost/secrethub_runtime_config"},
    {"ECTO_IPV6", nil},
    {"HUMAN_DATABASE_URL", nil},
    {"MIX_ENV", nil},
    {"PHX_HOST", nil},
    {"PHX_SERVER", nil},
    {"PORT", nil},
    {"SECRET_HUB_ADMIN_CERT_FINGERPRINTS", nil},
    {"SECRET_HUB_ADMIN_ENDPOINT_CA_CERT_PATH", nil},
    {"SECRET_HUB_ADMIN_ENDPOINT_CERT_PATH", nil},
    {"SECRET_HUB_ADMIN_ENDPOINT_KEY_PATH", nil},
    {"SECRET_HUB_ADMIN_ENDPOINT_PORT", nil},
    {"SECRET_HUB_ADMIN_ENDPOINT_SERVER", nil},
    {"SECRET_HUB_AGENT_ENDPOINT_SERVER", nil},
    {"SECRET_HUB_CLUSTER_NODE_ID", "runtime-config-test"},
    {"SECRET_KEY_BASE", String.duplicate("c", 64)},
    {"SECRETHUB_ROLE", "core"}
  ]

  @probe """
  config = Config.Reader.read!(#{inspect(@runtime_config)}, env: :prod)
  web_config = Keyword.fetch!(config, :secrethub_web)
  endpoint_config = Keyword.fetch!(web_config, SecretHub.Web.Endpoint)
  https_config = Keyword.get(endpoint_config, :https, [])

  transport_options =
    https_config
    |> Keyword.get(:thousand_island_options, [])
    |> Keyword.get(:transport_options, [])

  payload = %{
    admin_cert_fingerprints: Keyword.get(web_config, :ADMIN_CERT_FINGERPRINTS),
    admin_https_port: Keyword.get(https_config, :port),
    cacertfile: Keyword.get(transport_options, :cacertfile),
    certfile: Keyword.get(https_config, :certfile),
    fail_if_no_peer_cert: Keyword.get(transport_options, :fail_if_no_peer_cert),
    keyfile: Keyword.get(https_config, :keyfile),
    server: Keyword.get(endpoint_config, :server),
    verify: Keyword.get(transport_options, :verify),
    versions: Keyword.get(transport_options, :versions)
  }

  IO.puts(#{inspect(@result_prefix)} <> Base.encode64(:erlang.term_to_binary(payload)))
  """

  test "admin mTLS listener is disabled by default" do
    assert %{
             admin_cert_fingerprints: nil,
             admin_https_port: nil,
             server: nil
           } = read_runtime_config()
  end

  test "production admin sessions use secure cookies" do
    config = Config.Reader.read!(@compile_config, env: :prod)

    assert config
           |> Keyword.fetch!(:secrethub_web)
           |> Keyword.fetch!(SecretHub.Web.Endpoint)
           |> Keyword.fetch!(:session_options)
           |> Keyword.fetch!(:secure)
  end

  test "admin mTLS listener requires peer certificates and loads its allowlist" do
    assert %{
             admin_cert_fingerprints: [
               "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
               "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
             ],
             admin_https_port: 4667,
             cacertfile: ~c"/run/secrethub/admin/ca.pem",
             certfile: "/run/secrethub/admin/server.pem",
             fail_if_no_peer_cert: true,
             keyfile: "/run/secrethub/admin/server-key.pem",
             server: true,
             verify: :verify_peer,
             versions: [:"tlsv1.2", :"tlsv1.3"]
           } =
             read_runtime_config([
               {"SECRET_HUB_ADMIN_CERT_FINGERPRINTS",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,\n" <>
                  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
               {"SECRET_HUB_ADMIN_ENDPOINT_CA_CERT_PATH", "/run/secrethub/admin/ca.pem"},
               {"SECRET_HUB_ADMIN_ENDPOINT_CERT_PATH", "/run/secrethub/admin/server.pem"},
               {"SECRET_HUB_ADMIN_ENDPOINT_KEY_PATH", "/run/secrethub/admin/server-key.pem"},
               {"SECRET_HUB_ADMIN_ENDPOINT_SERVER", "true"}
             ])
  end

  test "admin mTLS listener rejects a missing or invalid fingerprint allowlist" do
    base = admin_endpoint_env()

    for fingerprints <- [nil, "", "not-a-sha256-fingerprint"] do
      overrides =
        [{"SECRET_HUB_ADMIN_CERT_FINGERPRINTS", fingerprints} | base]

      {output, status} = run_runtime_config(overrides)

      assert status != 0
      assert output =~ "SECRET_HUB_ADMIN_CERT_FINGERPRINTS"
    end
  end

  test "admin mTLS listener requires every TLS file path" do
    for key <- [
          "SECRET_HUB_ADMIN_ENDPOINT_CA_CERT_PATH",
          "SECRET_HUB_ADMIN_ENDPOINT_CERT_PATH",
          "SECRET_HUB_ADMIN_ENDPOINT_KEY_PATH"
        ] do
      overrides = List.keydelete(valid_admin_endpoint_env(), key, 0)
      {output, status} = run_runtime_config(overrides)

      assert status != 0
      assert output =~ key
    end
  end

  test "admin mTLS listener cannot reuse the public HTTP port" do
    {output, status} =
      run_runtime_config([{"PORT", "4667"} | valid_admin_endpoint_env()])

    assert status != 0
    assert output =~ "SECRET_HUB_ADMIN_ENDPOINT_PORT must differ from PORT"
  end

  defp admin_endpoint_env do
    [
      {"SECRET_HUB_ADMIN_ENDPOINT_CA_CERT_PATH", "/run/secrethub/admin/ca.pem"},
      {"SECRET_HUB_ADMIN_ENDPOINT_CERT_PATH", "/run/secrethub/admin/server.pem"},
      {"SECRET_HUB_ADMIN_ENDPOINT_KEY_PATH", "/run/secrethub/admin/server-key.pem"},
      {"SECRET_HUB_ADMIN_ENDPOINT_SERVER", "true"}
    ]
  end

  defp valid_admin_endpoint_env do
    [
      {"SECRET_HUB_ADMIN_CERT_FINGERPRINTS", String.duplicate("a", 64)}
      | admin_endpoint_env()
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
    Code.ensure_loaded!(RuntimeRole)
    runtime_role_ebin = RuntimeRole |> :code.which() |> List.to_string() |> Path.dirname()
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
      ["-i" | runtime_env] ++ [elixir, "--erl", "+S 2:2", "-pa", runtime_role_ebin, "-e", @probe],
      cd: @project_root,
      stderr_to_stdout: true
    )
  end
end
