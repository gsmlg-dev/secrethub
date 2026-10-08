defmodule SecretHub.Core.PrelaunchRuntimeConfigTest do
  use ExUnit.Case, async: false

  @root Path.expand("../../../..", __DIR__)
  @keys ~w(RELEASE_DISTRIBUTION SECRETHUB_ROLE PHX_SERVER SECRET_HUB_CLUSTER_NODE_ID DATABASE_URL DATABASE_URL_FILE SECRET_KEY_BASE SECRET_KEY_BASE_FILE AUDIT_HMAC_KEY AUDIT_HMAC_KEY_FILE AUDIT_HMAC_KEY_ID AUDIT_HMAC_VERIFICATION_KEYS AUDIT_HMAC_VERIFICATION_KEYS_FILE SECRET_HUB_MANAGEMENT_ORIGIN SECRET_HUB_MANAGEMENT_BIND_IP SECRET_HUB_TRUSTED_PROXY_IP SECRET_HUB_MACHINE_ENDPOINT_SERVER SECRET_HUB_MACHINE_BIND_IP SECRET_HUB_MACHINE_PORT SECRET_HUB_ADMIN_ENDPOINT_SERVER SECRET_HUB_AGENT_ENDPOINT_SERVER SECRET_HUB_AGENT_ENDPOINT_PORT SECRET_HUB_AGENT_CORE_URL SECRET_HUB_AGENT_HOST_KEY_PATH SECRET_HUB_AGENT_ENROLLMENT_CA_PATH SECRET_HUB_AGENT_STATE_DIR SECRET_HUB_AGENT_SOCKET_PATH SECRET_HUB_CLIENT_AUTH_BUNDLE_DIR PORT)

  setup do
    keys =
      @keys ++
        ~w(SECRET_HUB_MANAGEMENT_ALLOWED_ORIGINS SECRET_HUB_MANAGEMENT_ALLOWED_ORIGINS_FILE)

    saved = Map.new(keys, &{&1, System.get_env(&1)})
    for key <- keys, do: System.delete_env(key)

    on_exit(fn ->
      for {key, value} <- saved do
        if value, do: System.put_env(key, value), else: System.delete_env(key)
      end
    end)

    System.put_env(%{
      "RELEASE_DISTRIBUTION" => "none",
      "SECRETHUB_ROLE" => "core",
      "SECRET_HUB_CLUSTER_NODE_ID" => "fixture-core",
      "DATABASE_URL" => "postgresql://fixture:private@db/fixture",
      "SECRET_KEY_BASE" => Base.encode64(:crypto.strong_rand_bytes(48)),
      "AUDIT_HMAC_KEY" => Base.encode64(:crypto.strong_rand_bytes(32)),
      "AUDIT_HMAC_KEY_ID" => "fixture-audit",
      "SECRET_HUB_MANAGEMENT_ORIGIN" => "https://admin.example.test",
      "SECRET_HUB_MACHINE_ENDPOINT_SERVER" => "true"
    })

    :ok
  end

  defp read(role),
    do:
      Config.Reader.read!(Path.join(@root, "config/#{role}_runtime.exs"),
        env: :prod,
        target: :host
      )

  test "management uses a private transport and independent canonical public origin" do
    config = read("core")
    endpoint = config[:secrethub_web][SecretHub.Web.Endpoint]
    assert endpoint[:http][:ip] == {127, 0, 0, 1}
    assert endpoint[:trusted_proxy_ips] == [{127, 0, 0, 1}]
    assert endpoint[:url][:scheme] == "https"
    assert endpoint[:url][:port] == 443
    assert endpoint[:check_origin] == ["https://admin.example.test"]
    assert endpoint[:https] == nil
    assert config[:secrethub_human][:enabled] == false
    assert config[:secrethub_web][SecretHub.Web.MachineEndpoint][:server]
  end

  test "additional public origins are explicit, normalized and deduplicated" do
    System.put_env(
      "SECRET_HUB_MANAGEMENT_ALLOWED_ORIGINS",
      "https://core.example.test, https://admin.example.test/, https://core.example.test"
    )

    endpoint = read("core")[:secrethub_web][SecretHub.Web.Endpoint]
    assert endpoint[:url][:host] == "admin.example.test"
    assert endpoint[:check_origin] == ["https://admin.example.test", "https://core.example.test"]
  end

  test "unsafe additional public origins fail closed without echoing input" do
    for origin <- [
          "*",
          "https://*.example.test",
          "http://core.example.test",
          "https://core.example.test/path",
          "https://user:private@core.example.test",
          "https://core.example.test,"
        ] do
      System.put_env("SECRET_HUB_MANAGEMENT_ALLOWED_ORIGINS", origin)

      assert_raise ArgumentError, "SECRET_HUB_MANAGEMENT_ALLOWED_ORIGINS: invalid_origin", fn ->
        read("core")
      end
    end
  end

  @tag :tmp_dir
  test "runtime key changes and file-backed values are evaluated on each boot", %{tmp_dir: dir} do
    old_key = read("core")[:secrethub_core][:audit_hmac_secret]
    new_key = :crypto.strong_rand_bytes(32)
    path = Path.join(dir, "audit-key")
    File.write!(path, Base.encode64(new_key) <> "\n")
    System.delete_env("AUDIT_HMAC_KEY")
    System.put_env("AUDIT_HMAC_KEY_FILE", path)
    assert read("core")[:secrethub_core][:audit_hmac_secret] == new_key
    assert old_key != new_key
  end

  @tag :tmp_dir
  test "blocking errors do not print secret input or credential-bearing URL" do
    System.delete_env("AUDIT_HMAC_KEY")
    assert_raise ArgumentError, "AUDIT_HMAC_KEY: missing", fn -> read("core") end
    System.put_env("AUDIT_HMAC_KEY", "private-marker")
    assert_raise ArgumentError, "AUDIT_HMAC_KEY: invalid_base64_key", fn -> read("core") end
  end

  test "duplicate admin TLS, wildcard backend and conflicting listeners are rejected" do
    System.put_env("SECRET_HUB_ADMIN_ENDPOINT_SERVER", "true")

    assert_raise ArgumentError,
                 "SECRET_HUB_ADMIN_ENDPOINT_SERVER: unsupported_duplicate_authentication",
                 fn -> read("core") end

    System.delete_env("SECRET_HUB_ADMIN_ENDPOINT_SERVER")
    System.put_env("SECRET_HUB_MANAGEMENT_BIND_IP", "0.0.0.0")

    assert_raise ArgumentError, "SECRET_HUB_MANAGEMENT_BIND_IP: private_address_required", fn ->
      read("core")
    end

    System.delete_env("SECRET_HUB_MANAGEMENT_BIND_IP")
    System.put_env("SECRET_HUB_MACHINE_PORT", "4664")
    assert_raise ArgumentError, "listeners: conflicting_ports", fn -> read("core") end
  end

  test "Agent configuration needs no Core DB or Human secrets" do
    for key <- ~w(DATABASE_URL SECRET_KEY_BASE AUDIT_HMAC_KEY SECRET_HUB_CLUSTER_NODE_ID),
        do: System.delete_env(key)

    System.put_env(%{
      "SECRET_HUB_AGENT_CORE_URL" => "https://machine.example.test",
      "SECRET_HUB_AGENT_HOST_KEY_PATH" => "/fixture/host-key",
      "SECRET_HUB_AGENT_STATE_DIR" => "/fixture/state",
      "SECRET_HUB_AGENT_SOCKET_PATH" => "/fixture/run/agent.sock",
      "SECRET_HUB_CLIENT_AUTH_BUNDLE_DIR" => "/fixture/bundle"
    })

    config = read("agent")
    assert config[:secrethub_core] == nil
    assert config[:secrethub_human] == nil
    assert config[:secrethub_agent][:launch_profile] == :single_operator
    assert config[:secrethub_agent][:enrollment_opts][:paths][:rsa] == "/fixture/host-key"
    assert config[:secrethub_agent][:enrollment_req_options] == []

    System.put_env("SECRET_HUB_AGENT_ENROLLMENT_CA_PATH", "/fixture/enrollment-ca.pem")
    config = read("agent")

    transport =
      config[:secrethub_agent][:enrollment_req_options][:connect_options][:transport_opts]

    assert transport[:cacertfile] == "/fixture/enrollment-ca.pem"
    assert transport[:verify] == :verify_peer
  end
end
