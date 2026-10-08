defmodule SecretHub.Shared.RuntimeConfigTest do
  use ExUnit.Case, async: true
  alias SecretHub.Shared.RuntimeConfig

  test "database URL validation never exposes credential-bearing input in errors" do
    valid = "postgresql://user:private-marker@localhost/database?socket_dir=/socket"
    assert RuntimeConfig.database_url!(valid) == valid

    for invalid <- [
          "postgresql://user:private-marker@localhost",
          "not-a-url-private-marker",
          "https://user:private-marker@localhost/database"
        ] do
      assert_raise ArgumentError, "DATABASE_URL: invalid_database_url", fn ->
        RuntimeConfig.database_url!(invalid)
      end
    end
  end

  test "machine endpoints require HTTPS without embedded credentials" do
    assert %{host: "core.example"} = RuntimeConfig.https_url!("CORE", "https://core.example:4668")

    for value <- [
          "http://core.example",
          "https://user:private@core.example",
          "invalid",
          "https://core.example?token=private"
        ] do
      assert_raise ArgumentError, "CORE: invalid_https_url", fn ->
        RuntimeConfig.https_url!("CORE", value)
      end
    end
  end

  test "key parsing and historical keyring errors never echo material" do
    key = :crypto.strong_rand_bytes(32)
    assert key == RuntimeConfig.decode_key!("KEY", Base.encode64(key))

    assert %{"old" => key} ==
             RuntimeConfig.verification_keys!(Jason.encode!(%{"old" => Base.encode64(key)}))

    assert %{} == RuntimeConfig.verification_keys!(nil)

    assert_raise ArgumentError, "KEY: invalid_base64_key", fn ->
      RuntimeConfig.decode_key!("KEY", "private")
    end

    assert_raise ArgumentError, "AUDIT_HMAC_VERIFICATION_KEYS: invalid_keyring", fn ->
      RuntimeConfig.verification_keys!("private")
    end

    assert_raise ArgumentError, "AUDIT_HMAC_VERIFICATION_KEYS: invalid_key", fn ->
      RuntimeConfig.verification_keys!(~s({"old":"private"}))
    end
  end

  test "management origins require exact HTTPS origins without wildcard hosts or URL extras" do
    assert URI.to_string(RuntimeConfig.https_origin!("ORIGIN", "https://admin.example:8443/")) ==
             "https://admin.example:8443"

    for value <- [
          "http://admin.example",
          "//admin.example",
          "https://*.example",
          "https://admin.example/path",
          "https://user:private@admin.example",
          "https://admin.example?token=private",
          "https://admin.example#private",
          "https://admin.example:0",
          "https://admin.example:65536",
          "",
          "*"
        ] do
      assert_raise ArgumentError, "ORIGIN: invalid_origin", fn ->
        RuntimeConfig.https_origin!("ORIGIN", value)
      end
    end
  end
end
