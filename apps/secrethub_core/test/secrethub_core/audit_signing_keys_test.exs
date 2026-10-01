defmodule SecretHub.Core.AuditSigningKeysTest do
  use ExUnit.Case, async: true

  alias SecretHub.Core.Audit.SigningKeys

  test "production rejects missing, empty, development and malformed signing material" do
    for secret <- [nil, "", "dev-audit-secret", "change-me-in-production", <<1>>, :invalid] do
      config = [env: :prod, audit_hmac_key_id: "current", audit_hmac_secret: secret]
      assert {:error, _} = SigningKeys.active(config)
    end

    for id <- [nil, "", "a|b", String.duplicate("a", 65), :invalid] do
      config = [env: :prod, audit_hmac_key_id: id, audit_hmac_secret: <<42::256>>]
      assert {:error, _} = SigningKeys.active(config)
    end
  end

  test "runtime active keys and historical keys are independent of hash versions" do
    first = <<1::256>>
    second = <<2::256>>

    config = [
      env: :prod,
      audit_hmac_key_id: "second",
      audit_hmac_secret: second,
      audit_hmac_verification_keys: %{"first" => first, "legacy" => "old-key"}
    ]

    assert {:ok, %{id: "second", secret: ^second, version: 2}} = SigningKeys.active(config)
    assert {:ok, ^first} = SigningKeys.verification_key(config, "first", 2)
    assert {:ok, ^second} = SigningKeys.verification_key(config, "second", 2)
    assert {:ok, "old-key"} = SigningKeys.verification_key(config, nil, 1)
    assert {:error, :unknown_audit_key} = SigningKeys.verification_key(config, "lost", 2)
    assert {:error, _} = SigningKeys.verification_key(config, "second", 99)
  end

  test "production never substitutes the current key for missing legacy recovery material" do
    config = [env: :prod, audit_hmac_key_id: "current", audit_hmac_secret: <<1::256>>]
    assert {:error, :unknown_audit_key} = SigningKeys.verification_key(config, nil, 1)
  end

  test "development preserves the existing legacy signing contract" do
    assert {:ok, %{id: nil, secret: "dev-audit-secret", version: 1}} =
             SigningKeys.active(env: :test)

    assert {:ok, "dev-audit-secret"} = SigningKeys.verification_key([env: :test], nil, 1)
  end
end
