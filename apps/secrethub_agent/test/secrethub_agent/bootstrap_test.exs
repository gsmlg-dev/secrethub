defmodule SecretHub.Agent.BootstrapTest do
  use ExUnit.Case, async: true

  alias SecretHub.Agent.Bootstrap

  test "legacy AppRole bootstrap is hard-disabled for agents" do
    assert Bootstrap.needs_bootstrap?()

    assert {:error, :legacy_approle_bootstrap_disabled} =
             Bootstrap.bootstrap_with_approle(role_id: "role", secret_id: "secret")
  end

  test "certificate renewal requires a trusted identity" do
    assert {:error, :renewal_requires_trusted_identity} =
             Bootstrap.renew_certificate("test-agent", "wss://localhost:4001")
  end

  describe "get_certificate_info/0" do
    test "legacy certificate path lookup is disabled" do
      assert {:error, :legacy_certificate_info_disabled} = Bootstrap.get_certificate_info()
    end
  end
end
