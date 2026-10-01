defmodule SecretHub.Core.AuditRuntimeKeysTest do
  use SecretHub.Core.DataCase, async: false

  alias SecretHub.Core.{Audit, Repo}
  alias SecretHub.Shared.Schemas.AuditLog

  setup do
    names = [:audit_hmac_secret, :audit_hmac_key_id, :audit_hmac_verification_keys]
    original = Map.new(names, &{&1, Application.fetch_env(:secrethub_core, &1)})

    on_exit(fn ->
      for {name, value} <- original do
        case value do
          {:ok, saved} -> Application.put_env(:secrethub_core, name, saved)
          :error -> Application.delete_env(:secrethub_core, name)
        end
      end
    end)

    Repo.delete_all(AuditLog)
    :ok
  end

  test "the same loaded artifact signs with runtime keys and verifies historical IDs" do
    event = %{event_type: "secret.accessed", actor_type: "system", actor_id: "runtime-test"}
    first_key = <<11::256>>
    second_key = <<12::256>>
    Application.put_env(:secrethub_core, :audit_hmac_secret, first_key)
    Application.put_env(:secrethub_core, :audit_hmac_key_id, "first")
    assert {:ok, first} = Audit.log_event(event)
    assert Map.get(first, :signing_key_id) == "first"
    assert Map.get(first, :signature_version) == 2

    Application.put_env(:secrethub_core, :audit_hmac_secret, second_key)
    Application.put_env(:secrethub_core, :audit_hmac_key_id, "second")
    Application.put_env(:secrethub_core, :audit_hmac_verification_keys, %{"first" => first_key})
    assert {:ok, second} = Audit.log_event(event)
    assert Map.get(second, :signing_key_id) == "second"
    assert {:ok, :valid} = Audit.verify_chain()

    Application.put_env(:secrethub_core, :audit_hmac_verification_keys, %{})
    assert {:error, reason} = Audit.verify_chain()
    assert reason =~ "Invalid signature"
  end

  test "changing a signature key ID invalidates the signature even when keys match" do
    key = <<13::256>>
    Application.put_env(:secrethub_core, :audit_hmac_secret, key)
    Application.put_env(:secrethub_core, :audit_hmac_key_id, "first")
    Application.put_env(:secrethub_core, :audit_hmac_verification_keys, %{"other" => key})
    assert {:ok, log} = Audit.log_event(%{event_type: "secret.accessed"})
    Repo.query!("UPDATE audit_logs SET signing_key_id = 'other' WHERE id = $1", [log.id])
    assert {:error, reason} = Audit.verify_chain()
    assert reason =~ "Invalid signature"
  end
end
