defmodule SecretHub.Shared.HostCredentialsTest do
  use ExUnit.Case, async: true

  alias SecretHub.Shared.AccessAudit.Event
  alias SecretHub.Shared.HostCredentials

  @entry "11111111-2222-4333-8444-555555555555"

  describe "request contract" do
    test "Git lookups may omit the account; stores must name it" do
      lookup = %{"namespace" => "git", "service" => "https", "authority" => "h:8443"}

      assert {:ok, %{"account" => nil, "context" => ""}} =
               HostCredentials.validate("credential_get", lookup)

      assert {:error, :invalid_request} =
               HostCredentials.validate("credential_put", Map.put(lookup, "value", "v"))

      assert {:ok, %{"username" => "u", "value" => ""}} =
               HostCredentials.validate(
                 "credential_put",
                 Map.merge(lookup, %{"account" => "u", "value" => ""})
               )
    end

    test "Docker identity is the registry alone and requires a username to store" do
      registry = %{"namespace" => "docker", "service" => "localhost:5000"}
      assert {:ok, _} = HostCredentials.validate("credential_get", registry)

      assert {:error, :invalid_request} =
               HostCredentials.validate("credential_get", Map.put(registry, "authority", "x"))

      assert {:error, :invalid_request} =
               HostCredentials.validate("credential_put", Map.put(registry, "value", "s"))

      assert {:ok, %{"username" => "<token>"}} =
               HostCredentials.validate(
                 "credential_put",
                 Map.merge(registry, %{"username" => "<token>", "value" => "s"})
               )
    end

    test "unknown keys, identity claims, control characters and oversize values are rejected" do
      base = %{"namespace" => "generic", "service" => "svc", "account" => "u"}

      for params <- [
            Map.put(base, "agent_id", "x"),
            Map.put(base, "service", "a\nb"),
            Map.put(base, "account", String.duplicate("a", 513)),
            Map.put(base, "namespace", "ssh")
          ] do
        assert {:error, :invalid_request} = HostCredentials.validate("credential_get", params)
      end

      too_large =
        Map.put(base, "value", String.duplicate("v", HostCredentials.max_value_bytes() + 1))

      assert {:error, :invalid_request} = HostCredentials.validate("credential_put", too_large)

      assert {:error, :invalid_request} =
               HostCredentials.validate("credential_put", Map.put(base, "value", <<255>>))
    end

    test "entry lookups and known revisions are exact" do
      assert {:ok, %{"entry_id" => @entry}} =
               HostCredentials.validate("credential_get", %{"entry_id" => @entry})

      assert {:error, :invalid_request} =
               HostCredentials.validate("credential_get", %{
                 "entry_id" => @entry,
                 "service" => "x"
               })

      known = %{"entry_id" => @entry, "binding_revision" => 1, "source_revision" => 2}

      assert {:ok, %{"known" => ^known}} =
               HostCredentials.validate("credential_get", %{
                 "entry_id" => @entry,
                 "known" => known
               })

      assert {:error, :invalid_request} =
               HostCredentials.validate("credential_get", %{
                 "entry_id" => @entry,
                 "known" => %{known | "binding_revision" => 0}
               })
    end

    test "resources are opaque and the reserved prefix is recognized" do
      assert HostCredentials.entry_resource("agent", "git", @entry) ==
               "host-credentials.agent.git." <> @entry

      assert HostCredentials.reserved_path?("host-credentials.a.git")
      refute HostCredentials.reserved_path?("host-credentials-other.a")
    end
  end

  describe "access audit schema v2" do
    defp event(version, operation, reason \\ "allowed") do
      %{
        "schema_version" => version,
        "event_id" => Ecto.UUID.generate(),
        "producer_id" => Ecto.UUID.generate(),
        "producer_sequence" => 1,
        "request_id" => Ecto.UUID.generate(),
        "attempt_id" => Ecto.UUID.generate(),
        "source" => "agent",
        "phase" => "response_sent",
        "observed_at" => DateTime.to_iso8601(DateTime.utc_now()),
        "identity_status" => "unverified",
        "attribution" => "none",
        "operation" => operation,
        "outcome" => "success",
        "reason_code" => reason,
        "cache_status" => "none",
        "secret_path" => "host-credentials.agent.git." <> @entry
      }
    end

    test "credential operations require version 2 and version 1 is unchanged" do
      assert {:ok, _} = Event.validate(event(2, "credential_write"))
      assert {:error, :invalid_event} = Event.validate(event(1, "credential_write"))
      assert {:ok, _} = Event.validate(event(1, "read"))
      assert {:error, :invalid_event} = Event.validate(event(2, "read"))
      assert {:error, :invalid_event} = Event.validate(event(3, "credential_read"))
    end

    test "version 2 reasons do not leak into version 1" do
      assert {:ok, _} = Event.validate(event(2, "credential_read", "ambiguous"))
      assert {:error, :invalid_event} = Event.validate(event(1, "read", "ambiguous"))
      assert Event.reason(:ambiguous, 2) == "ambiguous"
      assert Event.reason(:ambiguous) == "internal_error"
      assert Event.schema_version_for("credential_list") == 2
      assert Event.schema_version_for("read") == 1
    end
  end
end
