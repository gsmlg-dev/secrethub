defmodule SecretHub.Shared.AccessAudit.EventTest do
  use ExUnit.Case, async: true
  alias SecretHub.Shared.AccessAudit.Event

  defp event(attrs \\ %{}) do
    Map.merge(
      %{
        "schema_version" => 1,
        "event_id" => Ecto.UUID.generate(),
        "producer_id" => Ecto.UUID.generate(),
        "producer_sequence" => 1,
        "request_id" => Ecto.UUID.generate(),
        "attempt_id" => Ecto.UUID.generate(),
        "source" => "agent",
        "phase" => "admitted",
        "observed_at" => "2026-10-20T00:00:00Z",
        "identity_status" => "unverified",
        "attribution" => "none",
        "operation" => "read",
        "outcome" => "unknown",
        "reason_code" => "none",
        "cache_status" => "none"
      },
      attrs
    )
  end

  test "normalizes the allowlisted contract and nullable unknown identities" do
    input = event()
    assert {:ok, result} = Event.validate(input, source: "agent")
    assert result["application_id"] == nil
    assert result["secret_id"] == nil
    assert result["received_at"] == nil
    assert result["schema_version"] == 1
    assert Event.canonical(result) == Event.canonical(Map.new(Enum.reverse(Map.to_list(result))))
  end

  test "accepts independently Core-verified identity only from Core" do
    input =
      event(%{
        "phase" => "core_decision",
        "source" => "core",
        "outcome" => "success",
        "reason_code" => "allowed",
        "identity_status" => "verified",
        "attribution" => "core_certificate",
        "application_id" => Ecto.UUID.generate()
      })

    assert {:ok, _} = Event.validate(input, source: "core")
    assert {:error, _} = Event.validate(input, source: "agent")
    assert {:error, _} = Event.validate(Map.put(input, "source", "agent"))
  end

  test "Agent observations cannot assign identity from unverified claims or tokens" do
    app = Ecto.UUID.generate()
    assert {:error, _} = Event.validate(event(%{"application_id" => app}))

    assert {:ok, %{"attribution" => "agent_certificate"}} =
             Event.validate(
               event(%{
                 "application_id" => app,
                 "identity_status" => "verified",
                 "attribution" => "agent_certificate"
               })
             )

    assert {:error, _} = Event.validate(event(%{"attribution" => "token"}))
  end

  test "rejects arbitrary payloads, duplicate normalized keys and secret canaries" do
    canary = "DO-NOT-RECORD-SECRET-OR-TOKEN"

    for key <- ["metadata", "exception", "body", "value", "token", "received_at"] do
      assert {:error, _} = Event.validate(Map.put(event(), key, canary))
    end

    assert {:error, _} = Event.validate(Map.put(event(), :source, "agent"))
    assert {:error, _} = Event.validate(event(%{"client_correlation_id" => canary}))
    assert {:error, _} = Event.validate(event(%{"secret_path" => "bad\n" <> canary}))
    assert {:error, _} = Event.validate(event(%{"agent_id" => String.duplicate("a", 1024)}))
  end

  test "bounds phase semantics, duration, sequences, timestamps and encoded size" do
    for {key, value} <- [
          {"schema_version", 2},
          {"producer_sequence", 0},
          {"producer_sequence", 1.5},
          {"event_id", "caller-input"},
          {"duration_us", -1},
          {"observed_at", "not-a-time"},
          {"outcome", "secret_consumed"},
          {"cache_status", "offline"},
          {"reason_code", "raw exception"},
          {"phase", "core_access"},
          {"secret_path", String.duplicate("a", 513)}
        ] do
      assert {:error, _} = Event.validate(event(%{key => value}))
    end

    assert {:error, _} = Event.validate(event(%{"phase" => "response_sent", "attempt_id" => nil}))
    assert {:error, _} = Event.validate(event(%{"phase" => "admitted", "outcome" => "success"}))
    assert {:error, _} = Event.validate(String.duplicate("a", 8192))
  end

  test "safe path and reason normalization never serializes invalid input" do
    assert Event.safe_path("prod.db.password") == "prod.db.password"
    assert Event.safe_path("prod/db/password") == "prod/db/password"
    assert Event.safe_path(%{"value" => "canary"}) == nil
    assert Event.safe_path("../bad?token=canary") == nil
    assert Event.reason(:permission_denied) == "permission_denied"
    assert Event.reason({:error, "private-value"}) == "internal_error"
  end
end
