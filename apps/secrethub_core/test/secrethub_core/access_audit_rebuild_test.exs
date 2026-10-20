defmodule SecretHub.Core.AccessAuditRebuildTest do
  use ExUnit.Case, async: false
  alias SecretHub.Core.{AccessAudit, Audit, Repo, RuntimeDatabaseFixture}
  alias SecretHub.Core.AccessAudit.{Observation, Request}

  setup_all do
    RuntimeDatabaseFixture.prepare_template()
  end

  setup tags do
    RuntimeDatabaseFixture.setup(tags)
    request_id = Ecto.UUID.generate()
    attempt_id = Ecto.UUID.generate()

    attrs = %{
      request_id: request_id,
      attempt_id: attempt_id,
      secret_path: "rebuild.fixture.secret"
    }

    assert {:ok, _} =
             AccessAudit.record_core(
               Map.merge(attrs, %{phase: "admitted", outcome: "unknown", reason_code: "none"})
             )

    assert {:ok, _} =
             AccessAudit.record_core(
               Map.merge(attrs, %{
                 phase: "core_decision",
                 outcome: "denied",
                 reason_code: "permission_denied"
               })
             )

    assert {:ok, _} =
             AccessAudit.record_core(
               Map.merge(attrs, %{
                 phase: "response_sent",
                 outcome: "denied",
                 reason_code: "permission_denied"
               })
             )

    %{request_id: request_id}
  end

  test "bounded rebuild restores one retained projection without replaying audit events", ctx do
    original = Repo.get_by!(Request, namespace: "core", request_id: ctx.request_id)
    assert {1, _} = Repo.delete_all(Request)
    assert {:ok, rebuilt} = AccessAudit.rebuild_request("core", ctx.request_id)
    assert projection_fields(rebuilt) == projection_fields(original)
    assert {:ok, repeated} = AccessAudit.rebuild_request("core", ctx.request_id)
    assert repeated.id == rebuilt.id
    assert Repo.aggregate(Request, :count) == 1
    assert Repo.aggregate(Observation, :count) == 3
    assert {:ok, :valid} = Audit.verify_chain()
  end

  test "expired raw evidence cannot be used to reconstruct a partial request", ctx do
    Repo.update_all(Request,
      set: [last_received_at: DateTime.add(DateTime.utc_now(), -40 * 86_400)]
    )

    assert {:ok, %{observations: 3, requests: 0}} = AccessAudit.prune(enabled: true)
    assert {:error, :raw_expired} = AccessAudit.rebuild_request("core", ctx.request_id)
    assert Repo.aggregate(Request, :count) == 1
    assert Repo.aggregate(Observation, :count) == 0
  end

  test "missing and malformed identities return bounded errors without creating requests" do
    assert {:error, :not_found} = AccessAudit.rebuild_request("core", Ecto.UUID.generate())

    assert {:error, :invalid_filter} =
             AccessAudit.rebuild_request(String.duplicate("x", 301), Ecto.UUID.generate())

    assert {:error, :invalid_filter} = AccessAudit.rebuild_request("core", "invalid")
    assert Repo.aggregate(Request, :count) == 1
  end

  test "unavailable raw storage cannot replace the existing projection", ctx do
    original = Repo.get_by!(Request, namespace: "core", request_id: ctx.request_id)
    Repo.query!("ALTER TABLE access_audit_events RENAME TO access_audit_events_unavailable")
    assert {:error, :storage_unavailable} = AccessAudit.rebuild_request("core", ctx.request_id)
    assert Repo.get!(Request, original.id) == original
  end

  test "rebuild rejects raw observations that disagree with their signed audit source", ctx do
    original = Repo.get_by!(Request, namespace: "core", request_id: ctx.request_id)
    observation = Repo.all(Observation) |> List.last()
    tampered = Map.put(observation.envelope, "reason_code", "not_found")
    observation |> Ecto.Changeset.change(envelope: tampered) |> Repo.update!()
    assert {:error, :invalid_source} = AccessAudit.rebuild_request("core", ctx.request_id)
    assert Repo.get!(Request, original.id) == original
  end

  @tag :integrity_source_regression
  test "missing terminal raw evidence cannot overwrite a complete signed request summary", ctx do
    original = Repo.get_by!(Request, namespace: "core", request_id: ctx.request_id)
    terminal = Enum.find(Repo.all(Observation), &(&1.envelope["phase"] == "response_sent"))
    Repo.delete!(terminal)
    assert {:error, :invalid_source} = AccessAudit.rebuild_request("core", ctx.request_id)
    assert Repo.get!(Request, original.id) == original
    assert Repo.aggregate(Observation, :count) == 2
    assert {:ok, :valid} = Audit.verify_chain()
  end

  @tag :integrity_source_regression
  test "missing all raw rows remains invalid source when the signed request still exists", ctx do
    original = Repo.get_by!(Request, namespace: "core", request_id: ctx.request_id)
    Repo.delete_all(Observation)
    assert {:error, :invalid_source} = AccessAudit.rebuild_request("core", ctx.request_id)
    assert Repo.get!(Request, original.id) == original
    assert {:ok, :valid} = Audit.verify_chain()
  end

  defp projection_fields(request), do: request |> Map.from_struct() |> Map.drop([:id, :__meta__])
end
