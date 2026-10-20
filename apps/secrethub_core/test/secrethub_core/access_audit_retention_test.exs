defmodule SecretHub.Core.AccessAuditRetentionTest do
  use ExUnit.Case, async: false
  import Ecto.Query
  alias SecretHub.Core.{AccessAudit, Audit, Repo, RuntimeDatabaseFixture}
  alias SecretHub.Core.AccessAudit.{Observation, Request}
  alias SecretHub.Shared.AccessAudit.Event
  alias SecretHub.Shared.Schemas.{Agent, Certificate}

  setup_all do
    RuntimeDatabaseFixture.prepare_template()
  end

  setup tags do
    RuntimeDatabaseFixture.setup(tags)
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    agent = "retention-#{System.unique_integer([:positive])}"

    certificate =
      Repo.insert!(%Certificate{
        serial_number: Ecto.UUID.generate(),
        fingerprint: Ecto.UUID.generate(),
        certificate_pem: "fixture",
        subject: "fixture",
        issuer: "fixture",
        common_name: agent,
        cert_type: :agent_client,
        entity_id: agent,
        entity_type: "agent",
        valid_from: now,
        valid_until: DateTime.add(now, 86_400)
      })

    Repo.insert!(%Agent{
      agent_id: agent,
      name: "Retention fixture",
      status: :active,
      certificate_id: certificate.id
    })

    %{
      identity: %{agent_id: agent, certificate_id: certificate.id},
      producer: Ecto.UUID.generate()
    }
  end

  test "default is finite targets with deletion disabled; disabled prune cannot delete", ctx do
    event = event(ctx, 1)
    assert {:ok, _} = AccessAudit.ingest(ctx.identity, [event])
    age_requests(400)

    assert {:ok,
            %{
              enabled: false,
              raw_days: 30,
              aggregate_days: 365,
              automatic_deletion: false,
              manual_pruning: true
            }} = AccessAudit.retention_policy()

    assert {:ok, %{observations: 0, requests: 0}} = AccessAudit.prune()
    assert Repo.aggregate(Observation, :count) == 1
    assert Repo.aggregate(Request, :count) == 1
    assert {:error, :invalid_retention_policy} = AccessAudit.prune(enabled: true, raw_days: nil)

    assert {:error, :invalid_retention_policy} =
             AccessAudit.prune(enabled: true, raw_days: 30, aggregate_days: 1)
  end

  test "manual raw expiry preserves aggregate, signed chain and non-access audit records", ctx do
    event = event(ctx, 1)
    assert {:ok, _} = AccessAudit.ingest(ctx.identity, [event])

    assert {:ok, legacy} =
             Audit.log_event(%{
               event_type: "secret.accessed",
               actor_type: "agent",
               actor_id: ctx.identity.agent_id
             })

    age_requests(40)

    observation = Repo.one!(Observation)
    log = Repo.get!(SecretHub.Shared.Schemas.AuditLog, observation.audit_log_id)
    assert observation.audit_log_timestamp == log.timestamp
    assert observation.namespace == log.event_data["access_audit"]["namespace"]

    assert observation.canonical ==
             Event.canonical(log.event_data["access_audit"]["envelope"])

    assert Repo.aggregate(
             from(a in SecretHub.Shared.Schemas.AuditLog,
               join: o in Observation,
               on:
                 o.audit_log_id == a.id and
                   fragment("? AT TIME ZONE 'UTC'", o.audit_log_timestamp) == a.timestamp
             ),
             :count
           ) == 1

    assert {:ok, {:ok, %{observations: 1, requests: 0, checkpoints: 1}}} =
             Repo.transaction(fn ->
               Repo.query!("SET LOCAL TIME ZONE 'Asia/Shanghai'")
               AccessAudit.prune(enabled: true)
             end)

    assert Repo.aggregate(Observation, :count) == 0
    assert Repo.aggregate(Request, :count) == 1

    assert {:error, :raw_expired} =
             AccessAudit.timeline("agent:" <> ctx.identity.agent_id, event["request_id"])

    assert {:ok, ^legacy} = Audit.get_log(legacy.id)
    assert {:ok, :valid} = Audit.verify_chain()

    assert {:ok, _} =
             AccessAudit.record_core(%{
               phase: :core_decision,
               outcome: :denied,
               reason_code: :permission_denied
             })

    assert {:ok, :valid} = Audit.verify_chain()
    assert {:ok, %{observations: 0, requests: 0}} = AccessAudit.prune(enabled: true)
    path = Application.app_dir(:secrethub_core, "priv/repo/migrations")

    assert_raise Postgrex.Error, fn ->
      Ecto.Migrator.run(Repo, path, :down, step: 1, log: false)
    end

    assert {:ok, :valid} = Audit.verify_chain()
  end

  test "raw tombstones deduplicate exact replay, reject changed IDs and sequences, and reject late resurrection",
       ctx do
    event = event(ctx, 1)
    assert {:ok, _} = AccessAudit.ingest(ctx.identity, [event])
    age_requests(40)
    assert {:ok, _} = AccessAudit.prune(enabled: true)
    assert {:ok, %{accepted: [], duplicates: [id]}} = AccessAudit.ingest(ctx.identity, [event])
    assert id == event["event_id"]

    assert {:error, :event_conflict} =
             AccessAudit.ingest(ctx.identity, [Map.put(event, "reason_code", "internal_error")])

    assert {:error, :sequence_conflict} = AccessAudit.ingest(ctx.identity, [event(ctx, 1)])
    late = event(ctx, 2) |> Map.put("request_id", event["request_id"])
    assert {:error, :outside_retention} = AccessAudit.ingest(ctx.identity, [late])
    assert Repo.aggregate(Observation, :count) == 0
    assert Repo.aggregate(Request, :count) == 1
  end

  test "aggregate expiry is bounded and keeps permanent replay tombstones", ctx do
    events = for sequence <- 1..3, do: event(ctx, sequence)
    assert {:ok, _} = AccessAudit.ingest(ctx.identity, events)
    age_requests(400)
    assert {:ok, %{observations: 1, requests: 1}} = AccessAudit.prune(enabled: true, limit: 1)
    assert Repo.aggregate(Observation, :count) == 2
    assert Repo.aggregate(Request, :count) == 2
    assert {:ok, %{observations: 2, requests: 2}} = AccessAudit.prune(enabled: true)
    assert Repo.aggregate(Request, :count) == 0
    assert {:ok, %{accepted: [], duplicates: ids}} = AccessAudit.ingest(ctx.identity, events)
    assert length(ids) == 3
    assert Repo.aggregate(Request, :count) == 0
    assert {:ok, :valid} = Audit.verify_chain()
  end

  test "tampered checkpoint fails chain verification and prune rolls back if checked marker append fails",
       ctx do
    event = event(ctx, 1)
    assert {:ok, _} = AccessAudit.ingest(ctx.identity, [event])
    age_requests(40)

    Repo.query!(
      "CREATE FUNCTION fail_retention_marker() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event_type = 'access.retention_checkpoint' THEN RAISE EXCEPTION 'fixture marker failure'; END IF; RETURN NEW; END $$"
    )

    Repo.query!(
      "CREATE TRIGGER retention_marker_failure BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION fail_retention_marker()"
    )

    assert {:error, _} = AccessAudit.prune(enabled: true)
    assert Repo.aggregate(Observation, :count) == 1
    assert Repo.aggregate(Request, :count) == 1
    assert {:ok, :valid} = Audit.verify_chain()
    Repo.query!("DROP TRIGGER retention_marker_failure ON audit_logs")
    assert {:ok, _} = AccessAudit.prune(enabled: true)

    [[digest]] = Repo.query!("SELECT canonical_digest FROM access_audit_event_tombstones").rows

    Repo.query!("UPDATE access_audit_event_tombstones SET canonical_digest = $1", [
      String.duplicate("0", 64)
    ])

    assert {:error, _} = Audit.verify_chain()
    assert {:error, :audit_unavailable} = AccessAudit.ingest(ctx.identity, [event])
    Repo.query!("UPDATE access_audit_event_tombstones SET canonical_digest = $1", [digest])
    assert {:ok, :valid} = Audit.verify_chain()

    Repo.query!(
      "UPDATE access_audit_chain_checkpoints SET checkpoint = jsonb_set(checkpoint, '{previous_hash}', '\"0000000000000000000000000000000000000000000000000000000000000000\"')"
    )

    assert {:error, _} = Audit.verify_chain()
  end

  defp age_requests(days) do
    old = DateTime.add(DateTime.utc_now(), -days * 86_400)
    Repo.update_all(from(r in Request), set: [last_received_at: old])
  end

  @tag :integrity_source_regression
  test "pruning refuses altered row identities before signing checkpoints or deleting evidence",
       ctx do
    original_event = event(ctx, 1)
    assert {:ok, _} = AccessAudit.ingest(ctx.identity, [original_event])
    age_requests(40)
    observation = Repo.one!(Observation)
    original_request = Repo.one!(Request)
    original_ledger_count = Repo.aggregate(SecretHub.Shared.Schemas.AuditLog, :count)

    alterations = [
      {:producer_sequence, 2, :invalid_retention_source},
      {:producer_id, Ecto.UUID.generate(), :invalid_retention_source},
      {:event_id, Ecto.UUID.generate(), :invalid_retention_source},
      {:request_id, Ecto.UUID.generate(), :inconsistent_retention_source},
      {:namespace, "core", :inconsistent_retention_source},
      {:observed_at, DateTime.add(observation.observed_at, 1), :invalid_retention_source},
      {:received_at, DateTime.add(observation.received_at, 1), :invalid_retention_source},
      {:audit_log_id, observation.audit_log_id + 1, :inconsistent_retention_source},
      {:audit_log_timestamp, DateTime.add(observation.audit_log_timestamp, 1),
       :inconsistent_retention_source},
      {:canonical, observation.canonical <> " ", :invalid_retention_source},
      {:envelope, Map.put(observation.envelope, "reason_code", "invalid_request"),
       :invalid_retention_source}
    ]

    for {field, value, reason} <- alterations do
      tampered = observation |> Ecto.Changeset.change([{field, value}]) |> Repo.update!()
      assert {:error, ^reason} = AccessAudit.prune(enabled: true)
      assert Repo.one!(Observation) == tampered
      assert Repo.one!(Request) == original_request
      assert Repo.aggregate(SecretHub.Shared.Schemas.AuditLog, :count) == original_ledger_count
      assert Repo.query!("SELECT count(*) FROM access_audit_chain_checkpoints").rows == [[0]]
      assert Repo.query!("SELECT count(*) FROM access_audit_event_tombstones").rows == [[0]]
      assert Repo.query!("SELECT count(*) FROM access_audit_expired_requests").rows == [[0]]
      assert {:ok, :valid} = Audit.verify_chain()

      tampered
      |> Ecto.Changeset.change([{field, Map.fetch!(observation, field)}])
      |> Repo.update!()
    end

    # Repaired raw metadata can then be pruned, and the originally signed
    # sequence remains reserved after both raw detail and aggregate expiration.
    assert {:ok, %{observations: 1}} = AccessAudit.prune(enabled: true)
    assert {:error, :sequence_conflict} = AccessAudit.ingest(ctx.identity, [event(ctx, 1)])
    assert {:ok, :valid} = Audit.verify_chain()
  end

  defp event(ctx, sequence) do
    %{
      "schema_version" => 1,
      "event_id" => Ecto.UUID.generate(),
      "producer_id" => ctx.producer,
      "producer_sequence" => sequence,
      "request_id" => Ecto.UUID.generate(),
      "source" => "agent",
      "phase" => "admitted",
      "observed_at" => DateTime.to_iso8601(DateTime.utc_now()),
      "identity_status" => "unverified",
      "attribution" => "none",
      "secret_path" => "retention.fixture",
      "operation" => "read",
      "outcome" => "unknown",
      "reason_code" => "none",
      "cache_status" => "none"
    }
  end
end
