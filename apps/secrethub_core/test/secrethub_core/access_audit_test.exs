defmodule SecretHub.Core.AccessAuditTest do
  use ExUnit.Case, async: false
  import Ecto.Query
  alias SecretHub.Core.{AccessAudit, Audit, Repo, RuntimeDatabaseFixture}
  alias SecretHub.Core.AccessAudit.{Observation, Producer, Queries, Request}
  alias SecretHub.Shared.Schemas.{Agent, AuditLog, Certificate}

  setup_all do
    RuntimeDatabaseFixture.prepare_template()
  end

  setup tags do
    RuntimeDatabaseFixture.setup(tags)
    agent_id = "audit-agent-#{System.unique_integer([:positive])}"
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    certificate =
      Repo.insert!(%Certificate{
        serial_number: Ecto.UUID.generate(),
        fingerprint: Ecto.UUID.generate(),
        certificate_pem: "fixture",
        subject: "fixture",
        issuer: "fixture",
        common_name: agent_id,
        cert_type: :agent_client,
        entity_id: agent_id,
        entity_type: "agent",
        valid_from: now,
        valid_until: DateTime.add(now, 86_400)
      })

    Repo.insert!(%Agent{
      agent_id: agent_id,
      name: "Audit Agent",
      status: :active,
      certificate_id: certificate.id
    })

    %{
      identity: %{agent_id: agent_id, certificate_id: certificate.id},
      producer: Ecto.UUID.generate(),
      app: Ecto.UUID.generate()
    }
  end

  test "100 accepted operations retain 60 success 20 denied 10 error 10 incomplete independent of phases and retries",
       ctx do
    for n <- 1..100 do
      outcome =
        cond do
          n <= 60 -> "success"
          n <= 80 -> "denied"
          n <= 90 -> "error"
          true -> "unknown"
        end

      admission = event(ctx, (n - 1) * 3 + 1, "admitted")

      attempt =
        event(ctx, (n - 1) * 3 + 2, "attempt", %{
          "request_id" => admission["request_id"],
          "attempt_id" => Ecto.UUID.generate()
        })

      terminal =
        event(ctx, (n - 1) * 3 + 3, "response_sent", %{
          "request_id" => admission["request_id"],
          "attempt_id" => attempt["attempt_id"],
          "outcome" => outcome
        })

      batch =
        if outcome == "unknown", do: [admission, attempt], else: [admission, attempt, terminal]

      assert {:ok, %{accepted: ids, duplicates: []}} = AccessAudit.ingest(ctx.identity, batch)
      assert ids == Enum.map(batch, & &1["event_id"])
      assert {:ok, %{accepted: [], duplicates: ^ids}} = AccessAudit.ingest(ctx.identity, batch)
    end

    assert {:ok,
            %{
              requests: 100,
              success: 60,
              denied: 20,
              error: 10,
              incomplete: 10,
              attempts: 100,
              unverified: 0
            }} = AccessAudit.summary()

    assert {:ok, [%{application_id: app, requests: 100, success: 60}]} =
             AccessAudit.applications()

    assert app == ctx.app
    assert {:ok, [%{secret_path: "audit.fixture.secret", requests: 100}]} = AccessAudit.secrets()
    assert {:ok, [%{requests: 100}]} = AccessAudit.time_buckets()
    assert {:ok, [%{reason_code: "none", count: 100}]} = AccessAudit.reasons()
    assert Repo.aggregate(Request, :count) == 100
    assert Repo.aggregate(Observation, :count) == 290
    assert {:ok, :valid} = Audit.verify_chain()
  end

  test "reordered delivery reconciles incomplete Core fact, admission never overwrites delivery or verified Core identity",
       ctx do
    request = Ecto.UUID.generate()
    attempt = Ecto.UUID.generate()

    assert {:ok, core} =
             AccessAudit.record_core(%{
               agent_id: ctx.identity.agent_id,
               application_id: ctx.app,
               request_id: request,
               attempt_id: attempt,
               identity_status: :verified,
               attribution: :core_certificate,
               phase: :core_decision,
               outcome: :denied,
               reason_code: :permission_denied,
               secret_path: "audit.fixture.secret"
             })

    assert {:ok, %{incomplete: 1, denied: 0}} = AccessAudit.summary()

    sent =
      event(ctx, 3, "response_sent", %{
        "request_id" => request,
        "attempt_id" => attempt,
        "outcome" => "success"
      })

    admission = event(ctx, 1, "admitted", %{"request_id" => request})
    assert {:ok, _} = AccessAudit.ingest(ctx.identity, [sent])
    assert {:ok, %{producers: producers}} = AccessAudit.health()
    assert %{gaps: 2} = Enum.find(producers, &(&1.producer_id == ctx.producer))
    assert {:ok, _} = AccessAudit.ingest(ctx.identity, [admission])

    assert {:ok,
            %{
              entries: [
                %{
                  contradictory: true,
                  core_outcome: "denied",
                  delivery_outcome: "success",
                  attribution: "core_certificate",
                  attempts: 1
                }
              ]
            }} = AccessAudit.requests()

    assert {:ok, observations} = AccessAudit.timeline("agent:" <> ctx.identity.agent_id, request)
    assert Enum.any?(observations, &(&1.id == core.id))
    assert {:ok, %{producers: producers}} = AccessAudit.health()
    assert %{gaps: 1} = Enum.find(producers, &(&1.producer_id == ctx.producer))
  end

  test "collisions and malformed batches roll back all observations, audit appends, and projections",
       ctx do
    initial = event(ctx, 1, "admitted")
    assert {:ok, _} = AccessAudit.ingest(ctx.identity, [initial])
    candidate = event(ctx, 2, "admitted")
    changed = Map.put(initial, "secret_path", "other.secret")
    assert {:error, :event_conflict} = AccessAudit.ingest(ctx.identity, [candidate, changed])
    assert Repo.aggregate(Observation, :count) == 1
    assert Repo.aggregate(AuditLog, :count) == 1
    assert Repo.aggregate(Request, :count) == 1

    assert {:error, :sequence_conflict} =
             AccessAudit.ingest(ctx.identity, [event(ctx, 1, "admitted")])

    assert {:error, _} =
             AccessAudit.ingest(ctx.identity, [
               candidate,
               Map.put(candidate, "secret_value", "CANARY-SECRET")
             ])

    assert {:error, :invalid_batch} =
             AccessAudit.ingest(ctx.identity, List.duplicate(candidate, 101))

    assert Repo.aggregate(Observation, :count) == 1
    assert {:ok, :valid} = Audit.verify_chain()
  end

  test "revocation and provenance are checked on every batch; no claimed verified app from invalid traffic",
       ctx do
    base = event(ctx, 1, "admitted")

    for forbidden <- [
          Map.put(base, "agent_id", "different-agent"),
          Map.put(base, "phase", "core_access"),
          Map.put(base, "attribution", "core_certificate"),
          Map.put(base, "producer_id", "00000000-0000-4000-8000-000000000001")
        ] do
      assert {:error, _} = AccessAudit.ingest(ctx.identity, [forbidden])
    end

    invalid =
      base
      |> Map.put("identity_status", "unverified")
      |> Map.put("attribution", "none")
      |> Map.put("application_id", nil)
      |> Map.put("phase", "rejected")
      |> Map.put("outcome", "denied")

    assert {:ok, _} = AccessAudit.ingest(ctx.identity, [invalid])
    assert {:ok, []} = AccessAudit.applications()
    assert {:ok, %{unverified: 1, denied: 1}} = AccessAudit.summary()

    Repo.get!(Certificate, ctx.identity.certificate_id)
    |> Ecto.Changeset.change(revoked: true)
    |> Repo.update!()

    assert {:error, _} = AccessAudit.ingest(ctx.identity, [event(ctx, 2, "admitted")])
    assert Repo.aggregate(Observation, :count) == 1
  end

  test "strict evidence rejects canaries and signatures cover the entire received envelope",
       ctx do
    assert {:error, _} =
             AccessAudit.record_core(%{
               phase: :core_decision,
               outcome: :error,
               reason_code: :internal_error,
               value: "CANARY-SECRET"
             })

    assert Repo.aggregate(AuditLog, :count) == 0
    assert {:ok, _} = AccessAudit.ingest(ctx.identity, [event(ctx, 1, "admitted")])
    log = Repo.one!(AuditLog)
    assert log.hash_version == 2
    assert log.event_data["access_audit"]["namespace"] == "agent:" <> ctx.identity.agent_id
    refute Jason.encode!(log.event_data) =~ "CANARY-SECRET"
    assert {:ok, :valid} = Audit.verify_chain()

    altered =
      put_in(log.event_data, ["access_audit", "envelope", "reason_code"], "internal_error")

    Repo.update_all(from(a in AuditLog, where: a.id == ^log.id), set: [event_data: altered])
    assert {:error, _} = Audit.verify_chain()
  end

  test "failed signed append never acknowledges or stores a partial batch", ctx do
    Repo.query!(
      "CREATE FUNCTION fail_access_audit_append() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event_type = 'access.observed' THEN RAISE EXCEPTION 'fixture storage failure'; END IF; RETURN NEW; END $$"
    )

    Repo.query!(
      "CREATE TRIGGER access_audit_failure BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION fail_access_audit_append()"
    )

    assert {:error, :storage_unavailable} =
             AccessAudit.ingest(ctx.identity, [event(ctx, 1, "admitted")])

    assert Repo.aggregate(Observation, :count) == 0
    assert Repo.aggregate(Request, :count) == 0
    assert Repo.aggregate(Producer, :count) == 0
  end

  test "keyset, finite windows, grouped filters and EXPLAIN use actual indexes", ctx do
    for n <- 1..4,
        do: assert({:ok, _} = AccessAudit.ingest(ctx.identity, [event(ctx, n, "admitted")]))

    assert {:ok, %{entries: first, next_cursor: cursor}} = AccessAudit.requests(%{limit: 2})
    assert length(first) == 2 and is_binary(cursor)

    assert {:ok, %{entries: second, next_cursor: nil}} =
             AccessAudit.requests(%{limit: 2, cursor: cursor})

    assert length(second) == 2
    assert MapSet.disjoint?(MapSet.new(first, & &1.id), MapSet.new(second, & &1.id))
    assert {:error, :invalid_cursor} = AccessAudit.requests(%{cursor: "not-a-cursor"})

    assert {:error, :invalid_filter} =
             AccessAudit.summary(%{from: DateTime.add(DateTime.utc_now(), -32 * 86_400)})

    assert {:error, :invalid_filter} = AccessAudit.requests(%{limit: 101})
    assert {:error, :invalid_filter} = AccessAudit.requests(%{unknown: "CANARY-SECRET"})
    assert {:ok, %{requests: 0}} = AccessAudit.summary(%{application_id: Ecto.UUID.generate()})
    {:ok, query, _} = Queries.query(%{application_id: ctx.app})

    fixture =
      Repo.one!(from(r in Request, limit: 1)) |> Map.from_struct() |> Map.drop([:__meta__, :id])

    other_app = Ecto.UUID.generate()

    rows =
      for _ <- 1..5000,
          do: Map.merge(fixture, %{request_id: Ecto.UUID.generate(), application_id: other_app})

    rows |> Enum.chunk_every(1000) |> Enum.each(&Repo.insert_all(Request, &1))
    Repo.query!("ANALYZE access_audit_requests")

    sql =
      Repo.explain(:all, from(r in query, order_by: [desc: r.started_at, desc: r.id], limit: 100),
        analyze: true
      )

    assert sql =~ "access_audit_requests_application_id_started_at_id_index"
  end

  test "null and malformed keyset components return invalid cursor without raising" do
    for components <- [
          [nil, 1],
          [false, 1],
          [123, 1],
          ["invalid-date", 1],
          [DateTime.to_iso8601(DateTime.utc_now()), 0]
        ] do
      cursor = components |> Jason.encode!() |> Base.url_encode64(padding: false)
      assert {:error, :invalid_cursor} = AccessAudit.requests(%{cursor: cursor})
    end
  end

  test "health-only uploads persist bounded authenticated operational reports", ctx do
    status = %{
      "pending_events" => 5,
      "pending_bytes" => 2000,
      "quarantined_events" => 1,
      "oldest_pending_at" => DateTime.to_iso8601(DateTime.add(DateTime.utc_now(), 3600)),
      "oldest_pending_age_ms" => 120_000,
      "journal_status" => "quarantined"
    }

    assert {:ok, %{accepted: [], duplicates: []}} = AccessAudit.ingest(ctx.identity, [], status)

    assert {:ok,
            %{
              pending_unknown: false,
              reports: [%{status: ^status, stale: false, oldest_pending_age_ms: age}]
            }} = AccessAudit.health()

    assert age == 120_000

    assert {:error, :invalid_health} =
             AccessAudit.record_health(
               ctx.identity,
               Map.put(status, "secret_value", "CANARY-SECRET")
             )

    assert {:error, :invalid_batch} = AccessAudit.ingest(ctx.identity, [])
  end

  test "a reporting Agent never hides another enrolled Agent without reports", ctx do
    status = %{
      "pending_events" => 0,
      "pending_bytes" => 0,
      "quarantined_events" => 0,
      "oldest_pending_at" => nil,
      "journal_status" => "healthy"
    }

    assert {:ok, _} = AccessAudit.record_health(ctx.identity, status)
    other = "missing-report-agent"

    Repo.insert!(%Agent{
      agent_id: other,
      name: "Missing report",
      status: :disconnected,
      certificate_id: ctx.identity.certificate_id
    })

    assert {:ok,
            %{
              pending_unknown: true,
              unknown_agents: [^other],
              coverage_limited: false,
              reports: [%{agent_status: :active}]
            }} = AccessAudit.health()
  end

  test "additive migration rolls down and back up without altering existing audit chain", ctx do
    assert {:ok, _} =
             Audit.log_event(%{
               event_type: "secret.accessed",
               actor_type: "agent",
               actor_id: ctx.identity.agent_id
             })

    path = Application.app_dir(:secrethub_core, "priv/repo/migrations")

    assert [20_261_020_000_002, 20_261_020_000_001] =
             Ecto.Migrator.run(Repo, path, :down, to: 20_261_020_000_001, log: false)

    assert {:ok, :valid} = Audit.verify_chain()

    assert [20_261_020_000_001, 20_261_020_000_002] =
             Ecto.Migrator.run(Repo, path, :up, to: 20_261_020_000_002, log: false)

    assert {:ok, _} = AccessAudit.ingest(ctx.identity, [event(ctx, 1, "admitted")])
    assert {:ok, :valid} = Audit.verify_chain()
  end

  test "persistent Agent sequence determines terminal state despite clock skew; successful retry does not contradict a previous denied attempt",
       ctx do
    request = Ecto.UUID.generate()
    denied_attempt = Ecto.UUID.generate()
    successful_attempt = Ecto.UUID.generate()

    assert {:ok, _} =
             AccessAudit.record_core(%{
               agent_id: ctx.identity.agent_id,
               request_id: request,
               attempt_id: denied_attempt,
               phase: :core_decision,
               outcome: :denied,
               reason_code: :permission_denied
             })

    assert {:ok, _} =
             AccessAudit.record_core(%{
               agent_id: ctx.identity.agent_id,
               request_id: request,
               attempt_id: successful_attempt,
               phase: :core_access,
               outcome: :success,
               reason_code: :allowed
             })

    earlier =
      event(ctx, 1, "response_sent", %{
        "request_id" => request,
        "attempt_id" => denied_attempt,
        "outcome" => "denied",
        "observed_at" => DateTime.to_iso8601(DateTime.add(DateTime.utc_now(), 60))
      })

    later =
      event(ctx, 2, "response_sent", %{
        "request_id" => request,
        "attempt_id" => successful_attempt,
        "outcome" => "success"
      })

    assert {:ok, _} = AccessAudit.ingest(ctx.identity, [later, earlier])

    assert {:ok,
            %{
              entries: [
                %{outcome: "success", contradictory: false, core_outcome: "success", attempts: 2}
              ]
            }} = AccessAudit.requests()

    conflict =
      event(ctx, 3, "admitted", %{
        "request_id" => request,
        "application_id" => Ecto.UUID.generate(),
        "secret_path" => "different.path"
      })

    assert {:ok, _} = AccessAudit.ingest(ctx.identity, [conflict])
    assert {:ok, %{entries: [%{contradictory: true}]}} = AccessAudit.requests()
  end

  test "per-request observation limit bounds projection and rejects the entire overflowing batch",
       ctx do
    existing = event(ctx, 1, "admitted")
    assert {:ok, _} = AccessAudit.ingest(ctx.identity, [existing])
    fixture = Repo.one!(Observation) |> Map.from_struct() |> Map.drop([:__meta__, :id])

    rows =
      for n <- 2..999,
          do: Map.merge(fixture, %{event_id: Ecto.UUID.generate(), producer_sequence: n})

    Repo.insert_all(Observation, rows)
    candidate = event(ctx, 1000, "admitted", %{"request_id" => existing["request_id"]})
    overflow = event(ctx, 1001, "admitted", %{"request_id" => existing["request_id"]})

    assert {:error, :request_limit_exceeded} =
             AccessAudit.ingest(ctx.identity, [candidate, overflow])

    assert Repo.aggregate(Observation, :count) == 999
    assert Repo.aggregate(AuditLog, :count) == 1
  end

  test "retention defaults to disabled deletion with explicit finite raw and aggregate targets" do
    assert {:ok,
            %{
              enabled: false,
              raw_days: 30,
              aggregate_days: 365,
              automatic_deletion: false,
              manual_pruning: true
            }} =
             AccessAudit.retention_policy()

    assert {:ok, %{enabled: true, raw_days: 30, aggregate_days: 365, automatic_deletion: false}} =
             AccessAudit.retention_policy(enabled: true, raw_days: 30, aggregate_days: 365)

    assert {:error, :invalid_retention_policy} =
             AccessAudit.retention_policy(raw_days: 365, aggregate_days: 30)

    assert {:error, :invalid_retention_policy} = AccessAudit.retention_policy(raw_days: 0)
    assert {:error, :invalid_retention_policy} = AccessAudit.retention_policy(aggregate_days: 29)
  end

  defp event(ctx, seq, phase, extra \\ %{}) do
    Map.merge(
      %{
        "schema_version" => 1,
        "event_id" => Ecto.UUID.generate(),
        "producer_id" => ctx.producer,
        "producer_sequence" => seq,
        "request_id" => Ecto.UUID.generate(),
        "attempt_id" => nil,
        "source" => "agent",
        "phase" => phase,
        "observed_at" => DateTime.to_iso8601(DateTime.utc_now()),
        "application_id" => ctx.app,
        "identity_status" => "verified",
        "attribution" => "agent_certificate",
        "secret_path" => "audit.fixture.secret",
        "operation" => "read",
        "outcome" => "unknown",
        "reason_code" => "none",
        "cache_status" => "none"
      },
      extra
    )
  end
end
