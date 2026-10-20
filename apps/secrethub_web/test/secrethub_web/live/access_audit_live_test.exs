defmodule SecretHub.Web.AccessAuditLiveTest do
  use ExUnit.Case, async: false
  import Phoenix.LiveViewTest, only: [rendered_to_string: 1]
  import Ecto.Query
  alias SecretHub.Core.{AccessAudit, Audit, Repo, RuntimeDatabaseFixture}
  alias SecretHub.Core.AccessAudit.Producer
  alias SecretHub.Shared.Schemas.{Agent, Certificate}
  alias SecretHub.Web.AuditLogLive

  setup_all do
    RuntimeDatabaseFixture.prepare_template()
  end

  setup tags do
    RuntimeDatabaseFixture.setup(tags)
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    agent = "ui-audit-#{System.unique_integer([:positive])}"

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
      name: "UI fixture",
      status: :active,
      certificate_id: certificate.id
    })

    %{
      identity: %{agent_id: agent, certificate_id: certificate.id},
      app: Ecto.UUID.generate(),
      producer: Ecto.UUID.generate()
    }
  end

  test "persisted 100-request distribution survives phase events and replay in the rendered UI",
       ctx do
    for n <- 1..100 do
      outcome =
        cond do
          n <= 60 -> "success"
          n <= 80 -> "denied"
          n <= 90 -> "error"
          true -> "unknown"
        end

      admitted = event(ctx, n * 3 - 2, "admitted")

      attempt =
        event(ctx, n * 3 - 1, "attempt", %{
          "request_id" => admitted["request_id"],
          "attempt_id" => Ecto.UUID.generate()
        })

      sent =
        event(ctx, n * 3, "response_sent", %{
          "request_id" => admitted["request_id"],
          "attempt_id" => attempt["attempt_id"],
          "outcome" => outcome
        })

      events = if outcome == "unknown", do: [admitted, attempt], else: [admitted, attempt, sent]
      assert {:ok, _} = AccessAudit.ingest(ctx.identity, events)
      assert {:ok, _} = AccessAudit.ingest(ctx.identity, events)
    end

    assert {:ok, _} =
             Audit.log_event(%{
               event_type: "secret.accessed",
               actor_type: "agent",
               actor_id: ctx.identity.agent_id,
               event_data: %{"value" => "UI-SECRET-CANARY", "token" => "UI-TOKEN-CANARY"}
             })

    socket = page(%{"application_id" => ctx.app})

    assert Map.take(
             socket.assigns.summary,
             ~w(requests success denied error incomplete attempts unverified)a
           ) == %{
             requests: 100,
             success: 60,
             denied: 20,
             error: 10,
             incomplete: 10,
             attempts: 100,
             unverified: 0
           }

    assert length(socket.assigns.requests) == 50
    html = html(socket)
    assert html =~ "Application access audit"
    assert html =~ "Agent-attested application certificate"
    assert html =~ "Legacy / partial coverage"
    assert html =~ "secret.accessed"
    refute html =~ "UI-SECRET-CANARY"
    refute html =~ "UI-TOKEN-CANARY"
    assert html =~ "does not prove consumer use"
  end

  test "filters and keyset URLs retain the window and application without counting the page",
       ctx do
    for n <- 1..3,
        do: assert({:ok, _} = AccessAudit.ingest(ctx.identity, [event(ctx, n, "admitted")]))

    params = %{
      "application_id" => ctx.app,
      "limit" => "2",
      "secret_path" => "audit.fixture.secret"
    }

    socket = page(params)
    assert socket.assigns.summary.requests == 3
    assert length(socket.assigns.requests) == 2
    assert is_binary(socket.assigns.next_cursor)
    assert html(socket) =~ "Next requests"
    second = page(Map.put(socket.assigns.filters, "cursor", socket.assigns.next_cursor))
    assert length(second.assigns.requests) == 1
    assert second.assigns.summary.requests == 3
    assert second.assigns.next_cursor == nil
    refute hd(second.assigns.requests).id in Enum.map(socket.assigns.requests, & &1.id)

    {:noreply, patched} =
      AuditLogLive.handle_event(
        "filter_logs",
        %{"filters" => Map.merge(params, %{"agent_id" => "", "outcome" => "denied"})},
        socket
      )

    {:live, :patch, %{to: url}} = patched.redirected
    query = url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
    assert query["application_id"] == ctx.app
    assert query["outcome"] == "denied"
    assert query["from"] == socket.assigns.filters["from"]
    assert query["to"] == socket.assigns.filters["to"]
    refute Map.has_key?(query, "cursor")
    refute Map.has_key?(query, "agent_id")
  end

  test "time boundaries are exclusive at the end and refresh reconciles a late terminal event",
       ctx do
    from = DateTime.add(DateTime.utc_now(), -600)
    to = DateTime.add(from, 300)
    first = event(ctx, 1, "admitted", %{"observed_at" => DateTime.to_iso8601(from)})
    excluded = event(ctx, 2, "admitted", %{"observed_at" => DateTime.to_iso8601(to)})
    assert {:ok, _} = AccessAudit.ingest(ctx.identity, [first, excluded])
    socket = page(%{"from" => DateTime.to_iso8601(from), "to" => DateTime.to_iso8601(to)})
    assert socket.assigns.summary.requests == 1
    assert socket.assigns.summary.incomplete == 1

    sent =
      event(ctx, 3, "response_sent", %{
        "request_id" => first["request_id"],
        "attempt_id" => Ecto.UUID.generate(),
        "outcome" => "success"
      })

    assert {:ok, _} = AccessAudit.ingest(ctx.identity, [sent])
    {:noreply, refreshed} = AuditLogLive.handle_event("refresh", %{}, socket)
    assert refreshed.assigns.summary.requests == 1
    assert refreshed.assigns.summary.success == 1
    assert refreshed.assigns.summary.incomplete == 0
  end

  test "timeline displays independent Core facts, Agent reports and ambiguous delivery", ctx do
    request = Ecto.UUID.generate()
    attempt = Ecto.UUID.generate()

    assert {:ok, _} =
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

    sent =
      event(ctx, 2, "response_sent", %{
        "request_id" => request,
        "attempt_id" => attempt,
        "outcome" => "success",
        "cache_status" => "hit"
      })

    assert {:ok, _} =
             AccessAudit.ingest(ctx.identity, [
               sent,
               event(ctx, 1, "admitted", %{"request_id" => request})
             ])

    socket = page(%{"id" => request, "namespace" => "agent:" <> ctx.identity.agent_id})
    html = html(socket)
    assert length(socket.assigns.timeline) == 3
    assert html =~ "Independently Core-verified application certificate"
    assert html =~ "Agent-attested application certificate"
    assert html =~ "Contradictory observations"
    assert html =~ "core_decision"
    assert html =~ "response_sent"
    assert html =~ "permission_denied"
    assert html =~ "hit"
    assert html =~ "Received by Core"
  end

  test "empty, invalid window, invalid cursor and unavailable storage never fabricate zero activity" do
    empty = page(%{})
    assert html(empty) =~ "No retained requests in this window"
    assert html(empty) =~ "Pending backlog is unknown"
    invalid = page(%{"from" => "invalid-date"})
    assert invalid.assigns.summary == nil
    assert html(invalid) =~ "Audit query unavailable"
    assert page(%{"cursor" => "bad-cursor"}).assigns.summary == nil
    cursor = [nil, 1] |> Jason.encode!() |> Base.url_encode64(padding: false)
    assert html(page(%{"cursor" => cursor})) =~ "Audit query unavailable"
    assert html(page(%{"application_id" => %{"bad" => "filter"}})) =~ "Audit query unavailable"
    Repo.query!("ALTER TABLE access_audit_requests RENAME TO hidden_access_audit_requests")
    failed = page(%{})
    assert failed.assigns.summary == nil
    assert html(failed) =~ "Audit query unavailable"
    refute html(failed) =~ "No retained requests in this window"
  end

  test "pipeline shows stale producer gaps and stale backlog separately from request activity",
       ctx do
    assert {:ok, _} = AccessAudit.ingest(ctx.identity, [event(ctx, 3, "admitted")])
    stale = DateTime.add(DateTime.utc_now(), -600)
    Repo.update_all(from(p in Producer), set: [last_received_at: stale])

    assert {:ok, _} =
             AccessAudit.record_health(ctx.identity, %{
               "pending_events" => 8,
               "pending_bytes" => 2048,
               "quarantined_events" => 1,
               "oldest_pending_at" => DateTime.to_iso8601(stale),
               "oldest_pending_age_ms" => 600_000,
               "journal_status" => "quarantined"
             })

    Repo.query!("UPDATE access_audit_agent_health SET received_at = $1", [stale])
    html = page(%{}) |> html()
    assert html =~ "Stale / disconnected"
    assert html =~ "Sequence gaps: 2"
    assert html =~ "Pending events: 8"
    assert html =~ "Quarantined: 1"
    assert html =~ "Reported oldest pending age: 600000 ms"
    assert html =~ "Retained evidence only"
  end

  test "one healthy report does not hide another Agent's missing report or a disconnected status",
       ctx do
    existing = Repo.get!(Certificate, ctx.identity.certificate_id)
    missing_agent = "missing-ui-#{System.unique_integer([:positive])}"

    missing_certificate =
      Repo.insert!(%Certificate{
        serial_number: Ecto.UUID.generate(),
        fingerprint: Ecto.UUID.generate(),
        certificate_pem: "fixture",
        subject: "fixture",
        issuer: "fixture",
        common_name: missing_agent,
        cert_type: :agent_client,
        entity_id: missing_agent,
        entity_type: "agent",
        valid_from: existing.valid_from,
        valid_until: existing.valid_until
      })

    Repo.insert!(%Agent{
      agent_id: missing_agent,
      name: "Missing report fixture",
      status: :disconnected,
      certificate_id: missing_certificate.id
    })

    assert {:ok, _} =
             AccessAudit.record_health(ctx.identity, %{
               "pending_events" => 0,
               "pending_bytes" => 0,
               "quarantined_events" => 0,
               "oldest_pending_at" => nil,
               "oldest_pending_age_ms" => nil,
               "journal_status" => "healthy"
             })

    Repo.update_all(from(a in Agent, where: a.agent_id == ^ctx.identity.agent_id),
      set: [status: :disconnected]
    )

    html = page(%{}) |> html()
    assert html =~ "Agent connection status: disconnected"
    assert html =~ "Pending backlog is unknown"
    assert html =~ "Agents without a current report: #{missing_agent}"
  end

  test "expired raw timelines are distinguished from failed queries while aggregate remains",
       ctx do
    event = event(ctx, 1, "admitted")
    assert {:ok, _} = AccessAudit.ingest(ctx.identity, [event])
    old = DateTime.add(DateTime.utc_now(), -40 * 86_400)
    Repo.update_all(SecretHub.Core.AccessAudit.Request, set: [last_received_at: old])
    assert {:ok, %{observations: 1, requests: 0}} = AccessAudit.prune(enabled: true)

    socket =
      page(%{"id" => event["request_id"], "namespace" => "agent:" <> ctx.identity.agent_id})

    assert socket.assigns.summary.requests == 1
    assert socket.assigns.timeline_error == :raw_expired
    html = html(socket)
    assert html =~ "Raw timeline expired under retention"
    assert html =~ "Raw detail target: 30 days"
    refute html =~ "Audit query unavailable"
    refute html =~ "access.retention_checkpoint"
  end

  defp page(params) do
    socket = %Phoenix.LiveView.Socket{
      assigns: %{__changed__: %{}},
      endpoint: SecretHub.Web.Endpoint,
      router: SecretHub.Web.Router
    }

    {:ok, socket} = AuditLogLive.mount(%{}, %{}, socket)

    {:noreply, socket} =
      AuditLogLive.handle_params(params, "http://localhost/admin/audit", socket)

    socket
  end

  defp html(socket), do: socket.assigns |> AuditLogLive.render() |> rendered_to_string()

  defp event(ctx, sequence, phase, extra \\ %{}) do
    Map.merge(
      %{
        "schema_version" => 1,
        "event_id" => Ecto.UUID.generate(),
        "producer_id" => ctx.producer,
        "producer_sequence" => sequence,
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
