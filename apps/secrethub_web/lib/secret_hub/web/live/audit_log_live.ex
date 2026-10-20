defmodule SecretHub.Web.AuditLogLive do
  @moduledoc "Persisted application access evidence and reporting coverage."
  use SecretHub.Web, :live_view
  import Ecto.Query, only: [from: 2]

  alias SecretHub.Core.{AccessAudit, Repo}
  alias SecretHub.Shared.Schemas.AuditLog

  @filter_keys ~w(application_id agent_id secret_path outcome reason_code from to limit cursor)
  @counts [
    requests: "Requests",
    success: "Success",
    denied: "Denied",
    error: "Error",
    incomplete: "Incomplete",
    attempts: "Attempts",
    unverified: "Unverified"
  ]
  @refresh_ms 15_000

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: Process.send_after(self(), :refresh_audit, @refresh_ms)

    {:ok,
     assign(socket,
       filters: %{},
       summary: nil,
       requests: [],
       next_cursor: nil,
       applications: [],
       secrets: [],
       reasons: [],
       buckets: [],
       timeline: [],
       selected_request: nil,
       selected_namespace: nil,
       query_error: nil,
       timeline_error: nil,
       health: nil,
       health_error: nil,
       legacy: [],
       legacy_error: nil,
       loaded: false,
       refreshed_at: nil,
       count_labels: @counts
     )}
  end

  @impl true
  def handle_params(params, _uri, socket) do
    socket =
      assign(socket,
        filters: filters(params),
        selected_request: text_or_nil(params["id"]),
        selected_namespace: text_or_nil(params["namespace"])
      )

    {:noreply, load(socket)}
  end

  @impl true
  def handle_event("filter_logs", %{"filters" => params}, socket) do
    params =
      socket.assigns.filters
      |> Map.merge(Map.take(params, @filter_keys))
      |> Map.delete("cursor")
      |> nonempty()

    {:noreply, push_patch(socket, to: audit_url(params))}
  end

  def handle_event("clear_filters", _, socket),
    do: {:noreply, push_patch(socket, to: "/admin/audit")}

  def handle_event("refresh", _, socket), do: {:noreply, load(socket)}

  @impl true
  def handle_info(:refresh_audit, socket) do
    Process.send_after(self(), :refresh_audit, @refresh_ms)
    {:noreply, load(socket)}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="space-y-4 text-on-surface" aria-busy={!@loaded}>
      <header class="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 class="text-3xl font-bold">Application access audit</h1>
          <p class="text-sm text-on-surface-variant">
            Retained evidence only. A successful local response does not prove consumer use.
          </p>
        </div>
        <button type="button" class="btn btn-secondary" phx-click="refresh">Refresh evidence</button>
      </header>
      <p class="text-sm text-on-surface-variant">
        Counts represent logical requests, not phase events or upload retries. Core grants do not prove delivery.
        This fixed window refreshes every 15 seconds for late reports; clear filters to open the latest 24 hours.
        Last refreshed: {timestamp(@refreshed_at)}.
      </p>

      <.dm_card id="audit-filters">
        <:title>Filter retained requests</:title>
        <form id="audit-filter-form" phx-submit="filter_logs" class="space-y-4">
          <div class="grid grid-cols-1 gap-4 md:grid-cols-3">
            <div :for={
              {key, label} <- [
                {"application_id", "Application UUID"},
                {"agent_id", "Agent ID"},
                {"secret_path", "Secret path"},
                {"reason_code", "Reason code"},
                {"from", "From (ISO 8601 with timezone)"},
                {"to", "To (ISO 8601 with timezone)"}
              ]
            }>
              <label for={"audit-#{key}"} class="block text-sm font-medium">{label}</label>
              <input
                id={"audit-#{key}"}
                type="text"
                name={"filters[#{key}]"}
                value={text_or_nil(@filters[key])}
                class="input w-full"
              />
            </div>
            <div>
              <label for="audit-outcome" class="block text-sm font-medium">Outcome</label>
              <select id="audit-outcome" name="filters[outcome]" class="select w-full">
                <option value="">All outcomes</option>
                <option
                  :for={outcome <- ~w(success denied error incomplete)}
                  value={outcome}
                  selected={@filters["outcome"] == outcome}
                >
                  {outcome}
                </option>
              </select>
            </div>
            <div>
              <label for="audit-limit" class="block text-sm font-medium">Requests per page (1–100)</label>
              <input
                id="audit-limit"
                name="filters[limit]"
                type="number"
                min="1"
                max="100"
                value={text_or_nil(@filters["limit"])}
                class="input w-full"
              />
            </div>
          </div>
          <p class="text-sm text-on-surface-variant">
            Maximum window: 31 days. Start inclusive, end exclusive. Default: latest 24 hours.
          </p>
          <div class="flex gap-4">
            <button type="submit" class="btn btn-primary">Apply filters</button>
            <button type="button" class="btn btn-ghost" phx-click="clear_filters">Clear filters / latest 24 hours</button>
          </div>
        </form>
      </.dm_card>

      <p :if={!@loaded} role="status">Loading audit evidence…</p>
      <.dm_card :if={@query_error} id="audit-query-error">
        <:title>Audit query unavailable</:title>
        <p role="alert">
          {error_message(@query_error)} Counts are unavailable; this is not zero activity.
        </p>
      </.dm_card>

      <.dm_card :if={@summary} id="audit-summary">
        <:title>
          {if @filters["application_id"], do: "Selected application", else: "Request overview"}
        </:title>
        <p :if={@filters["application_id"]} class="font-mono break-all">
          {@filters["application_id"]}
        </p>
        <p class="text-sm text-on-surface-variant">
          Last observed activity in this window: {timestamp(@summary[:last_activity])}
        </p>
        <dl class="grid grid-cols-2 gap-4 md:grid-cols-7">
          <div :for={{key, label} <- @count_labels}>
            <dt class="text-sm text-on-surface-variant">{label}</dt>
            <dd id={"audit-count-#{key}"} class="text-2xl font-semibold">{@summary[key]}</dd>
          </div>
        </dl>
        <p :if={@summary.requests == 0} role="status">
          No retained requests in this window. This does not establish inactivity; check reporting coverage below.
        </p>
      </.dm_card>

      <.dm_card :if={@summary} id="audit-applications">
        <:title>Applications and identity provenance</:title>
        <p class="text-sm text-on-surface-variant">
          At most 100 application/provenance groups, using the selected non-application filters. Unverified requests are excluded from these groups.
        </p>
        <div class="overflow-x-auto">
          <table class="table w-full">
            <caption class="sr-only">Application request totals by identity provenance</caption>
            <thead>
              <tr>
                <th scope="col">Application</th><th scope="col">Provenance</th><th
                  :for={{_, label} <- @count_labels}
                  scope="col"
                >
                  {label}
                </th><th scope="col">Last activity</th>
              </tr>
            </thead>
            <tbody>
              <tr :for={app <- @applications}>
                <td>
                  <.link
                    patch={
                      audit_url(
                        Map.put(Map.delete(@filters, "cursor"), "application_id", app.application_id)
                      )
                    }
                    class="link font-mono"
                  >{app.application_id}</.link>
                </td>
                <td>{identity_label(app.attribution)}</td>
                <td :for={{key, _} <- @count_labels}>{app[key]}</td>
                <td>{timestamp(app[:last_activity])}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <p :if={@applications == []}>No attributed application evidence matches these filters.</p>
      </.dm_card>

      <div :if={@summary} class="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <.dm_card id="audit-secrets">
          <:title>Requested secrets</:title>
          <p class="text-sm text-on-surface-variant">
            At most 100 groups. Missing paths remain unknown.
          </p>
          <div class="overflow-x-auto">
            <table class="table w-full">
              <caption class="sr-only">Request counts by secret path</caption>
              <thead>
                <tr>
                  <th scope="col">Secret</th><th :for={{_, label} <- @count_labels} scope="col">
                    {label}
                  </th>
                </tr>
              </thead>
              <tbody>
                <tr :for={secret <- @secrets}>
                  <td class="font-mono">{secret.secret_path || "Unknown"}</td><td :for={
                    {key, _} <- @count_labels
                  }>
                    {secret[key]}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </.dm_card>
        <.dm_card id="audit-reasons">
          <:title>Outcome reasons</:title>
          <p class="text-sm text-on-surface-variant">
            Final observed request reasons, at most 100 groups.
          </p>
          <dl>
            <div :for={reason <- @reasons} class="flex justify-between gap-4">
              <dt>{reason.reason_code || "Unknown"}</dt><dd>{reason.count}</dd>
            </div>
          </dl>
        </.dm_card>
      </div>

      <.dm_card :if={@summary} id="audit-trends">
        <:title>Hourly request trend (UTC)</:title>
        <div class="overflow-x-auto max-h-80">
          <table class="table w-full">
            <caption class="sr-only">Persisted hourly request counts</caption>
            <thead>
              <tr>
                <th scope="col">Hour</th><th :for={{_, label} <- @count_labels} scope="col">
                  {label}
                </th>
              </tr>
            </thead>
            <tbody>
              <tr :for={bucket <- @buckets}>
                <th scope="row">{timestamp(bucket.at)}</th><td :for={{key, _} <- @count_labels}>
                  {bucket[key]}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </.dm_card>

      <.dm_card :if={@summary} id="audit-requests">
        <:title>Recent requests</:title>
        <div class="overflow-x-auto">
          <table class="table w-full">
            <caption class="sr-only">Recent logical requests in the selected window</caption>
            <thead>
              <tr>
                <th scope="col">Started (UTC)</th><th scope="col">Request / Agent</th><th scope="col">
                  Application provenance
                </th><th scope="col">Secret</th><th scope="col">Outcome / reason</th><th scope="col">
                  Attempts / cache
                </th>
              </tr>
            </thead>
            <tbody>
              <tr :for={request <- @requests}>
                <td>{timestamp(request.started_at)}</td>
                <td>
                  <.link patch={request_url(@filters, request)} class="link font-mono">{request.request_id}</.link><div>
                    {request.agent_id || "Direct Core request"}
                  </div>
                </td>
                <td>
                  <div class="font-mono">{request.application_id || "Unattributed"}</div>{identity_label(
                    request.attribution
                  )}
                  <div :if={request.identity_status == "unverified"}>Unverified identity</div>
                </td>
                <td class="font-mono">{request.secret_path || "Unknown"}</td>
                <td>
                  {request.outcome} / {request.reason_code}
                  <div :if={request.incomplete}>Incomplete evidence</div><strong :if={
                    request.contradictory
                  }>Contradictory observations</strong><div>
                    Core: {request.core_outcome || "No observation"} / {Map.get(
                      request,
                      :core_reason_code
                    ) || "Unknown reason"}; response: {request.delivery_outcome ||
                      "No observation"}
                  </div>
                </td>
                <td>{request.attempts} / {request.cache_status}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <nav aria-label="Request pagination" class="flex gap-4">
          <.link
            :if={@filters["cursor"]}
            patch={audit_url(Map.delete(@filters, "cursor"))}
            class="link"
          >Newest requests</.link>
          <.link
            :if={@next_cursor}
            patch={audit_url(Map.put(@filters, "cursor", @next_cursor))}
            class="link"
          >Next requests</.link>
        </nav>
      </.dm_card>

      <.dm_card :if={@selected_request} id="audit-timeline">
        <:title>Request timeline</:title>
        <.link patch={audit_url(@filters)} class="link">Close timeline</.link>
        <p class="font-mono break-all">{@selected_namespace} / {@selected_request}</p>
        <p class="text-sm text-on-surface-variant">
          Observation clocks may differ. Received by Core is recorded independently. Admission, attempts and response observations remain separate; missing send evidence leaves delivery ambiguous. At most 1000 observations.
        </p>
        <p :if={@timeline_error == :raw_expired} role="status">
          Raw timeline expired under retention; the aggregate may remain. Signed chain checkpoints and replay tombstones are retained.
        </p>
        <p :if={@timeline_error && @timeline_error != :raw_expired} role="alert">
          Timeline unavailable: {error_message(@timeline_error)}
        </p>
        <p :if={!@timeline_error and @timeline == []}>
          No retained observations for this request and namespace.
        </p>
        <ol class="space-y-4">
          <li :for={observation <- @timeline} class="border-l border-outline-variant pl-4">
            <strong>{observation.envelope["source"]} / {observation.envelope["phase"]}</strong>
            <div>
              {identity_label(observation.envelope["attribution"])}; identity: {observation.envelope[
                "identity_status"
              ]}
            </div>
            <div class="font-mono break-all">
              Agent: {observation.envelope["agent_id"] || "None"}; application: {observation.envelope[
                "application_id"
              ] || "Unattributed"}; secret: {observation.envelope["secret_path"] || "Unknown"}
            </div>
            <div>
              Outcome: {observation.envelope["outcome"]}; reason: {observation.envelope["reason_code"]}; cache: {observation.envelope[
                "cache_status"
              ]}
            </div>
            <div>
              Observed: {timestamp(observation.observed_at)}; Received by Core: {timestamp(
                observation.received_at
              )}
            </div>
            <div class="font-mono break-all">
              Event: {observation.event_id}; attempt: {observation.envelope["attempt_id"] || "None"}; producer sequence: {observation.producer_sequence}
            </div>
          </li>
        </ol>
      </.dm_card>

      <.dm_card id="audit-health">
        <:title>Audit pipeline health</:title>
        <p :if={@health_error} role="alert">Reporting health unavailable. Completeness is unknown.</p>
        <div :if={@health}>
          <p>
            Retained evidence only. Automatic retention deletion is disabled. Health lists at most 100 producers and 100 Agent reports.
          </p>
          <p :if={Map.has_key?(@health, :retention_policy)}>
            Raw detail target: {@health.retention_policy.raw_days} days; aggregate target: {@health.retention_policy.aggregate_days} days.
            Manual pruning enabled: {if @health.retention_policy.enabled, do: "yes", else: "no"}. No automatic scheduler runs.
          </p>
          <p :if={@health.pending_unknown} role="status">
            Pending backlog is unknown for some Agents. Missing, stale or legacy reports mean coverage may be partial.
          </p>
          <p :if={Map.get(@health, :coverage_limited, false)} role="status">
            Health coverage is limited to the most recent 100 Agents, producers and reports. Other pipeline state is unknown.
          </p>
          <p :if={Map.get(@health, :unknown_agents, []) != []}>
            Agents without a current report: {Enum.join(Map.get(@health, :unknown_agents, []), ", ")}
          </p>
          <ul class="space-y-4">
            <li :for={producer <- @health.producers}>
              <span class="font-mono break-all">{producer.namespace} / {producer.producer_id}</span>
              <strong :if={producer.stale}>Stale / disconnected</strong>
              <div>
                Sequence gaps: {producer.gaps}; last sequence: {producer.last_sequence}; received events: {producer.event_count}
              </div>
              <div>
                Last report received: {timestamp(producer.last_received_at)}; last producer observation: {timestamp(
                  producer.last_observed_at
                )}
              </div>
            </li>
          </ul>
          <ul class="space-y-4 mt-4">
            <li :for={report <- @health.reports}>
              <strong>{report.agent_id}: {report.status["journal_status"]}</strong>
              <div>Agent connection status: {Map.get(report, :agent_status) || "unknown"}</div>
              <strong :if={report.stale}>Stale / disconnected</strong>
              <div>
                Pending events: {report.status["pending_events"]}; pending bytes: {report.status[
                  "pending_bytes"
                ]}; Quarantined: {report.status["quarantined_events"]}
              </div>
              <div>
                Reported oldest pending age: {report.oldest_pending_age_ms || "unknown"} ms; received: {timestamp(
                  report.received_at
                )}
              </div>
              <p :if={report.stale}>Backlog values are stale; current pending work is unknown.</p>
            </li>
          </ul>
        </div>
      </.dm_card>

      <.dm_card id="audit-legacy">
        <:title>Legacy / partial coverage</:title>
        <p>
          Latest 50 legacy audit records across history, independently of the request filters. These records do not establish application identity, request totals, cache outcomes or delivery. Arbitrary event payloads are excluded.
        </p>
        <p :if={@legacy_error} role="alert">Legacy records unavailable.</p>
        <p :if={!@legacy_error and @legacy == []}>No retained legacy records.</p>
        <ul>
          <li :for={record <- @legacy}>
            {timestamp(record.timestamp)} · {record.event_type} · {record.actor_type}: {record.actor_id} · resource: {record.secret_id ||
              "Unknown"} · access granted: {legacy_outcome(record.access_granted)}
          </li>
        </ul>
      </.dm_card>
    </div>
    """
  end

  defp load(socket) do
    filters = socket.assigns.filters

    socket =
      case query_data(filters) do
        {:ok, data} ->
          socket |> assign(data) |> assign(:query_error, nil)

        {:error, reason} ->
          assign(socket,
            summary: nil,
            requests: [],
            applications: [],
            secrets: [],
            reasons: [],
            buckets: [],
            next_cursor: nil,
            query_error: reason
          )
      end

    socket
    |> load_health()
    |> load_legacy()
    |> load_timeline()
    |> assign(loaded: true, refreshed_at: DateTime.utc_now())
  end

  defp load_health(socket) do
    case AccessAudit.health() do
      {:ok, health} -> assign(socket, health: health, health_error: nil)
      {:error, reason} -> assign(socket, health: nil, health_error: reason)
    end
  end

  defp load_legacy(socket) do
    case legacy_records() do
      {:ok, legacy} -> assign(socket, legacy: legacy, legacy_error: nil)
      {:error, reason} -> assign(socket, legacy: [], legacy_error: reason)
    end
  end

  defp load_timeline(%{assigns: %{selected_request: nil}} = socket),
    do: assign(socket, timeline: [], timeline_error: nil)

  defp load_timeline(socket) do
    case AccessAudit.timeline(socket.assigns.selected_namespace, socket.assigns.selected_request) do
      {:ok, timeline} -> assign(socket, timeline: timeline, timeline_error: nil)
      {:error, reason} -> assign(socket, timeline: [], timeline_error: reason)
    end
  end

  defp query_data(filters) do
    totals_filters = Map.delete(filters, "cursor")

    with {:ok, page} <- AccessAudit.requests(filters),
         {:ok, summary} <- AccessAudit.summary(totals_filters),
         {:ok, applications} <-
           AccessAudit.applications(Map.delete(totals_filters, "application_id")),
         {:ok, secrets} <- AccessAudit.secrets(totals_filters),
         {:ok, reasons} <- AccessAudit.reasons(totals_filters),
         {:ok, buckets} <- AccessAudit.time_buckets(totals_filters) do
      {:ok,
       %{
         requests: page.entries,
         next_cursor: page.next_cursor,
         summary: summary,
         applications: applications,
         secrets: secrets,
         reasons: reasons,
         buckets: buckets
       }}
    end
  end

  defp legacy_records do
    {:ok,
     Repo.all(
       from(a in AuditLog,
         where: a.event_type not in ["access.observed", "access.retention_checkpoint"],
         order_by: [desc: a.timestamp, desc: a.id],
         limit: 50,
         select: %{
           id: a.id,
           timestamp: a.timestamp,
           event_type: a.event_type,
           actor_type: a.actor_type,
           actor_id: a.actor_id,
           secret_id: a.secret_id,
           access_granted: a.access_granted
         }
       )
     )}
  rescue
    _ in [Postgrex.Error, DBConnection.ConnectionError] -> {:error, :storage_unavailable}
  catch
    :exit, _ -> {:error, :storage_unavailable}
  end

  defp filters(params) do
    params = params |> Map.take(@filter_keys) |> nonempty()
    now = DateTime.utc_now()
    to = Map.get(params, "to", DateTime.to_iso8601(now))

    from =
      case DateTime.from_iso8601(if(is_binary(to), do: to, else: "")) do
        {:ok, date, _} -> DateTime.to_iso8601(DateTime.add(date, -86_400))
        _ -> DateTime.to_iso8601(DateTime.add(now, -86_400))
      end

    params |> Map.put_new("to", to) |> Map.put_new("from", from) |> Map.put_new("limit", "50")
  end

  defp nonempty(params), do: Map.reject(params, fn {_key, value} -> value in [nil, ""] end)

  defp audit_url(filters),
    do:
      "/admin/audit?" <>
        URI.encode_query(Map.filter(filters, fn {_, value} -> is_binary(value) end))

  defp request_url(filters, request),
    do:
      "/admin/audit/#{request.request_id}?" <>
        URI.encode_query(Map.put(filters, "namespace", request.namespace))

  defp identity_label("core_certificate"),
    do: "Independently Core-verified application certificate"

  defp identity_label("agent_certificate"), do: "Agent-attested application certificate"
  defp identity_label("token"), do: "Token identity; no verified application"
  defp identity_label(_), do: "Unverified / unattributed"
  defp timestamp(nil), do: "Unknown"
  defp timestamp(%DateTime{} = datetime), do: DateTime.to_iso8601(datetime)
  defp timestamp(%NaiveDateTime{} = datetime), do: NaiveDateTime.to_iso8601(datetime) <> "Z"
  defp text_or_nil(value) when is_binary(value), do: value
  defp text_or_nil(_), do: nil
  defp legacy_outcome(true), do: "yes (legacy observation)"
  defp legacy_outcome(false), do: "no (legacy observation)"
  defp legacy_outcome(_), do: "unknown"

  defp error_message(reason) when reason in [:invalid_filter, :invalid_cursor],
    do: "Check the filters, time window and pagination cursor."

  defp error_message(_), do: "The persisted audit source could not be read."
end
