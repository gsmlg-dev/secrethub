defmodule SecretHub.Core.AccessAudit do
  @moduledoc """
  Checked, idempotent access observations and transactional request projections.

  Every returned acknowledgement follows the enclosing database commit. Application
  attribution from Agents remains explicitly Agent-attested. A Core grant alone
  never counts as delivery. Retention requires explicit manual opt-in; minimal
  signed checkpoints and replay tombstones survive expiration.
  """
  import Ecto.Query
  alias SecretHub.Core.AccessAudit.{Observation, Producer, Queries, Rebuild, Request, Retention}
  alias SecretHub.Core.{Agents, Audit, Repo}
  alias SecretHub.Shared.AccessAudit.Event

  @core_producer "00000000-0000-4000-8000-000000000001"
  @lock "secrethub:access-audit:v1"
  @max_request_observations 1000

  defdelegate requests(filters \\ %{}), to: Queries
  defdelegate summary(filters \\ %{}), to: Queries
  defdelegate applications(filters \\ %{}), to: Queries
  defdelegate secrets(filters \\ %{}), to: Queries
  defdelegate reasons(filters \\ %{}), to: Queries
  defdelegate time_buckets(filters \\ %{}), to: Queries
  defdelegate timeline(namespace, request_id), to: Retention
  defdelegate health(), to: Queries

  @doc "Finite retention targets, disabled by default. No automatic scheduler."
  defdelegate retention_policy(opts \\ []), to: Retention, as: :policy
  defdelegate prune(opts \\ []), to: Retention

  @doc "Rebuild one retained request projection from its immutable observations."
  defdelegate rebuild_request(namespace, request_id), to: Rebuild

  @doc "Validate and atomically ingest an authenticated Agent's bounded batch."
  def ingest(identity, events, health \\ nil)

  def ingest(%{agent_id: agent_id, certificate_id: certificate_id}, events, health)
      when is_binary(agent_id) and byte_size(agent_id) in 1..128 and is_binary(certificate_id) do
    with :ok <- Agents.authorize_runtime(agent_id, certificate_id),
         {:ok, status} <- validate_health(health),
         {:ok, normalized} <- validate_batch(events, agent_id, status) do
      safe_transaction(fn -> ingest_locked!(agent_id, certificate_id, normalized, status) end)
    else
      {:error, _} = error -> error
    end
  rescue
    _ in [Postgrex.Error, DBConnection.ConnectionError] -> {:error, :storage_unavailable}
  catch
    :exit, _ -> {:error, :storage_unavailable}
  end

  def ingest(_, _, _), do: {:error, :unauthorized}

  def record_health(identity, status), do: ingest(identity, [], status)

  defp ingest_locked!(agent_id, certificate_id, events, status) do
    lock!()
    # A batch queued before revocation must recheck after acquiring the lock.
    case Agents.authorize_runtime(agent_id, certificate_id) do
      :ok -> :ok
      {:error, _} -> Repo.rollback(:unauthorized)
    end

    {accepted, duplicates} =
      Enum.reduce(events, {[], []}, &ingest_event!(&1, &2, namespace(agent_id)))

    if status do
      Repo.insert_all(
        "access_audit_agent_health",
        [%{agent_id: agent_id, status: status, received_at: DateTime.utc_now()}],
        on_conflict: {:replace, [:status, :received_at]},
        conflict_target: [:agent_id]
      )
    end

    %{accepted: Enum.reverse(accepted), duplicates: Enum.reverse(duplicates)}
  end

  defp ingest_event!(event, {accepted, duplicates}, ns) do
    case persist!(ns, event) do
      {:inserted, _} -> {[event["event_id"] | accepted], duplicates}
      {:duplicate, _} -> {accepted, [event["event_id"] | duplicates]}
    end
  end

  @doc "Record a trusted server observation with generated identity and a locked persistent sequence."
  def record_core(attrs) when is_map(attrs) do
    safe_transaction(fn ->
      lock!()
      attrs = string_keys!(attrs)
      ns = namespace(attrs["agent_id"])
      producer = Repo.get_by(Producer, namespace: ns, producer_id: @core_producer)

      event =
        attrs
        |> Map.put("source", "core")
        |> Map.put("producer_id", @core_producer)
        |> Map.put("producer_sequence", if(producer, do: producer.last_sequence + 1, else: 1))
        |> Map.put_new("schema_version", 1)
        |> default("event_id", Ecto.UUID.generate())
        |> default("request_id", Ecto.UUID.generate())
        |> default("attempt_id", Ecto.UUID.generate())
        |> default("observed_at", DateTime.to_iso8601(DateTime.utc_now()))
        |> Map.put_new("phase", "core_decision")
        |> Map.put_new("identity_status", "unverified")
        |> Map.put_new("attribution", "none")
        |> Map.put_new("operation", "read")
        |> Map.put_new("outcome", "error")
        |> Map.put_new("reason_code", "internal_error")
        |> Map.put_new("cache_status", "none")

      case Event.validate(event, source: "core") do
        {:ok, normalized} ->
          {_, record} = persist!(ns, normalized)
          record

        {:error, reason} ->
          Repo.rollback(reason)
      end
    end)
  end

  def record_core(_), do: {:error, :invalid_event}

  defp validate_batch([], _, health) when is_map(health), do: {:ok, []}

  defp validate_batch(events, agent_id, _) when is_list(events) and length(events) in 1..100 do
    if byte_size(Jason.encode!(events)) > 131_072 do
      {:error, :batch_too_large}
    else
      validate_events(events, agent_id)
    end
  rescue
    _ in [Protocol.UndefinedError, Jason.EncodeError] -> {:error, :invalid_batch}
  end

  defp validate_batch(_, _, _), do: {:error, :invalid_batch}

  defp validate_events(events, agent_id) do
    Enum.reduce_while(events, {:ok, []}, fn event, {:ok, acc} ->
      case bind_event(event, agent_id) do
        {:ok, bound} -> {:cont, {:ok, [bound | acc]}}
        {:error, _} = error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, events} -> {:ok, Enum.reverse(events)}
      error -> error
    end
  end

  defp bind_event(event, agent_id) do
    with {:ok, normalized} <- Event.validate(event, source: "agent"),
         true <- normalized["producer_id"] != @core_producer,
         true <- normalized["agent_id"] in [nil, agent_id] do
      Event.validate(Map.put(normalized, "agent_id", agent_id), source: "agent")
    else
      false -> {:error, :invalid_provenance}
      {:error, _} = error -> error
    end
  end

  defp validate_health(nil), do: {:ok, nil}

  defp validate_health(status) when is_map(status) do
    keys = ~w(pending_events pending_bytes quarantined_events oldest_pending_at journal_status)
    numeric = ~w(pending_events pending_bytes quarantined_events)

    optional = ~w(oldest_pending_age_ms)

    if Enum.all?(keys, &Map.has_key?(status, &1)) and
         Enum.all?(Map.keys(status), &(&1 in (keys ++ optional))) and
         health_time?(status["oldest_pending_at"]) and
         health_optional_number?(status["oldest_pending_age_ms"]) and
         Enum.all?(numeric, &health_number?(status[&1])) and
         status["journal_status"] in ~w(healthy audit_unavailable journal_full journal_corrupt quarantined unsupported) do
      {:ok, status}
    else
      {:error, :invalid_health}
    end
  end

  defp validate_health(_), do: {:error, :invalid_health}

  defp health_time?(nil), do: true

  defp health_time?(time) when is_binary(time) and byte_size(time) <= 40,
    do: match?({:ok, _, _}, DateTime.from_iso8601(time))

  defp health_time?(_), do: false
  defp health_optional_number?(nil), do: true
  defp health_optional_number?(value), do: health_number?(value)
  defp health_number?(value), do: is_integer(value) and value in 0..9_007_199_254_740_991

  defp persist!(ns, event) do
    canonical = Event.canonical(event)

    case Retention.check_event(ns, event, canonical) do
      {:duplicate, tombstone} -> {:duplicate, tombstone}
      {:error, reason} -> Repo.rollback(reason)
      :new -> persist_live!(ns, event, canonical)
    end
  end

  defp persist_live!(ns, event, canonical) do
    existing =
      Repo.get_by(Observation,
        namespace: ns,
        producer_id: event["producer_id"],
        event_id: event["event_id"]
      )

    cond do
      existing && existing.canonical == canonical ->
        {:duplicate, existing}

      existing ->
        Repo.rollback(:event_conflict)

      Repo.get_by(Observation,
        namespace: ns,
        producer_id: event["producer_id"],
        producer_sequence: event["producer_sequence"]
      ) ->
        Repo.rollback(:sequence_conflict)

      true ->
        insert!(ns, event, canonical)
    end
  end

  defp insert!(ns, event, canonical) do
    count =
      Repo.aggregate(
        from(e in Observation,
          where: e.namespace == ^ns and e.request_id == ^event["request_id"],
          limit: @max_request_observations
        ),
        :count
      )

    if count >= @max_request_observations, do: Repo.rollback(:request_limit_exceeded)
    received_at = DateTime.utc_now()

    evidence = %{
      "namespace" => ns,
      "received_at" => DateTime.to_iso8601(received_at),
      "envelope" => event
    }

    audit =
      case Audit.log_event(%{
             event_type: "access.observed",
             hash_version: 2,
             actor_type: event["source"],
             actor_id: event["agent_id"] || "core",
             secret_id: event["secret_id"],
             access_granted: event["outcome"] == "success",
             correlation_id: event["request_id"],
             event_data: %{"access_audit" => evidence}
           }) do
        {:ok, log} -> log
        {:error, _} -> Repo.rollback(:audit_unavailable)
      end

    {:ok, observed_at, _} = DateTime.from_iso8601(event["observed_at"])

    observation =
      Repo.insert!(%Observation{
        namespace: ns,
        event_id: event["event_id"],
        producer_id: event["producer_id"],
        producer_sequence: event["producer_sequence"],
        request_id: event["request_id"],
        envelope: event,
        canonical: canonical,
        observed_at: observed_at,
        received_at: received_at,
        audit_log_id: audit.id,
        audit_log_timestamp: audit.timestamp
      })

    update_producer!(observation)
    project!(ns, event["request_id"])
    {:inserted, observation}
  end

  defp update_producer!(observation) do
    attrs = %{
      namespace: observation.namespace,
      producer_id: observation.producer_id,
      last_sequence: observation.producer_sequence,
      event_count: 1,
      last_received_at: observation.received_at,
      last_observed_at: observation.observed_at
    }

    query =
      from(p in Producer,
        update: [
          set: [
            last_sequence: fragment("GREATEST(?, EXCLUDED.last_sequence)", p.last_sequence),
            last_observed_at:
              fragment("GREATEST(?, EXCLUDED.last_observed_at)", p.last_observed_at),
            last_received_at: ^observation.received_at
          ],
          inc: [event_count: 1]
        ]
      )

    Repo.insert_all(Producer, [attrs],
      on_conflict: query,
      conflict_target: [:namespace, :producer_id]
    )
  end

  @doc false
  def project_retained!(ns, request_id), do: project!(ns, request_id)

  defp project!(ns, request_id) do
    observations =
      Repo.all(
        from(e in Observation,
          where: e.namespace == ^ns and e.request_id == ^request_id,
          order_by: [asc: e.observed_at, asc: e.producer_sequence, asc: e.event_id],
          limit: @max_request_observations
        )
      )

    attrs = projection_attrs(ns, request_id, observations)

    Repo.insert_all(Request, [attrs],
      on_conflict: {:replace_all_except, [:id]},
      conflict_target: [:namespace, :request_id]
    )
  end

  defp projection_attrs(ns, request_id, observations) do
    events = Enum.map(observations, & &1.envelope)
    core = core_decision(events)
    delivery = delivery_observation(events)
    identity = request_identity(events)
    resource = request_resource(events)
    incomplete = is_nil(delivery) or delivery["outcome"] == "unknown"
    outcome = if incomplete, do: "incomplete", else: delivery["outcome"]

    %{
      namespace: ns,
      request_id: request_id,
      agent_id: identity["agent_id"],
      application_id:
        if(identity["identity_status"] == "verified", do: identity["application_id"]),
      identity_status: identity["identity_status"],
      attribution: identity["attribution"],
      secret_id: resource["secret_id"],
      secret_path: resource["secret_path"],
      operation: resource["operation"],
      started_at: hd(observations).observed_at,
      last_observed_at: List.last(observations).observed_at,
      last_received_at:
        Enum.max_by(observations, &DateTime.to_unix(&1.received_at, :microsecond)).received_at,
      outcome: outcome,
      reason_code: request_reason(delivery, core, events),
      attempts: request_attempts(events),
      incomplete: incomplete,
      contradictory: contradictory?(events, delivery, outcome),
      core_outcome: field_or_nil(core, "outcome"),
      core_reason_code: field_or_nil(core, "reason_code"),
      delivery_outcome: field_or_nil(delivery, "outcome"),
      cache_status: cache_status(delivery, events)
    }
  end

  defp core_decision(events) do
    events
    |> Enum.filter(&(&1["source"] == "core" and &1["phase"] in ["core_decision", "core_access"]))
    |> Enum.max_by(&{&1["producer_sequence"], &1["event_id"]}, fn -> nil end)
  end

  defp delivery_observation(events) do
    events
    |> Enum.filter(&(&1["phase"] in ["response_sent", "response_failed", "rejected"]))
    |> Enum.max_by(
      &{if(&1["source"] == "agent", do: 1, else: 0), &1["producer_sequence"], &1["event_id"]},
      fn -> nil end
    )
  end

  defp request_identity(events) do
    Enum.find(
      events,
      &(&1["attribution"] == "core_certificate" and &1["identity_status"] == "verified")
    ) ||
      Enum.find(
        events,
        &(&1["attribution"] == "agent_certificate" and &1["identity_status"] == "verified")
      ) ||
      hd(events)
  end

  defp request_resource(events) do
    Enum.find(events, &(&1["source"] == "core" and not is_nil(&1["secret_path"]))) ||
      Enum.find(events, &(not is_nil(&1["secret_path"]))) || hd(events)
  end

  defp request_attempts(events) do
    events
    |> Enum.filter(&(&1["phase"] in ["attempt", "core_decision", "core_access"]))
    |> Enum.map(& &1["attempt_id"])
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()
    |> length()
  end

  defp contradictory?(events, delivery, outcome) do
    denied_same_attempt?(events, delivery, outcome) or
      conflicting_field?(events, "application_id") or
      conflicting_field?(events, "secret_id") or
      conflicting_field?(events, "secret_path") or
      conflicting_field?(Enum.filter(events, &(&1["source"] == "agent")), "producer_id")
  end

  defp denied_same_attempt?(_, nil, _), do: false
  defp denied_same_attempt?(_events, _delivery, outcome) when outcome != "success", do: false

  defp denied_same_attempt?(events, delivery, "success") do
    Enum.any?(
      events,
      &(&1["source"] == "core" and &1["outcome"] == "denied" and
          &1["attempt_id"] == delivery["attempt_id"])
    )
  end

  defp conflicting_field?(events, key) do
    events |> Enum.map(& &1[key]) |> Enum.reject(&is_nil/1) |> Enum.uniq() |> length() > 1
  end

  defp request_reason(delivery, core, events),
    do: (delivery || core || List.last(events))["reason_code"]

  defp cache_status(delivery, events), do: (delivery || List.last(events))["cache_status"]
  defp field_or_nil(nil, _), do: nil
  defp field_or_nil(event, key), do: event[key]

  defp namespace(nil), do: "core"
  defp namespace(agent_id) when is_binary(agent_id), do: "agent:" <> agent_id
  defp namespace(_), do: Repo.rollback(:invalid_event)

  defp lock!,
    do: Repo.query!("SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))", [@lock])

  defp default(map, key, value), do: if(is_nil(map[key]), do: Map.put(map, key, value), else: map)

  defp string_keys!(attrs) do
    Enum.reduce(attrs, %{}, fn {key, value}, acc ->
      key = if is_atom(key), do: Atom.to_string(key), else: key
      if Map.has_key?(acc, key), do: Repo.rollback(:invalid_event)

      value =
        if is_atom(value) and value not in [nil, true, false],
          do: Atom.to_string(value),
          else: value

      Map.put(acc, key, value)
    end)
  end

  defp safe_transaction(fun) do
    Repo.transaction(fun)
  rescue
    _ in [Postgrex.Error, DBConnection.ConnectionError, Ecto.ConstraintError] ->
      {:error, :storage_unavailable}
  catch
    :exit, _ -> {:error, :storage_unavailable}
  end
end
