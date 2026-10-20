defmodule SecretHub.Core.AccessAudit.Retention do
  @moduledoc """
  Explicit, bounded pruning. Disabled by default; there is no automatic scheduler.
  Raw expiry freezes request reconciliation. Minimal signed chain checkpoints and
  event/sequence/request replay tombstones are preserved indefinitely. Their loss
  requires restoration from a pre-prune backup, not migration rollback.
  """
  import Ecto.Query
  alias SecretHub.Core.AccessAudit.{Observation, Queries, Request, Source}
  alias SecretHub.Core.Audit
  alias SecretHub.Core.Audit.SigningKeys
  alias SecretHub.Core.Repo
  alias SecretHub.Shared.AccessAudit.Checkpoint
  alias SecretHub.Shared.Schemas.AuditLog
  @lock "secrethub:access-audit:v1"
  @events "access_audit_event_tombstones"
  @expired "access_audit_expired_requests"
  @checkpoints "access_audit_chain_checkpoints"

  def policy(opts \\ []) do
    config = Application.get_env(:secrethub_core, :access_audit_retention, [])

    if Keyword.keyword?(config) and Keyword.keyword?(opts) do
      policy =
        Keyword.merge(
          [enabled: false, raw_days: 30, aggregate_days: 365],
          Keyword.merge(config, opts)
        )

      if Enum.sort(Keyword.keys(policy)) == Enum.sort([:enabled, :raw_days, :aggregate_days]) and
           is_boolean(policy[:enabled]) and days?(policy[:raw_days]) and
           days?(policy[:aggregate_days]) and
           policy[:raw_days] <= policy[:aggregate_days] do
        {:ok,
         %{
           enabled: policy[:enabled],
           raw_days: policy[:raw_days],
           aggregate_days: policy[:aggregate_days],
           automatic_deletion: false,
           manual_pruning: true
         }}
      else
        {:error, :invalid_retention_policy}
      end
    else
      {:error, :invalid_retention_policy}
    end
  end

  def prune(opts \\ []) do
    with true <- Keyword.keyword?(opts),
         {limit, policy_opts} = Keyword.pop(opts, :limit, 10),
         true <- is_integer(limit) and limit in 1..10,
         {:ok, policy} <- policy(policy_opts) do
      execute_prune(policy, limit)
    else
      _ -> {:error, :invalid_retention_policy}
    end
  end

  defp execute_prune(%{enabled: false}, _limit), do: {:ok, counts(0, 0)}

  defp execute_prune(policy, limit) do
    transaction(fn ->
      Repo.query!("SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))", [@lock])
      prune_locked(policy, limit)
    end)
  end

  def timeline(namespace, request_id) do
    with true <- is_binary(namespace) and byte_size(namespace) <= 300,
         {:ok, request_id} <- Ecto.UUID.cast(request_id) do
      if expired?(namespace, request_id),
        do: {:error, :raw_expired},
        else: Queries.timeline(namespace, request_id)
    else
      _ -> {:error, :invalid_filter}
    end
  rescue
    _ in [Postgrex.Error, DBConnection.ConnectionError] -> {:error, :storage_unavailable}
  catch
    :exit, _ -> {:error, :storage_unavailable}
  end

  # Called under the same access lock as ingestion and pruning.
  def check_event(namespace, event, canonical) do
    existing =
      Repo.one(
        from(t in tombstone_query(),
          where:
            t.namespace == ^namespace and t.producer_id == type(^event["producer_id"], Ecto.UUID) and
              t.event_id == type(^event["event_id"], Ecto.UUID)
        )
      )

    verify_existing!(existing)
    classify_event(existing, namespace, event, canonical)
  end

  defp classify_event(nil, namespace, event, _canonical) do
    cond do
      sequence_exists?(namespace, event) -> {:error, :sequence_conflict}
      expired?(namespace, event["request_id"]) -> {:error, :outside_retention}
      true -> :new
    end
  end

  defp classify_event(existing, _namespace, _event, canonical) do
    if existing.canonical_digest == digest(canonical),
      do: {:duplicate, existing},
      else: {:error, :event_conflict}
  end

  defp verify_existing!(nil), do: :ok

  defp verify_existing!(existing) do
    checkpoint =
      Repo.one(
        from(c in @checkpoints,
          where: c.sequence_number == ^existing.audit_sequence_number,
          select: c.checkpoint
        )
      )

    unless verify_checkpoint(checkpoint) == :ok and tombstone_matches?(existing, checkpoint),
      do: Repo.rollback(:audit_unavailable)
  end

  def chain_entries(logs) do
    if checkpoint_table?() do
      checkpoints =
        Repo.all(
          from(c in @checkpoints,
            select: %{
              sequence_number: c.sequence_number,
              prune_id: type(c.prune_id, Ecto.UUID),
              checkpoint: c.checkpoint
            }
          )
        )

      with :ok <- verify_checkpoints(checkpoints),
           :ok <- verify_anchors(logs, checkpoints),
           :ok <- verify_tombstones(checkpoints) do
        entries = Enum.map(checkpoints, &checkpoint_entry/1)
        {:ok, Enum.sort_by(logs ++ entries, & &1.sequence_number)}
      end
    else
      {:ok, logs}
    end
  end

  defp checkpoint_entry(row) do
    %{
      sequence_number: row.sequence_number,
      previous_hash: row.checkpoint["previous_hash"],
      current_hash: row.checkpoint["current_hash"],
      retention_checkpoint: row.checkpoint
    }
  end

  def verify_checkpoint(checkpoint) do
    with {:ok, checkpoint} <- Checkpoint.validate(checkpoint),
         {:ok, key} <-
           SigningKeys.verification_key(
             Application.get_all_env(:secrethub_core),
             checkpoint["signing_key_id"],
             checkpoint["signature_version"]
           ),
         true <-
           :crypto.hash_equals(
             checkpoint["signature"],
             hmac(Checkpoint.signature_payload(checkpoint), key)
           ),
         :ok <-
           Audit.verify_retention_signature(%AuditLog{
             event_id: checkpoint["event_id"],
             sequence_number: checkpoint["sequence_number"],
             hash_version: checkpoint["hash_version"],
             current_hash: checkpoint["current_hash"],
             signature: checkpoint["original_signature"],
             signature_version: checkpoint["original_signature_version"],
             signing_key_id: checkpoint["original_signing_key_id"]
           }) do
      :ok
    else
      _ -> {:error, "Invalid retention checkpoint"}
    end
  end

  defp prune_locked(policy, limit) do
    now = DateTime.utc_now()
    raw_before = DateTime.add(now, -policy.raw_days * 86_400)
    aggregate_before = DateTime.add(now, -policy.aggregate_days * 86_400)

    raw_requests =
      Repo.all(
        from(r in Request,
          left_join: e in @expired,
          on: e.namespace == r.namespace and e.request_id == r.request_id,
          where: is_nil(e.request_id) and r.last_received_at < ^raw_before,
          order_by: [asc: r.last_received_at, asc: r.id],
          limit: ^limit
        )
      )

    raw_ids = Enum.map(raw_requests, & &1.id)

    aggregate_ids =
      Repo.all(
        from(r in Request,
          left_join: e in @expired,
          on: e.namespace == r.namespace and e.request_id == r.request_id,
          where:
            r.last_received_at < ^aggregate_before and
              (not is_nil(e.request_id) or r.id in ^raw_ids),
          order_by: [asc: r.last_received_at, asc: r.id],
          limit: ^limit,
          select: r.id
        )
      )

    observations = Enum.flat_map(raw_requests, &observations!/1)

    if observations == [] and aggregate_ids == [] do
      counts(0, 0)
    else
      expire!(raw_requests, observations, aggregate_ids, now, raw_before, aggregate_before)
    end
  end

  defp observations!(request) do
    observations =
      Repo.all(
        from(o in Observation,
          where: o.namespace == ^request.namespace and o.request_id == ^request.request_id,
          limit: 1001
        )
      )

    if length(observations) not in 1..1000, do: Repo.rollback(:inconsistent_retention_source)
    observations
  end

  defp expire!(requests, observations, aggregate_ids, now, raw_before, aggregate_before) do
    prune_id = Ecto.UUID.generate()
    ids = Enum.map(observations, & &1.id)

    logs =
      Repo.all(
        from(a in AuditLog,
          join: o in Observation,
          on:
            o.audit_log_id == a.id and
              fragment("? AT TIME ZONE 'UTC'", o.audit_log_timestamp) == a.timestamp,
          where: o.id in ^ids,
          select: a
        )
      )

    if length(logs) != length(observations), do: Repo.rollback(:inconsistent_retention_source)
    {:ok, key} = signing_key!()
    observations_by_log = Map.new(observations, &{{&1.audit_log_id, &1.audit_log_timestamp}, &1})
    logs_by_id = Map.new(logs, &{{&1.id, &1.timestamp}, &1})

    checkpoints =
      Enum.map(
        logs,
        &checkpoint!(&1, Map.fetch!(observations_by_log, {&1.id, &1.timestamp}), prune_id, key)
      )

    marker = %{
      "access_retention" => %{
        "schema_version" => 1,
        "prune_id" => prune_id,
        "raw_before" => DateTime.to_iso8601(raw_before),
        "aggregate_before" => DateTime.to_iso8601(aggregate_before),
        "observations" => length(observations),
        "requests" => length(aggregate_ids),
        "checkpoint_digest" => checkpoint_digest(checkpoints)
      }
    }

    case Audit.log_event(%{
           event_type: "access.retention_checkpoint",
           hash_version: 2,
           actor_type: "system",
           actor_id: "access_audit_retention",
           event_data: marker
         }) do
      {:ok, _} -> :ok
      {:error, _} -> Repo.rollback(:audit_unavailable)
    end

    insert_chunks(
      @checkpoints,
      Enum.map(
        checkpoints,
        &%{
          sequence_number: &1["sequence_number"],
          prune_id: Ecto.UUID.dump!(prune_id),
          checkpoint: &1
        }
      )
    )

    insert_chunks(
      @events,
      Enum.map(observations, fn o ->
        %{
          namespace: o.namespace,
          producer_id: Ecto.UUID.dump!(o.producer_id),
          event_id: Ecto.UUID.dump!(o.event_id),
          producer_sequence: o.producer_sequence,
          request_id: Ecto.UUID.dump!(o.request_id),
          canonical_digest: digest(o.canonical),
          audit_sequence_number:
            Map.fetch!(logs_by_id, {o.audit_log_id, o.audit_log_timestamp}).sequence_number
        }
      end)
    )

    insert_chunks(
      @expired,
      Enum.map(
        requests,
        &%{namespace: &1.namespace, request_id: Ecto.UUID.dump!(&1.request_id), expired_at: now}
      )
    )

    {deleted, _} =
      Repo.delete_all(
        from(a in AuditLog,
          join: o in Observation,
          on:
            o.audit_log_id == a.id and
              fragment("? AT TIME ZONE 'UTC'", o.audit_log_timestamp) == a.timestamp,
          where: o.id in ^ids and a.event_type == "access.observed"
        )
      )

    if deleted != length(observations), do: Repo.rollback(:inconsistent_retention_source)
    Repo.delete_all(from(o in Observation, where: o.id in ^ids))
    Repo.delete_all(from(r in Request, where: r.id in ^aggregate_ids))
    counts(length(observations), length(aggregate_ids))
  end

  defp checkpoint!(log, observation, prune_id, key) do
    unless Source.valid?(observation, log), do: Repo.rollback(:invalid_retention_source)

    checkpoint = %{
      "schema_version" => 1,
      "prune_id" => prune_id,
      "audit_log_id" => log.id,
      "event_id" => log.event_id,
      "sequence_number" => log.sequence_number,
      "timestamp" => DateTime.to_iso8601(log.timestamp),
      "previous_hash" => log.previous_hash,
      "current_hash" => log.current_hash,
      "hash_version" => log.hash_version,
      "original_signature" => log.signature,
      "original_signature_version" => log.signature_version,
      "original_signing_key_id" => log.signing_key_id,
      "signature_version" => key.version,
      "signing_key_id" => key.id,
      "namespace" => observation.namespace,
      "producer_id" => observation.producer_id,
      "producer_sequence" => observation.producer_sequence,
      "observation_event_id" => observation.event_id,
      "request_id" => observation.request_id,
      "canonical_digest" => digest(observation.canonical)
    }

    checkpoint =
      Map.put(checkpoint, "signature", hmac(Checkpoint.signature_payload(checkpoint), key.secret))

    case Checkpoint.validate(checkpoint) do
      {:ok, checkpoint} -> checkpoint
      {:error, _} -> Repo.rollback(:invalid_checkpoint)
    end
  end

  defp verify_anchors(logs, checkpoints) do
    markers =
      Map.new(Enum.filter(logs, &(&1.event_type == "access.retention_checkpoint")), fn log ->
        data =
          case log.event_data do
            %{"access_retention" => data} when is_map(data) -> data
            _ -> nil
          end

        {data && data["prune_id"], data}
      end)

    groups = Enum.group_by(checkpoints, & &1.prune_id, & &1.checkpoint)

    valid =
      Enum.all?(groups, fn {id, _} -> Map.has_key?(markers, id) end) and
        Enum.all?(markers, fn {id, marker} ->
          group = Map.get(groups, id, [])

          match?({:ok, _}, Checkpoint.validate_marker(%{"access_retention" => marker})) and
            marker["observations"] == length(group) and
            marker["checkpoint_digest"] == checkpoint_digest(group)
        end)

    if valid, do: :ok, else: {:error, "Retention checkpoint anchor mismatch"}
  end

  defp verify_checkpoints(checkpoints) do
    Enum.reduce_while(checkpoints, :ok, fn row, _ ->
      case verify_checkpoint_row(row) do
        :ok -> {:cont, :ok}
        error -> {:halt, error}
      end
    end)
  end

  defp verify_checkpoint_row(row) do
    if row.sequence_number == row.checkpoint["sequence_number"] and
         row.prune_id == row.checkpoint["prune_id"],
       do: verify_checkpoint(row.checkpoint),
       else: {:error, "Invalid retention checkpoint identity"}
  end

  defp checkpoint_digest(checkpoints),
    do:
      checkpoints
      |> Enum.sort_by(& &1["sequence_number"])
      |> Enum.map(&Checkpoint.canonical/1)
      |> Jason.encode!()
      |> digest()

  defp tombstone_query do
    from(t in @events,
      select: %{
        namespace: t.namespace,
        producer_id: type(t.producer_id, Ecto.UUID),
        event_id: type(t.event_id, Ecto.UUID),
        producer_sequence: t.producer_sequence,
        request_id: type(t.request_id, Ecto.UUID),
        canonical_digest: t.canonical_digest,
        audit_sequence_number: t.audit_sequence_number
      }
    )
  end

  defp tombstone_matches?(tombstone, checkpoint) do
    tombstone.namespace == checkpoint["namespace"] and
      tombstone.producer_id == checkpoint["producer_id"] and
      tombstone.event_id == checkpoint["observation_event_id"] and
      tombstone.producer_sequence == checkpoint["producer_sequence"] and
      tombstone.request_id == checkpoint["request_id"] and
      tombstone.canonical_digest == checkpoint["canonical_digest"] and
      tombstone.audit_sequence_number == checkpoint["sequence_number"]
  end

  defp verify_tombstones(checkpoints) do
    tombstones = Repo.all(tombstone_query())
    by_sequence = Map.new(tombstones, &{&1.audit_sequence_number, &1})

    expired =
      Repo.all(from(e in @expired, select: {e.namespace, type(e.request_id, Ecto.UUID)}))
      |> MapSet.new()

    expected = MapSet.new(checkpoints, &{&1.checkpoint["namespace"], &1.checkpoint["request_id"]})

    valid =
      length(tombstones) == length(checkpoints) and expired == expected and
        Enum.all?(checkpoints, fn row ->
          case by_sequence[row.sequence_number] do
            nil -> false
            tombstone -> tombstone_matches?(tombstone, row.checkpoint)
          end
        end)

    if valid, do: :ok, else: {:error, "Retention replay tombstone mismatch"}
  end

  defp digest(content), do: :crypto.hash(:sha256, content) |> Base.encode16(case: :lower)

  defp hmac(content, key),
    do: :crypto.mac(:hmac, :sha256, key, content) |> Base.encode16(case: :lower)

  defp days?(value), do: is_integer(value) and value in 1..36_500

  defp counts(observations, requests),
    do: %{observations: observations, requests: requests, checkpoints: observations}

  defp insert_chunks(table, rows),
    do: rows |> Enum.chunk_every(500) |> Enum.each(&Repo.insert_all(table, &1))

  defp sequence_exists?(namespace, event),
    do:
      Repo.exists?(
        from(t in @events,
          where:
            t.namespace == ^namespace and t.producer_id == type(^event["producer_id"], Ecto.UUID) and
              t.producer_sequence == ^event["producer_sequence"]
        )
      )

  defp expired?(namespace, id),
    do:
      Repo.exists?(
        from(t in @expired,
          where: t.namespace == ^namespace and t.request_id == type(^id, Ecto.UUID)
        )
      )

  defp checkpoint_table?,
    do:
      Repo.query!("SELECT to_regclass('public.access_audit_chain_checkpoints') IS NOT NULL").rows ==
        [[true]]

  defp signing_key! do
    case SigningKeys.active(Application.get_all_env(:secrethub_core)) do
      {:ok, _} = key -> key
      {:error, _} -> Repo.rollback(:audit_unavailable)
    end
  end

  defp transaction(fun) do
    Repo.transaction(fun)
  rescue
    _ in [Postgrex.Error, DBConnection.ConnectionError, Ecto.ConstraintError] ->
      {:error, :storage_unavailable}
  catch
    :exit, _ -> {:error, :storage_unavailable}
  end
end
