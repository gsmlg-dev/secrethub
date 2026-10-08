defmodule SecretHub.Access do
  @moduledoc "Public server-to-server boundary for Human operations. Never accepts arbitrary event payloads."
  import Ecto.Query
  alias SecretHub.Core.{Audit, Repo}
  alias SecretHub.Shared.{HumanAuditEvidence, Schemas.AuditLog}

  defdelegate authorize(token, request), to: SecretHub.Core.HumanAccess
  defdelegate list_capabilities(token), to: SecretHub.Core.HumanAccess
  defdelegate issue_dynamic_secret(token, request), to: SecretHub.Core.HumanAccess
  defdelegate read_lease(token, id), to: SecretHub.Core.HumanAccess
  defdelegate list_leases(token), to: SecretHub.Core.HumanAccess
  defdelegate renew_lease(token, request), to: SecretHub.Core.HumanAccess
  defdelegate revoke_lease(token, id), to: SecretHub.Core.HumanAccess
  defdelegate request_approval(token, request), to: SecretHub.Core.HumanAccess
  defdelegate approve_request(token, id), to: SecretHub.Core.HumanAccess
  defdelegate deny_request(token, id), to: SecretHub.Core.HumanAccess
  defdelegate list_approvals(token), to: SecretHub.Core.HumanAccess
  defdelegate process_revocations(), to: SecretHub.Core.HumanAccess, as: :cleanup

  defdelegate revoke_organization_membership(organization_id, subject_id),
    to: SecretHub.Core.HumanAccess

  defdelegate abandon_human_lease(id), to: SecretHub.Core.HumanAccess, as: :abandon_lease

  @doc "Server-only readiness and aggregate operational counts. Contains no principals or credentials."
  def human_health do
    case Repo.query("SELECT 1", [], log: false, timeout: 1000) do
      {:ok, _} ->
        {:ok,
         %{dynamic_enabled: Application.get_env(:secrethub_core, :human_dynamic_enabled, false)}}

      _ ->
        {:error, :core_unavailable}
    end
  rescue
    _ -> {:error, :core_unavailable}
  catch
    :exit, _ -> {:error, :core_unavailable}
  end

  def human_metrics do
    now = DateTime.utc_now()
    alias SecretHub.Core.HumanAccess.{Approval, Lease}

    counts =
      Repo.all(
        from(a in AuditLog,
          where: a.actor_type == "human",
          group_by: a.event_type,
          select: {a.event_type, count(a.id)}
        )
      )
      |> Map.new()

    [[requests]] =
      Repo.query!(
        "SELECT COUNT(*) FROM (SELECT subject_id::text, request_id::text FROM core_human_approvals UNION SELECT subject_id::text, request_id::text FROM core_human_leases UNION SELECT actor_id, event_data->>'request_id' FROM audit_logs WHERE actor_type='human' AND event_type='human.dynamic_secret.denied' AND event_data->>'reason'='unauthorized' AND event_data->>'request_id' IS NOT NULL) AS requests",
        [],
        log: false
      ).rows

    %{
      human_dynamic_requests_total: requests,
      human_dynamic_requests_denied_total: Map.get(counts, "human.dynamic_secret.denied", 0),
      human_reveals_total: Map.get(counts, "human.dynamic_secret.revealed", 0),
      human_reveal_failures_total: Map.get(counts, "human.dynamic_secret.reveal_failed", 0),
      human_active_leases:
        Repo.aggregate(
          from(l in Lease, where: l.status == "active" and l.expires_at > ^now),
          :count
        ),
      human_pending_approvals:
        Repo.aggregate(
          from(a in Approval, where: a.status == "pending" and a.expires_at > ^now),
          :count
        )
    }
  end

  defdelegate cleanup_expired(), to: SecretHub.Core.HumanAccess, as: :cleanup

  @doc "Appends one sanitized Human event. Idempotency survives outbox retries. Not a public HTTP API."
  def record_human_event(event, actor_id, metadata, event_id) do
    with {:ok, data} <- HumanAuditEvidence.validate(event, metadata),
         {:ok, id} <- Ecto.UUID.cast(event_id),
         true <- is_nil(actor_id) or match?({:ok, _}, Ecto.UUID.cast(actor_id)) do
      Repo.transaction(fn -> append_human_event(event, actor_id, data, id) end)
    else
      _ -> {:error, :invalid_evidence}
    end
  end

  defp append_human_event(event, actor_id, data, id) do
    Repo.query!("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [
      "human-audit:" <> id
    ])

    case Repo.one(from(a in AuditLog, where: a.correlation_id == ^id and a.event_type == ^event)) do
      nil ->
        case Audit.log_event(%{
               event_type: event,
               actor_type: "human",
               actor_id: actor_id,
               correlation_id: id,
               hash_version: 2,
               event_data: data
             }) do
          {:ok, entry} -> entry.event_id
          {:error, _} -> Repo.rollback(:audit_unavailable)
        end

      entry ->
        if entry.actor_id == actor_id and entry.event_data == data,
          do: entry.event_id,
          else: Repo.rollback(:event_conflict)
    end
  end
end
