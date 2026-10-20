defmodule SecretHub.Core.AccessAudit.Rebuild do
  @moduledoc "Bounded reconstruction of one request from complete, signed retained observations."
  import Ecto.Query
  alias SecretHub.Core.{AccessAudit, Repo}
  alias SecretHub.Core.AccessAudit.{Request, Retention, Source}
  alias SecretHub.Shared.Schemas.AuditLog

  @lock "secrethub:access-audit:v1"

  def rebuild_request(namespace, request_id)
      when is_binary(namespace) and byte_size(namespace) in 1..300 do
    case Ecto.UUID.cast(request_id) do
      {:ok, request_id} -> Repo.transaction(fn -> rebuild_locked(namespace, request_id) end)
      _ -> {:error, :invalid_filter}
    end
  rescue
    _ in [Postgrex.Error, DBConnection.ConnectionError, Ecto.ConstraintError] ->
      {:error, :storage_unavailable}
  catch
    :exit, _ -> {:error, :storage_unavailable}
  end

  def rebuild_request(_, _), do: {:error, :invalid_filter}

  defp rebuild_locked(namespace, request_id) do
    Repo.query!("SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))", [@lock])

    observations =
      case Retention.timeline(namespace, request_id) do
        {:ok, observations} -> observations
        {:error, reason} -> Repo.rollback(reason)
      end

    verify_source!(namespace, request_id, observations)
    AccessAudit.project_retained!(namespace, request_id)
    Repo.get_by!(Request, namespace: namespace, request_id: request_id)
  end

  defp verify_source!(namespace, request_id, observations) do
    logs =
      Repo.all(
        from(a in AuditLog,
          where:
            a.event_type == "access.observed" and
              fragment("? #>> '{access_audit,namespace}'", a.event_data) == ^namespace and
              (a.correlation_id == ^request_id or
                 fragment("? #>> '{access_audit,envelope,request_id}'", a.event_data) ==
                   ^request_id),
          limit: 1001
        )
      )

    if observations == [] and logs == [], do: Repo.rollback(:not_found)
    by_identity = Map.new(logs, &{{&1.id, &1.timestamp}, &1})

    valid =
      length(observations) in 1..1000 and length(logs) == length(observations) and
        Enum.all?(observations, fn observation ->
          log = by_identity[{observation.audit_log_id, observation.audit_log_timestamp}]
          Source.valid?(observation, log)
        end)

    if not valid, do: Repo.rollback(:invalid_source)
  end
end
