defmodule SecretHub.Core.AccessAudit.Source do
  @moduledoc false
  alias SecretHub.Core.AccessAudit.Observation
  alias SecretHub.Core.Audit
  alias SecretHub.Shared.AccessAudit.Event
  alias SecretHub.Shared.Schemas.AuditLog

  def valid?(%Observation{} = observation, %AuditLog{} = log) do
    envelope = observation.envelope

    evidence = %{
      "namespace" => observation.namespace,
      "received_at" => DateTime.to_iso8601(observation.received_at),
      "envelope" => envelope
    }

    with {:ok, normalized} <- Event.validate(envelope),
         true <- normalized == envelope,
         true <- observation.canonical == Event.canonical(envelope),
         true <- observation.namespace == namespace(envelope),
         true <- observation.event_id == envelope["event_id"],
         true <- observation.producer_id == envelope["producer_id"],
         true <- observation.producer_sequence == envelope["producer_sequence"],
         true <- observation.request_id == envelope["request_id"],
         {:ok, observed_at, _} <- DateTime.from_iso8601(envelope["observed_at"]),
         true <- DateTime.compare(observation.observed_at, observed_at) == :eq,
         true <- observation.audit_log_id == log.id,
         true <- observation.audit_log_timestamp == log.timestamp,
         true <- log.correlation_id == observation.request_id,
         true <- log.event_data == %{"access_audit" => evidence},
         :ok <- Audit.verify_retention_entry(log) do
      true
    else
      _ -> false
    end
  end

  def valid?(_, _), do: false

  defp namespace(%{"agent_id" => agent}) when is_binary(agent), do: "agent:" <> agent
  defp namespace(_), do: "core"
end
