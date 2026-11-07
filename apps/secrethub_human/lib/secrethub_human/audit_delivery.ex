defmodule SecretHub.Human.AuditDelivery do
  alias SecretHub.Human.Audit
  @moduledoc "Retries metadata-only outbox delivery without persisting secrets in job arguments."
  use Styx.Worker, queue: :human_audit, max_attempts: 20
  @impl Styx.Worker
  def perform(%Styx.Job{args: %{"event_id" => id}}), do: Audit.deliver(id)
end
