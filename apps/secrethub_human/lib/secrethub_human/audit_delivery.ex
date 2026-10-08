defmodule SecretHub.Human.AuditDelivery do
  alias SecretHub.Human.Audit
  @moduledoc "Retries metadata-only outbox delivery without persisting secrets in job arguments."
  use Oban.Worker, queue: :human_audit, max_attempts: 20
  @impl Oban.Worker
  def perform(%Oban.Job{args: %{"event_id" => id}}), do: Audit.deliver(id)
end
