defmodule SecretHub.Human.LeaseMonitor do
  alias SecretHub.Human.Accounts
  alias SecretHub.Human.Metrics

  @moduledoc "Human-owned periodic job invoking only public Core cleanup operations. Carries no credentials."
  use Styx.Worker, queue: :human_audit, max_attempts: 5
  @impl Styx.Worker
  def perform(%Styx.Job{}) do
    Accounts.cleanup_refresh_evidence()
    Metrics.emit()

    {:ok, _} = SecretHub.Access.cleanup_expired()
    :ok
  end
end
