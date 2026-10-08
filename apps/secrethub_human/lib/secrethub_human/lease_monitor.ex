defmodule SecretHub.Human.LeaseMonitor do
  alias SecretHub.Human.Accounts
  alias SecretHub.Human.Metrics

  @moduledoc "Human-owned periodic job invoking only public Core cleanup operations. Carries no credentials."
  use Oban.Worker, queue: :human_audit, max_attempts: 5
  @impl Oban.Worker
  def perform(%Oban.Job{}) do
    Accounts.cleanup_refresh_evidence()
    Metrics.emit()

    case SecretHub.Access.cleanup_expired() do
      {:ok, _} -> :ok
      {:error, _} -> {:error, :core_unavailable}
    end
  end
end
