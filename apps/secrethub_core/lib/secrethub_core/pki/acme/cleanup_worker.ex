defmodule SecretHub.Core.PKI.ACME.CleanupWorker do
  @moduledoc "Independent cleanup/revocation obligations remain runnable while issuance is disabled."
  use Oban.Worker,
    queue: :acme_cleanup,
    max_attempts: 8,
    unique: [
      period: 60,
      fields: [:worker, :args],
      states: [:available, :scheduled, :executing, :retryable]
    ]

  import Ecto.Query
  alias SecretHub.Core.PKI.ACME.{DNSOperations, Revocation, Worker, Workflow}
  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.DNSChallengeOperation

  @impl true
  def perform(%Oban.Job{args: %{"revoke_version_id" => id}}),
    do: Revocation.run(id, Worker.options())

  def perform(%Oban.Job{args: %{"cleanup_operation_id" => id}}) do
    cleanup(Repo.get(DNSChallengeOperation, id), :operation)
  end

  def perform(%Oban.Job{args: %{"cleanup_order_id" => id}}) do
    Repo.one(
      from(d in DNSChallengeOperation,
        where: d.order_id == ^id and d.cleanup_status != "cleaned",
        order_by: d.inserted_at,
        limit: 1
      )
    )
    |> cleanup(:order)
  end

  defp cleanup(nil, _scope), do: :ok

  defp cleanup(operation, scope) do
    case DNSOperations.cleanup(operation, Worker.options()) do
      {:ok, %{cleanup_status: "cleaned"}} -> if scope == :order, do: {:snooze, 1}, else: :ok
      {:ok, _} -> {:snooze, 15}
      {:error, reason} -> {:error, Workflow.error(reason)}
    end
  end
end
