defmodule SecretHub.Core.PKI.ACME.Worker do
  @moduledoc "Durable bounded certificate/account progress on the named Core instance."
  use Oban.Worker,
    queue: :acme,
    max_attempts: 8,
    unique: [
      period: 60,
      fields: [:worker, :args],
      states: [:available, :scheduled, :executing, :retryable]
    ]

  alias Ecto.Changeset
  alias SecretHub.Core.PKI.ACME.{RenewalScheduler, Workflow}
  alias SecretHub.Core.PKI.ManagedCertificates
  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.AcmeAccount

  @impl true
  def perform(%Oban.Job{args: %{"order_id" => id}}), do: Workflow.step(id, options())

  def perform(%Oban.Job{args: %{"renewal_info_id" => id}}) do
    with {:ok, version} <- ManagedCertificates.get_version(id),
         {:ok, _} <- RenewalScheduler.refresh(version, options()),
         do: :ok
  end

  def perform(%Oban.Job{args: %{"account_id" => id}}) do
    case Workflow.register_account(id, options()) do
      {:ok, _} ->
        :ok

      {:error, reason} ->
        error = Workflow.error(reason)
        with {:ok, _} <- record_account_error(id, error), do: registration_failure(reason, error)
    end
  end

  defp record_account_error(id, error) do
    Repo.transaction(fn ->
      current = ManagedCertificates.locked!(AcmeAccount, id)

      if current.status == "valid" and is_binary(current.account_url),
        do: current,
        else: ManagedCertificates.update!(Changeset.change(current, last_error: error))
    end)
  end

  defp registration_failure(reason, _) when reason in [:disabled, :feature_unavailable],
    do: {:cancel, reason}

  defp registration_failure(_, error), do: {:error, error}

  def options, do: Application.get_env(:secrethub_core, :acme_adapter_options, [])
end
