defmodule SecretHub.Human.Organizations.RevokeMembership do
  @moduledoc "Durable UUID-only bridge from committed membership removal to Core revocation."
  use Oban.Worker, queue: :human_audit, max_attempts: 20

  @impl Oban.Worker
  def perform(%Oban.Job{args: %{"organization_id" => org, "subject_id" => subject}}),
    do: revoke(org, subject, SecretHub.Access)

  def revoke(org, subject, adapter) do
    with {:ok, _} <- Ecto.UUID.cast(org), {:ok, _} <- Ecto.UUID.cast(subject) do
      case adapter.revoke_organization_membership(org, subject) do
        :ok -> :ok
        {:error, _} -> {:error, :revocation_unavailable}
      end
    else
      _ -> {:error, :invalid_input}
    end
  rescue
    _ -> {:error, :revocation_unavailable}
  catch
    :exit, _ -> {:error, :revocation_unavailable}
  end
end
