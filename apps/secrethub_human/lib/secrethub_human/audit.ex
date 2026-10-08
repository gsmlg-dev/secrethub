defmodule SecretHub.Human.Audit do
  @moduledoc "Transactional, sanitized outbox delivered idempotently through the public Core sink."
  alias SecretHub.Human.Audit.Event
  alias SecretHub.Human.AuditDelivery
  alias SecretHub.Human.Repo
  alias SecretHub.Shared.HumanAuditEvidence

  def record(event, actor, metadata \\ %{}) do
    actor_id = if is_map(actor), do: Map.get(actor, :user_id) || Map.get(actor, :id)

    with {:ok, data} <- HumanAuditEvidence.validate(event, metadata) do
      Repo.transaction(fn -> persist_outbox(event, actor_id, data) end)
    end
  end

  def deliver(id) do
    case Repo.get(Event, id) do
      nil ->
        {:error, :not_found}

      %Event{delivered_at: at} when not is_nil(at) ->
        :ok

      %Event{} = event ->
        deliver_event(event)
    end
  end

  defp persist_outbox(event, actor_id, data) do
    row = Repo.insert!(%Event{event_type: event, actor_id: actor_id, metadata: data})
    job = AuditDelivery.new(%{"event_id" => row.id})

    case Oban.insert(SecretHub.Human.Oban, job) do
      {:ok, _} -> row.id
      {:error, _} -> Repo.rollback(:audit_unavailable)
    end
  end

  defp deliver_event(event) do
    case SecretHub.Access.record_human_event(
           event.event_type,
           event.actor_id,
           event.metadata,
           event.id
         ) do
      {:ok, _} -> mark_delivered(event)
      {:error, _} -> {:error, :audit_unavailable}
    end
  end

  defp mark_delivered(event) do
    case event |> Ecto.Changeset.change(delivered_at: DateTime.utc_now()) |> Repo.update() do
      {:ok, _} -> :ok
      {:error, _} -> {:error, :audit_unavailable}
    end
  end
end
