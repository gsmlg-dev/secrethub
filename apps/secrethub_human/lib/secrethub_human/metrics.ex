defmodule SecretHub.Human.Metrics do
  @moduledoc "Database-backed operational counters. No actor identifiers or payloads are emitted."
  import Ecto.Query
  alias SecretHub.Human.Audit.Event
  alias SecretHub.Human.Repo
  alias SecretHub.Human.Schemas.Session
  alias SecretHub.Human.Vault.Item

  def snapshot do
    now = DateTime.utc_now()

    events =
      Repo.all(from(e in Event, group_by: e.event_type, select: {e.event_type, count(e.id)}))
      |> Map.new()

    core = SecretHub.Access.human_metrics()

    Map.merge(core, %{
      human_sessions_active:
        Repo.aggregate(
          from(s in Session, where: is_nil(s.revoked_at) and s.expires_at > ^now),
          :count
        ),
      human_vault_items_total:
        Repo.aggregate(from(i in Item, where: is_nil(i.deleted_at)), :count),
      human_login_failures_total: Map.get(events, "human.login.failed", 0)
    })
  end

  def emit do
    :telemetry.execute([:secrethub, :human, :metrics], snapshot(), %{})
    :ok
  end
end
