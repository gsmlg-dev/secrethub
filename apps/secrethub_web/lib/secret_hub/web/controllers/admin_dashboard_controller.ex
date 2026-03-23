defmodule SecretHub.Web.AdminDashboardController do
  @moduledoc """
  Dashboard controller for admin interface.

  Provides JSON APIs for dashboard data and admin management actions.
  """

  use SecretHub.Web, :controller
  require Logger

  alias SecretHub.Core.{Agents, Audit, Secrets}
  alias SecretHub.Core.Auth.AppRole

  def system_stats(conn, _params) do
    secret_stats = Secrets.get_secret_stats()
    agent_stats = Agents.get_agent_stats()
    roles = AppRole.list_roles()

    stats = %{
      total_secrets: secret_stats.total,
      active_agents: agent_stats.active,
      total_roles: length(roles),
      static_secrets: secret_stats.static,
      dynamic_secrets: secret_stats.dynamic
    }

    conn
    |> put_resp_content_type("application/json")
    |> json(%{status: "ok", data: stats})
  end

  def connected_agents(conn, _params) do
    agents = Agents.list_agents(%{status: :active})

    agent_data =
      Enum.map(agents, fn agent ->
        %{
          id: agent.agent_id,
          name: agent.name,
          status: agent.status,
          last_seen: agent.last_heartbeat_at,
          os: agent.metadata["os"],
          ip_address: agent.metadata["ip_address"]
        }
      end)

    conn
    |> put_resp_content_type("application/json")
    |> json(%{status: "ok", data: agent_data})
  end

  def secret_stats(conn, _params) do
    stats = Secrets.get_secret_stats()

    conn
    |> put_resp_content_type("application/json")
    |> json(%{status: "ok", data: stats})
  end

  def audit_logs(conn, %{"filter" => _filter, "event_type" => event_type}) do
    filters =
      case event_type do
        "all" -> %{limit: 50}
        type -> %{event_type: type, limit: 50}
      end

    logs = Audit.search_logs(filters)

    log_data =
      Enum.map(logs, fn log ->
        %{
          id: log.id,
          timestamp: log.timestamp,
          event_type: log.event_type,
          actor_id: log.actor_id,
          resource_type: log.resource_type,
          resource_id: log.resource_id,
          action: log.action,
          result: log.result,
          access_granted: log.access_granted,
          ip_address: log.ip_address,
          correlation_id: log.correlation_id
        }
      end)

    conn
    |> put_resp_content_type("application/json")
    |> json(%{status: "ok", data: log_data})
  end

  def export_audit_logs(conn, params) do
    filters = Map.take(params, ["event_type", "from", "to"])

    csv_data = Audit.export_to_csv(filters)

    conn
    |> put_resp_content_type("text/csv")
    |> put_resp_header("content-disposition", "attachment; filename=\"audit-logs.csv\"")
    |> send_resp(200, csv_data)
  end

  def rotate_all_leases(conn, _params) do
    Logger.info("Lease rotation triggered via admin dashboard")

    conn
    |> put_resp_content_type("application/json")
    |> json(%{status: "ok", message: "Rotation started"})
  end

  def cleanup_expired_secrets(conn, _params) do
    Logger.info("Cleanup of expired secrets triggered via admin dashboard")

    conn
    |> put_resp_content_type("application/json")
    |> json(%{status: "ok", message: "Cleanup started"})
  end
end
