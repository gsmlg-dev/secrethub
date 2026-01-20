defmodule SecretHub.Web.AdminDashboardController do
  @moduledoc """
  Dashboard controller for admin interface.

  Provides JSON APIs for dashboard data and admin management actions.
  """

  use SecretHub.Web, :controller
  require Logger

  # FIXME: Replace with actual calls to SecretHub.Core modules
  # For now, return mock data for demonstration

  def system_stats(conn, _params) do
    # Mock data - replace with actual implementation
    stats = %{
      total_secrets: 156,
      active_agents: 23,
      total_roles: 12,
      uptime_hours: 72,
      last_rotation: "2025-10-20T14:30:00Z",
      storage_used_gb: 2.3
    }

    conn
    |> put_resp_content_type("application/json")
    |> json(%{status: "ok", data: stats})
  end

  def connected_agents(conn, _params) do
    # Mock agent data
    agents = [
      %{
        id: "agent-prod-01",
        name: "Production Web Server",
        status: :connected,
        last_seen: "2025-10-21T16:45:00Z",
        secrets_accessed: 45,
        uptime_hours: 48.5,
        os: "linux",
        ip_address: "10.0.1.42"
      },
      %{
        id: "agent-prod-02",
        name: "Backend Worker",
        status: :disconnected,
        last_seen: "2025-10-21T15:30:00Z",
        secrets_accessed: 12,
        uptime_hours: nil,
        os: "alpine-linux",
        ip_address: "10.0.1.45"
      }
    ]

    conn
    |> put_resp_content_type("application/json")
    |> json(%{status: "ok", data: agents})
  end

  def secret_stats(conn, _params) do
    # Mock secret statistics
    stats = %{
      total_secrets: 156,
      static_secrets: 89,
      dynamic_secrets: 67,
      secrets_rotated_24h: 12,
      secrets_expiring_7d: 8,
      most_accessed_secret: "prod.db.postgres.password",
      policies_active: 12
    }

    conn
    |> put_resp_content_type("application/json")
    |> json(%{status: "ok", data: stats})
  end

  def audit_logs(conn, %{"filter" => _filter, "event_type" => event_type}) do
    # Mock audit logs
    logs = [
      %{
        id: "1",
        timestamp: "2025-10-21T14:25:00Z",
        event_type: "secret_access",
        agent_id: "agent-prod-01",
        secret_path: "prod.db.postgres.password",
        access_granted: true,
        policy_matched: "webapp-secrets",
        source_ip: "10.0.1.42",
        response_time_ms: 45,
        correlation_id: "550e8400-e29b-41d4-a5a0-c276e42c5ca"
      },
      %{
        id: "2",
        timestamp: "2025-10-21T13:15:00Z",
        event_type: "secret_access_denied",
        agent_id: "agent-prod-02",
        secret_path: "prod.api.payment.key",
        access_granted: false,
        policy_matched: "production-secrets",
        denial_reason: "Agent not authorized for production secrets",
        source_ip: "10.0.1.45",
        response_time_ms: 23,
        correlation_id: "550e8400-e29b-41d4-a5a0-c276e42c5cb"
      }
    ]

    filtered_logs = maybe_filter_by_event_type(logs, event_type)

    conn
    |> put_resp_content_type("application/json")
    |> json(%{status: "ok", data: filtered_logs})
  end

  def export_audit_logs(conn, _params) do
    # Trigger audit log export
    # FIXME: Implement actual export functionality
    Task.start(fn ->
      # Simulate export processing time
      :timer.sleep(2000)
      Logger.info("Audit logs export completed")
    end)

    conn
    |> put_resp_content_type("application/json")
    |> json(%{status: "ok", message: "Export started"})
  end

  def rotate_all_leases(conn, _params) do
    # Trigger lease rotation
    # FIXME: Call SecretHub.Core.Secrets.rotate_all_leases()
    Logger.info("Lease rotation triggered")

    conn
    |> put_resp_content_type("application/json")
    |> json(%{status: "ok", message: "Rotation started"})
  end

  def cleanup_expired_secrets(conn, _params) do
    # Trigger cleanup of expired secrets
    # FIXME: Call SecretHub.Core.Secrets.cleanup_expired_secrets()
    Logger.info("Cleanup of expired secrets started")

    conn
    |> put_resp_content_type("application/json")
    |> json(%{status: "ok", message: "Cleanup started"})
  end

  defp maybe_filter_by_event_type(logs, "all"), do: logs

  defp maybe_filter_by_event_type(logs, event_type) do
    Enum.filter(logs, fn log -> log.event_type == event_type end)
  end
end
