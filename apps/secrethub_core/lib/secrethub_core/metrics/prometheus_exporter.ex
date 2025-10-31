defmodule SecretHub.Core.Metrics.PrometheusExporter do
  @moduledoc """
  Prometheus metrics exporter for SecretHub.

  Exports operational metrics in Prometheus format for monitoring and alerting.
  Metrics include:
  - Audit log statistics
  - Secret access patterns
  - Rotation success/failure rates
  - Anomaly detection triggers
  - System health indicators
  - Agent connectivity
  - Lease statistics

  ## Metric Types

  - **Counters**: Monotonically increasing values (e.g., total requests)
  - **Gauges**: Current value that can go up or down (e.g., active connections)
  - **Histograms**: Distribution of values (e.g., request duration)
  - **Summaries**: Similar to histograms with quantiles

  ## Usage

      # In your telemetry setup
      PrometheusExporter.setup()

      # Metrics are automatically collected and exposed at /metrics
  """

  use Prometheus.Metric

  require Logger

  @doc """
  Sets up all Prometheus metrics.
  Call this during application startup.
  """
  def setup do
    # Audit metrics
    Counter.declare(
      name: :secrethub_audit_logs_total,
      help: "Total number of audit log entries",
      labels: [:event_type, :result]
    )

    Counter.declare(
      name: :secrethub_audit_logs_archived_total,
      help: "Total number of audit logs archived",
      labels: [:provider]
    )

    Gauge.declare(
      name: :secrethub_audit_logs_pending_archival,
      help: "Number of audit logs pending archival"
    )

    # Secret metrics
    Counter.declare(
      name: :secrethub_secret_reads_total,
      help: "Total number of secret reads",
      labels: [:engine_type]
    )

    Counter.declare(
      name: :secrethub_secret_writes_total,
      help: "Total number of secret writes",
      labels: [:engine_type]
    )

    Gauge.declare(
      name: :secrethub_secrets_count,
      help: "Current number of secrets",
      labels: [:status]
    )

    # Rotation metrics
    Counter.declare(
      name: :secrethub_rotations_total,
      help: "Total number of rotation attempts",
      labels: [:rotation_type, :result]
    )

    Histogram.declare(
      name: :secrethub_rotation_duration_seconds,
      help: "Rotation duration in seconds",
      labels: [:rotation_type],
      buckets: [0.1, 0.5, 1, 2, 5, 10, 30, 60]
    )

    Gauge.declare(
      name: :secrethub_next_rotation_seconds,
      help: "Seconds until next scheduled rotation",
      labels: [:schedule_name]
    )

    # Anomaly detection metrics
    Counter.declare(
      name: :secrethub_anomalies_detected_total,
      help: "Total number of anomalies detected",
      labels: [:rule_type, :severity]
    )

    Gauge.declare(
      name: :secrethub_alerts_open,
      help: "Number of open alerts",
      labels: [:severity]
    )

    Counter.declare(
      name: :secrethub_alerts_total,
      help: "Total number of alerts triggered",
      labels: [:severity, :channel_type]
    )

    # Agent metrics
    Gauge.declare(
      name: :secrethub_agents_connected,
      help: "Number of currently connected agents",
      labels: [:status]
    )

    Counter.declare(
      name: :secrethub_agent_connections_total,
      help: "Total number of agent connection attempts",
      labels: [:result]
    )

    Histogram.declare(
      name: :secrethub_agent_heartbeat_latency_seconds,
      help: "Agent heartbeat latency in seconds",
      labels: [:agent_id],
      buckets: [0.01, 0.05, 0.1, 0.5, 1, 2, 5]
    )

    # Lease metrics
    Gauge.declare(
      name: :secrethub_leases_active,
      help: "Number of active leases",
      labels: [:engine_type]
    )

    Counter.declare(
      name: :secrethub_leases_issued_total,
      help: "Total number of leases issued",
      labels: [:engine_type]
    )

    Counter.declare(
      name: :secrethub_leases_renewed_total,
      help: "Total number of lease renewals",
      labels: [:engine_type, :result]
    )

    Counter.declare(
      name: :secrethub_leases_revoked_total,
      help: "Total number of lease revocations",
      labels: [:engine_type, :reason]
    )

    # Engine health metrics
    Gauge.declare(
      name: :secrethub_engine_health,
      help: "Engine health status (1=healthy, 0=unhealthy)",
      labels: [:engine_name, :engine_type]
    )

    Histogram.declare(
      name: :secrethub_engine_response_time_seconds,
      help: "Engine response time in seconds",
      labels: [:engine_name, :operation],
      buckets: [0.01, 0.05, 0.1, 0.5, 1, 2, 5, 10]
    )

    # System metrics
    Gauge.declare(
      name: :secrethub_vault_sealed,
      help: "Vault seal status (1=sealed, 0=unsealed)"
    )

    Gauge.declare(
      name: :secrethub_cluster_nodes,
      help: "Number of cluster nodes",
      labels: [:status]
    )

    Counter.declare(
      name: :secrethub_http_requests_total,
      help: "Total HTTP requests",
      labels: [:method, :path, :status]
    )

    Histogram.declare(
      name: :secrethub_http_request_duration_seconds,
      help: "HTTP request duration in seconds",
      labels: [:method, :path],
      buckets: [0.01, 0.05, 0.1, 0.5, 1, 2, 5]
    )

    Logger.info("Prometheus metrics configured")
    :ok
  end

  # Metric update functions

  @doc """
  Records an audit log entry.
  """
  def record_audit_log(event_type, result) do
    Counter.inc(
      name: :secrethub_audit_logs_total,
      labels: [event_type, result]
    )
  end

  @doc """
  Records an archival operation.
  """
  def record_archival(provider, count) do
    Counter.inc(
      name: :secrethub_audit_logs_archived_total,
      labels: [provider],
      value: count
    )
  end

  @doc """
  Updates pending archival count.
  """
  def update_pending_archival(count) do
    Gauge.set([name: :secrethub_audit_logs_pending_archival], count)
  end

  @doc """
  Records a secret read.
  """
  def record_secret_read(engine_type) do
    Counter.inc(
      name: :secrethub_secret_reads_total,
      labels: [engine_type]
    )
  end

  @doc """
  Records a secret write.
  """
  def record_secret_write(engine_type) do
    Counter.inc(
      name: :secrethub_secret_writes_total,
      labels: [engine_type]
    )
  end

  @doc """
  Records a rotation attempt.
  """
  def record_rotation(rotation_type, result, duration_ms) do
    Counter.inc(
      name: :secrethub_rotations_total,
      labels: [rotation_type, result]
    )

    Histogram.observe(
      name: :secrethub_rotation_duration_seconds,
      labels: [rotation_type],
      value: duration_ms / 1000
    )
  end

  @doc """
  Records an anomaly detection.
  """
  def record_anomaly(rule_type, severity) do
    Counter.inc(
      name: :secrethub_anomalies_detected_total,
      labels: [rule_type, severity]
    )
  end

  @doc """
  Updates open alerts count.
  """
  def update_open_alerts(severity, count) do
    Gauge.set([name: :secrethub_alerts_open, labels: [severity]], count)
  end

  @doc """
  Records an alert being sent.
  """
  def record_alert(severity, channel_type) do
    Counter.inc(
      name: :secrethub_alerts_total,
      labels: [severity, channel_type]
    )
  end

  @doc """
  Updates agent connection count.
  """
  def update_agent_count(status, count) do
    Gauge.set([name: :secrethub_agents_connected, labels: [status]], count)
  end

  @doc """
  Records agent heartbeat latency.
  """
  def record_heartbeat_latency(agent_id, latency_ms) do
    Histogram.observe(
      name: :secrethub_agent_heartbeat_latency_seconds,
      labels: [agent_id],
      value: latency_ms / 1000
    )
  end

  @doc """
  Updates active lease count.
  """
  def update_active_leases(engine_type, count) do
    Gauge.set([name: :secrethub_leases_active, labels: [engine_type]], count)
  end

  @doc """
  Records a lease issuance.
  """
  def record_lease_issued(engine_type) do
    Counter.inc(
      name: :secrethub_leases_issued_total,
      labels: [engine_type]
    )
  end

  @doc """
  Records engine health status.
  """
  def update_engine_health(engine_name, engine_type, healthy?) do
    value = if healthy?, do: 1, else: 0
    Gauge.set([name: :secrethub_engine_health, labels: [engine_name, engine_type]], value)
  end

  @doc """
  Records engine operation response time.
  """
  def record_engine_response_time(engine_name, operation, duration_ms) do
    Histogram.observe(
      name: :secrethub_engine_response_time_seconds,
      labels: [engine_name, operation],
      value: duration_ms / 1000
    )
  end

  @doc """
  Updates vault seal status.
  """
  def update_vault_seal_status(sealed?) do
    value = if sealed?, do: 1, else: 0
    Gauge.set([name: :secrethub_vault_sealed], value)
  end

  @doc """
  Records an HTTP request.
  """
  def record_http_request(method, path, status, duration_ms) do
    Counter.inc(
      name: :secrethub_http_requests_total,
      labels: [method, path, status]
    )

    Histogram.observe(
      name: :secrethub_http_request_duration_seconds,
      labels: [method, path],
      value: duration_ms / 1000
    )
  end

  @doc """
  Collects current metrics snapshot for display.
  """
  def collect_metrics do
    %{
      audit: collect_audit_metrics(),
      secrets: collect_secret_metrics(),
      rotations: collect_rotation_metrics(),
      anomalies: collect_anomaly_metrics(),
      agents: collect_agent_metrics(),
      leases: collect_lease_metrics(),
      engines: collect_engine_metrics(),
      system: collect_system_metrics()
    }
  end

  defp collect_audit_metrics do
    %{
      total_logs: Counter.value(name: :secrethub_audit_logs_total),
      archived: Counter.value(name: :secrethub_audit_logs_archived_total),
      pending_archival: Gauge.value(name: :secrethub_audit_logs_pending_archival)
    }
  end

  defp collect_secret_metrics do
    %{
      reads: Counter.value(name: :secrethub_secret_reads_total),
      writes: Counter.value(name: :secrethub_secret_writes_total),
      count: Gauge.value(name: :secrethub_secrets_count)
    }
  end

  defp collect_rotation_metrics do
    %{
      total: Counter.value(name: :secrethub_rotations_total)
    }
  end

  defp collect_anomaly_metrics do
    %{
      detected: Counter.value(name: :secrethub_anomalies_detected_total),
      open_alerts: Gauge.value(name: :secrethub_alerts_open)
    }
  end

  defp collect_agent_metrics do
    %{
      connected: Gauge.value(name: :secrethub_agents_connected)
    }
  end

  defp collect_lease_metrics do
    %{
      active: Gauge.value(name: :secrethub_leases_active),
      issued: Counter.value(name: :secrethub_leases_issued_total)
    }
  end

  defp collect_engine_metrics do
    %{
      health: Gauge.value(name: :secrethub_engine_health)
    }
  end

  defp collect_system_metrics do
    %{
      vault_sealed: Gauge.value(name: :secrethub_vault_sealed),
      cluster_nodes: Gauge.value(name: :secrethub_cluster_nodes)
    }
  end
end
