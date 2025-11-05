defmodule SecretHub.Core.Alerting do
  @moduledoc """
  Alert routing and delivery system.

  Manages creation, routing, and delivery of alerts to configured channels
  (email, Slack, webhooks, etc.). Handles severity-based routing and
  delivery confirmation.

  ## Alert Lifecycle

  1. Alert created (from anomaly detection or manual trigger)
  2. Alert routed based on severity and configuration
  3. Alert delivered to channels (email, Slack, webhook, etc.)
  4. Delivery tracked and confirmed
  5. Alert can be acknowledged, investigated, or resolved

  ## Example

      # Create and route an alert
      alert = create_anomaly_alert(attrs)
      route_alert(alert)

      # Acknowledge an alert
      acknowledge_alert(alert_id, "admin@example.com")

      # Resolve an alert
      resolve_alert(alert_id, :resolved, "Fixed the issue", "admin@example.com")
  """

  require Logger

  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.{AnomalyAlert, AlertRoutingConfig}

  import Ecto.Query

  @doc """
  Creates a new anomaly alert.
  """
  def create_anomaly_alert(attrs) do
    %AnomalyAlert{}
    |> AnomalyAlert.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Routes an alert to configured channels based on severity.
  """
  def route_alert(alert) do
    routing_configs = get_matching_configs(alert.severity)

    Logger.info("Routing alert",
      alert_id: alert.id,
      severity: alert.severity,
      channels: length(routing_configs)
    )

    results =
      routing_configs
      |> Enum.map(&send_to_channel(&1, alert))

    # Track successful deliveries
    successful = Enum.count(results, &match?({:ok, _}, &1))

    Logger.info("Alert routed",
      alert_id: alert.id,
      total_channels: length(routing_configs),
      successful: successful
    )

    {:ok, %{total: length(routing_configs), successful: successful}}
  end

  @doc """
  Acknowledges an alert.
  """
  def acknowledge_alert(alert_id, acknowledged_by) do
    case Repo.get(AnomalyAlert, alert_id) do
      nil ->
        {:error, :not_found}

      alert ->
        alert
        |> AnomalyAlert.acknowledge()
        |> Ecto.Changeset.put_change(:resolved_by, acknowledged_by)
        |> Repo.update()
    end
  end

  @doc """
  Marks an alert as being investigated.
  """
  def start_investigation(alert_id) do
    case Repo.get(AnomalyAlert, alert_id) do
      nil -> {:error, :not_found}
      alert -> alert |> AnomalyAlert.start_investigation() |> Repo.update()
    end
  end

  @doc """
  Resolves an alert.
  """
  def resolve_alert(alert_id, status, notes, resolved_by) do
    case Repo.get(AnomalyAlert, alert_id) do
      nil ->
        {:error, :not_found}

      alert ->
        alert
        |> AnomalyAlert.resolve(status, notes: notes, resolved_by: resolved_by)
        |> Repo.update()
    end
  end

  @doc """
  Marks an alert as a false positive.
  """
  def mark_false_positive(alert_id, notes) do
    case Repo.get(AnomalyAlert, alert_id) do
      nil -> {:error, :not_found}
      alert -> alert |> AnomalyAlert.mark_false_positive(notes) |> Repo.update()
    end
  end

  @doc """
  Lists all open (unresolved) alerts.
  """
  def list_open_alerts do
    AnomalyAlert
    |> where([a], a.status in [:open, :acknowledged, :investigating])
    |> order_by([a], desc: a.triggered_at)
    |> Repo.all()
  end

  @doc """
  Lists critical unresolved alerts.
  """
  def list_critical_alerts do
    AnomalyAlert
    |> where([a], a.severity == :critical)
    |> where([a], a.status in [:open, :acknowledged, :investigating])
    |> order_by([a], desc: a.triggered_at)
    |> Repo.all()
  end

  @doc """
  Gets alerts by severity.
  """
  def list_alerts_by_severity(severity) do
    AnomalyAlert
    |> where([a], a.severity == ^severity)
    |> order_by([a], desc: a.triggered_at)
    |> limit(100)
    |> Repo.all()
  end

  # Private functions

  defp get_matching_configs(severity) do
    AlertRoutingConfig
    |> where([c], c.enabled == true)
    |> Repo.all()
    |> Enum.filter(&AlertRoutingConfig.matches_severity?(&1, severity))
  end

  defp send_to_channel(config, alert) do
    Logger.info("Sending alert to channel",
      alert_id: alert.id,
      channel: config.channel_type,
      config_name: config.name
    )

    result =
      case config.channel_type do
        :email -> send_email(config, alert)
        :slack -> send_slack(config, alert)
        :webhook -> send_webhook(config, alert)
        :pagerduty -> send_pagerduty(config, alert)
        :opsgenie -> send_opsgenie(config, alert)
        _ -> {:error, :unsupported_channel}
      end

    # Update last_used_at
    if match?({:ok, _}, result) do
      config
      |> AlertRoutingConfig.record_usage()
      |> Repo.update()
    end

    result
  end

  defp send_email(config, alert) do
    recipients = AlertRoutingConfig.email_recipients(config)

    subject = "[SecretHub] #{format_severity(alert.severity)} Alert: #{alert.description}"

    body = format_email_body(alert)

    Logger.info("Sending email alert",
      recipients: recipients,
      subject: subject
    )

    # Mock email sending - would integrate with Swoosh
    {:ok, %{channel: :email, recipients: recipients}}
  end

  defp send_slack(config, alert) do
    webhook_url = AlertRoutingConfig.slack_webhook_url(config)

    payload = %{
      text: "*SecretHub Alert*",
      attachments: [
        %{
          color: severity_color(alert.severity),
          title: alert.description,
          fields: [
            %{title: "Severity", value: format_severity(alert.severity), short: true},
            %{title: "Status", value: format_status(alert.status), short: true},
            %{
              title: "Triggered At",
              value: Calendar.strftime(alert.triggered_at, "%Y-%m-%d %H:%M:%S UTC"),
              short: false
            }
          ],
          footer: "SecretHub Anomaly Detection",
          ts: DateTime.to_unix(alert.triggered_at)
        }
      ]
    }

    Logger.info("Sending Slack alert", webhook_url: webhook_url)

    # Mock Slack sending - would use HTTPoison/Req
    {:ok, %{channel: :slack, webhook_url: webhook_url}}
  end

  defp send_webhook(config, alert) do
    url = AlertRoutingConfig.webhook_url(config)

    payload = %{
      alert_id: alert.id,
      severity: alert.severity,
      status: alert.status,
      description: alert.description,
      triggered_at: alert.triggered_at,
      context: alert.context
    }

    Logger.info("Sending webhook alert", url: url)

    # Mock webhook sending - would use HTTPoison/Req
    {:ok, %{channel: :webhook, url: url}}
  end

  defp send_pagerduty(config, _alert) do
    integration_key = get_in(config.config, ["integration_key"])

    Logger.info("Sending PagerDuty alert", integration_key: String.slice(integration_key, 0..8))

    # Mock PagerDuty sending
    {:ok, %{channel: :pagerduty}}
  end

  defp send_opsgenie(config, _alert) do
    api_key = get_in(config.config, ["api_key"])

    Logger.info("Sending Opsgenie alert", api_key: String.slice(api_key, 0..8))

    # Mock Opsgenie sending
    {:ok, %{channel: :opsgenie}}
  end

  defp format_email_body(alert) do
    """
    SecretHub Anomaly Alert

    Severity: #{format_severity(alert.severity)}
    Status: #{format_status(alert.status)}
    Triggered: #{Calendar.strftime(alert.triggered_at, "%Y-%m-%d %H:%M:%S UTC")}

    Description:
    #{alert.description}

    Context:
    #{Jason.encode!(alert.context, pretty: true)}

    ---
    This is an automated alert from SecretHub.
    """
  end

  defp format_severity(:critical), do: "CRITICAL"
  defp format_severity(:high), do: "HIGH"
  defp format_severity(:medium), do: "MEDIUM"
  defp format_severity(:low), do: "LOW"
  defp format_severity(:info), do: "INFO"
  defp format_severity(other), do: to_string(other)

  defp format_status(:open), do: "Open"
  defp format_status(:acknowledged), do: "Acknowledged"
  defp format_status(:investigating), do: "Investigating"
  defp format_status(:resolved), do: "Resolved"
  defp format_status(:false_positive), do: "False Positive"
  defp format_status(other), do: to_string(other)

  defp severity_color(:critical), do: "danger"
  defp severity_color(:high), do: "warning"
  defp severity_color(:medium), do: "#ffaa00"
  defp severity_color(:low), do: "good"
  defp severity_color(:info), do: "#cccccc"
  defp severity_color(_), do: "#cccccc"
end
