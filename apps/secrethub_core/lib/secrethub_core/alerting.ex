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
  alias SecretHub.Shared.Schemas.{AlertRoutingConfig, AnomalyAlert}

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

    case config.channel_type do
      :email -> send_email(config, alert)
      :slack -> send_slack(config, alert)
      :webhook -> send_webhook(config, alert)
      :pagerduty -> send_pagerduty(config, alert)
      :opsgenie -> send_opsgenie(config, alert)
      _ -> {:error, :unsupported_channel}
    end
  end

  defp send_email(_config, _alert) do
    # TODO: Integrate with Swoosh for email delivery
    Logger.warning("Email alert delivery not implemented")
    {:error, :not_implemented}
  end

  defp send_slack(_config, _alert) do
    # TODO: Integrate with Req for Slack webhook delivery
    Logger.warning("Slack alert delivery not implemented")
    {:error, :not_implemented}
  end

  defp send_webhook(_config, _alert) do
    # TODO: Integrate with Req for webhook delivery
    Logger.warning("Webhook alert delivery not implemented")
    {:error, :not_implemented}
  end

  defp send_pagerduty(_config, _alert) do
    # TODO: Integrate with PagerDuty Events API v2
    Logger.warning("PagerDuty alert delivery not implemented")
    {:error, :not_implemented}
  end

  defp send_opsgenie(_config, _alert) do
    # TODO: Integrate with Opsgenie Alert API
    Logger.warning("Opsgenie alert delivery not implemented")
    {:error, :not_implemented}
  end

end
