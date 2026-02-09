defmodule SecretHub.Core.HealthAlerts do
  @moduledoc """
  Manages health alert configurations and evaluation.

  Provides CRUD operations for alert rules and evaluates node health
  metrics against configured thresholds to trigger notifications.
  """

  import Ecto.Query
  require Logger

  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.{HealthAlert, NodeHealthMetric}

  @doc """
  Lists all health alerts.

  Options:
  - `:enabled_only` - Only return enabled alerts (default: false)
  """
  @spec list_alerts(keyword()) :: [HealthAlert.t()]
  def list_alerts(opts \\ []) do
    enabled_only = Keyword.get(opts, :enabled_only, false)

    query = from(a in HealthAlert, order_by: [asc: a.name])

    query =
      if enabled_only do
        from(a in query, where: a.enabled == true)
      else
        query
      end

    Repo.all(query)
  end

  @doc """
  Gets a single alert by ID.
  """
  @spec get_alert(binary()) :: {:ok, HealthAlert.t()} | {:error, :not_found}
  def get_alert(id) do
    case Repo.get(HealthAlert, id) do
      nil -> {:error, :not_found}
      alert -> {:ok, alert}
    end
  end

  @doc """
  Gets a single alert by name.
  """
  @spec get_alert_by_name(String.t()) :: {:ok, HealthAlert.t()} | {:error, :not_found}
  def get_alert_by_name(name) do
    case Repo.get_by(HealthAlert, name: name) do
      nil -> {:error, :not_found}
      alert -> {:ok, alert}
    end
  end

  @doc """
  Creates a new health alert.
  """
  @spec create_alert(map()) :: {:ok, HealthAlert.t()} | {:error, Ecto.Changeset.t()}
  def create_alert(attrs) do
    %HealthAlert{}
    |> HealthAlert.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Updates an existing health alert.
  """
  @spec update_alert(HealthAlert.t(), map()) ::
          {:ok, HealthAlert.t()} | {:error, Ecto.Changeset.t()}
  def update_alert(%HealthAlert{} = alert, attrs) do
    alert
    |> HealthAlert.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Deletes a health alert.
  """
  @spec delete_alert(HealthAlert.t()) :: {:ok, HealthAlert.t()} | {:error, Ecto.Changeset.t()}
  def delete_alert(%HealthAlert{} = alert) do
    Repo.delete(alert)
  end

  @doc """
  Enables an alert.
  """
  @spec enable_alert(binary()) :: {:ok, HealthAlert.t()} | {:error, term()}
  def enable_alert(id) do
    with {:ok, alert} <- get_alert(id) do
      update_alert(alert, %{enabled: true})
    end
  end

  @doc """
  Disables an alert.
  """
  @spec disable_alert(binary()) :: {:ok, HealthAlert.t()} | {:error, term()}
  def disable_alert(id) do
    with {:ok, alert} <- get_alert(id) do
      update_alert(alert, %{enabled: false})
    end
  end

  @doc """
  Evaluates all enabled alerts against current health metrics.

  Returns a list of triggered alerts.
  """
  @spec evaluate_alerts() :: [%{alert: HealthAlert.t(), metric: NodeHealthMetric.t()}]
  def evaluate_alerts do
    alerts = list_alerts(enabled_only: true)

    # Get recent metrics for all nodes (last 5 minutes)
    cutoff = DateTime.add(DateTime.utc_now() |> DateTime.truncate(:second), -5 * 60, :second)

    recent_metrics =
      from(m in NodeHealthMetric,
        where: m.timestamp >= ^cutoff,
        order_by: [desc: m.timestamp],
        distinct: m.node_id
      )
      |> Repo.all()

    # Evaluate each alert against recent metrics
    Enum.flat_map(alerts, fn alert ->
      evaluate_alert_against_metrics(alert, recent_metrics)
    end)
  end

  @doc """
  Evaluates a single alert against a list of metrics.
  """
  @spec evaluate_alert(HealthAlert.t()) :: [
          %{alert: HealthAlert.t(), metric: NodeHealthMetric.t()}
        ]
  def evaluate_alert(%HealthAlert{} = alert) do
    # Get recent metrics (last 5 minutes)
    cutoff = DateTime.add(DateTime.utc_now() |> DateTime.truncate(:second), -5 * 60, :second)

    recent_metrics =
      from(m in NodeHealthMetric,
        where: m.timestamp >= ^cutoff,
        order_by: [desc: m.timestamp],
        distinct: m.node_id
      )
      |> Repo.all()

    evaluate_alert_against_metrics(alert, recent_metrics)
  end

  # Private Functions

  defp evaluate_alert_against_metrics(alert, metrics) do
    # Check if alert is in cooldown
    if in_cooldown?(alert) do
      []
    else
      triggered =
        Enum.filter(metrics, fn metric ->
          evaluate_condition(alert, metric)
        end)

      if Enum.any?(triggered) do
        # Update last_triggered_at
        update_alert(alert, %{last_triggered_at: DateTime.utc_now() |> DateTime.truncate(:second)})

        # Return triggered alerts
        Enum.map(triggered, fn metric ->
          %{alert: alert, metric: metric}
        end)
      else
        []
      end
    end
  end

  defp in_cooldown?(%HealthAlert{last_triggered_at: nil}), do: false

  defp in_cooldown?(%HealthAlert{last_triggered_at: last_triggered, cooldown_minutes: cooldown}) do
    cooldown_seconds = cooldown * 60
    cutoff = DateTime.add(DateTime.utc_now() |> DateTime.truncate(:second), -cooldown_seconds, :second)
    DateTime.compare(last_triggered, cutoff) == :gt
  end

  defp evaluate_condition(%HealthAlert{alert_type: "node_down"}, %NodeHealthMetric{} = metric) do
    # Node is down if last heartbeat is older than 1 minute
    cutoff = DateTime.add(DateTime.utc_now() |> DateTime.truncate(:second), -60, :second)

    case metric.last_heartbeat_at do
      nil -> true
      heartbeat -> DateTime.compare(heartbeat, cutoff) == :lt
    end
  end

  defp evaluate_condition(
         %HealthAlert{alert_type: "high_cpu", threshold_value: threshold, threshold_operator: op},
         %NodeHealthMetric{cpu_percent: cpu}
       )
       when not is_nil(cpu) do
    compare_value(cpu, op, threshold)
  end

  defp evaluate_condition(
         %HealthAlert{
           alert_type: "high_memory",
           threshold_value: threshold,
           threshold_operator: op
         },
         %NodeHealthMetric{memory_percent: memory}
       )
       when not is_nil(memory) do
    compare_value(memory, op, threshold)
  end

  defp evaluate_condition(
         %HealthAlert{
           alert_type: "database_latency",
           threshold_value: threshold,
           threshold_operator: op
         },
         %NodeHealthMetric{database_latency_ms: latency}
       )
       when not is_nil(latency) do
    compare_value(latency, op, threshold)
  end

  defp evaluate_condition(
         %HealthAlert{alert_type: "vault_sealed"},
         %NodeHealthMetric{vault_sealed: sealed}
       ) do
    sealed == true
  end

  defp evaluate_condition(_alert, _metric), do: false

  defp compare_value(value, ">", threshold), do: value > threshold
  defp compare_value(value, "<", threshold), do: value < threshold
  defp compare_value(value, "==", threshold), do: value == threshold
  defp compare_value(value, "!=", threshold), do: value != threshold
  defp compare_value(_value, _op, _threshold), do: false
end
