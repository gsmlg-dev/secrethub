defmodule SecretHub.Core.AnomalyDetection do
  @moduledoc """
  Anomaly detection engine for identifying suspicious activity.

  Monitors audit logs and system metrics in real-time to detect anomalies
  based on configurable rules. Triggers alerts when anomalies are detected.

  ## Supported Rule Types

  - `:failed_login_threshold` - Too many failed login attempts
  - `:bulk_deletion` - Large number of deletions in short time
  - `:unusual_access_time` - Access outside normal hours
  - `:mass_secret_access` - Large number of secrets accessed
  - `:credential_export_spike` - Unusual credential generation rate
  - `:rotation_failure_rate` - High rotation failure rate
  - `:policy_violation` - Policy check failures
  - `:custom` - Custom rule logic

  ## Example

      # Check an audit event against all rules
      AnomalyDetection.check_event(audit_log)

      # Evaluate a specific rule
      AnomalyDetection.evaluate_rule(rule, context)
  """

  require Logger

  alias SecretHub.Core.{Alerting, Repo}
  alias SecretHub.Shared.Schemas.AnomalyDetectionRule

  import Ecto.Query

  @doc """
  Checks an audit event against all enabled detection rules.
  Returns list of triggered alerts.
  """
  def check_event(audit_log) do
    rules = list_enabled_rules()

    triggered_alerts =
      rules
      |> Enum.filter(&should_evaluate?(&1, audit_log))
      |> Enum.filter(&(!AnomalyDetectionRule.on_cooldown?(&1)))
      |> Enum.flat_map(&evaluate_rule(&1, audit_log))

    triggered_alerts
  end

  @doc """
  Lists all enabled anomaly detection rules.
  """
  def list_enabled_rules do
    AnomalyDetectionRule
    |> where([r], r.enabled == true)
    |> Repo.all()
  end

  @doc """
  Evaluates a specific rule against the provided context.
  """
  def evaluate_rule(rule, context) do
    case rule.rule_type do
      :failed_login_threshold -> check_failed_login_threshold(rule, context)
      :bulk_deletion -> check_bulk_deletion(rule, context)
      :unusual_access_time -> check_unusual_access_time(rule, context)
      :mass_secret_access -> check_mass_secret_access(rule, context)
      :credential_export_spike -> check_credential_export_spike(rule, context)
      :rotation_failure_rate -> check_rotation_failure_rate(rule, context)
      :policy_violation -> check_policy_violation(rule, context)
      :custom -> check_custom_rule(rule, context)
      _ -> []
    end
  end

  @doc """
  Creates an anomaly alert and triggers notifications.
  """
  def trigger_alert(rule, context, description) do
    Logger.warning("Anomaly detected",
      rule: rule.name,
      severity: rule.severity,
      description: description
    )

    # Create alert
    {:ok, alert} =
      Alerting.create_anomaly_alert(%{
        rule_id: rule.id,
        triggered_at: DateTime.utc_now() |> DateTime.truncate(:second),
        severity: rule.severity,
        description: description,
        context: context
      })

    # Update rule trigger count
    rule
    |> AnomalyDetectionRule.record_trigger()
    |> Repo.update()

    # Send notifications if configured
    if rule.alert_on_trigger do
      Alerting.route_alert(alert)
    end

    [alert]
  end

  # Rule-specific implementations

  defp check_failed_login_threshold(rule, context) do
    threshold = get_threshold(rule, "count", 5)
    window_minutes = get_threshold(rule, "window_minutes", 15)

    # Check if this is a failed login event
    if context.action == "login" and context.result == :failure do
      # Count recent failed logins for this actor
      count =
        count_recent_events(
          "login",
          :failure,
          context.actor_id,
          window_minutes
        )

      if count >= threshold do
        trigger_alert(
          rule,
          %{actor_id: context.actor_id, failed_count: count, window_minutes: window_minutes},
          "Failed login threshold exceeded: #{count} failures in #{window_minutes} minutes for #{context.actor_id}"
        )
      else
        []
      end
    else
      []
    end
  end

  defp check_bulk_deletion(rule, context) do
    threshold = get_threshold(rule, "count", 10)
    window_minutes = get_threshold(rule, "window_minutes", 5)

    if context.action == "delete" do
      count =
        count_recent_events(
          "delete",
          :success,
          context.actor_id,
          window_minutes
        )

      if count >= threshold do
        trigger_alert(
          rule,
          %{actor_id: context.actor_id, deletion_count: count, window_minutes: window_minutes},
          "Bulk deletion detected: #{count} deletions in #{window_minutes} minutes by #{context.actor_id}"
        )
      else
        []
      end
    else
      []
    end
  end

  defp check_unusual_access_time(rule, context) do
    allowed_start_hour = get_threshold(rule, "start_hour", 6)
    allowed_end_hour = get_threshold(rule, "end_hour", 22)

    current_hour = (DateTime.utc_now() |> DateTime.truncate(:second)).hour

    if current_hour < allowed_start_hour or current_hour >= allowed_end_hour do
      trigger_alert(
        rule,
        %{
          actor_id: context.actor_id,
          access_hour: current_hour,
          allowed_hours: "#{allowed_start_hour}-#{allowed_end_hour}"
        },
        "Unusual access time detected: #{context.actor_id} accessed at hour #{current_hour} UTC"
      )
    else
      []
    end
  end

  defp check_mass_secret_access(rule, context) do
    threshold = get_threshold(rule, "count", 20)
    window_minutes = get_threshold(rule, "window_minutes", 10)

    if context.action == "read" and context.resource_type == "secret" do
      count =
        count_recent_events(
          "read",
          :success,
          context.actor_id,
          window_minutes,
          "secret"
        )

      if count >= threshold do
        trigger_alert(
          rule,
          %{actor_id: context.actor_id, secret_count: count, window_minutes: window_minutes},
          "Mass secret access detected: #{count} secrets accessed in #{window_minutes} minutes by #{context.actor_id}"
        )
      else
        []
      end
    else
      []
    end
  end

  defp check_credential_export_spike(rule, context) do
    threshold = get_threshold(rule, "count", 50)
    window_minutes = get_threshold(rule, "window_minutes", 5)

    if context.action == "generate_credentials" do
      count =
        count_recent_events(
          "generate_credentials",
          :success,
          context.actor_id,
          window_minutes
        )

      if count >= threshold do
        trigger_alert(
          rule,
          %{actor_id: context.actor_id, credential_count: count, window_minutes: window_minutes},
          "Credential export spike detected: #{count} credentials generated in #{window_minutes} minutes"
        )
      else
        []
      end
    else
      []
    end
  end

  defp check_rotation_failure_rate(rule, context) do
    threshold_percent = get_threshold(rule, "failure_percent", 50)
    window_minutes = get_threshold(rule, "window_minutes", 60)

    if context.action == "rotate_secret" do
      {success_count, failure_count} = count_rotation_results(window_minutes)
      total = success_count + failure_count

      if total > 0 do
        failure_percent = failure_count * 100 / total

        if failure_percent >= threshold_percent do
          trigger_alert(
            rule,
            %{
              success_count: success_count,
              failure_count: failure_count,
              failure_percent: failure_percent,
              window_minutes: window_minutes
            },
            "High rotation failure rate: #{Float.round(failure_percent, 1)}% failures (#{failure_count}/#{total})"
          )
        else
          []
        end
      else
        []
      end
    else
      []
    end
  end

  defp check_policy_violation(rule, context) do
    if context.event_type == "policy_violation" do
      trigger_alert(
        rule,
        context,
        "Policy violation detected: #{context.event_data["policy_name"]} by #{context.actor_id}"
      )
    else
      []
    end
  end

  defp check_custom_rule(rule, context) do
    # Custom rules would require code injection or safe evaluation
    # For now, we'll use simple condition matching
    condition_type = rule.condition["type"]
    operator = rule.condition["operator"]
    expected_value = rule.condition["value"]

    actual_value = get_context_value(context, condition_type)

    if evaluate_condition(actual_value, operator, expected_value) do
      trigger_alert(
        rule,
        context,
        "Custom rule triggered: #{rule.description}"
      )
    else
      []
    end
  end

  # Helper functions

  defp should_evaluate?(rule, context) do
    # Basic filtering - only evaluate if event type matches rule scope
    case rule.rule_type do
      :failed_login_threshold -> context.action == "login"
      :bulk_deletion -> context.action == "delete"
      :mass_secret_access -> context.resource_type == "secret"
      :credential_export_spike -> context.action == "generate_credentials"
      :rotation_failure_rate -> context.action == "rotate_secret"
      :policy_violation -> context.event_type == "policy_violation"
      _ -> true
    end
  end

  defp get_threshold(rule, key, default) do
    get_in(rule.threshold, [key]) || default
  end

  defp count_recent_events(action, result, actor_id, window_minutes, resource_type \\ nil) do
    # This would query the audit logs
    # Placeholder implementation
    cutoff =
      DateTime.add(
        DateTime.utc_now() |> DateTime.truncate(:second),
        -window_minutes * 60,
        :second
      )

    query =
      from(a in "audit_logs",
        where: a.action == ^action,
        where: a.result == ^to_string(result),
        where: a.actor_id == ^actor_id,
        where: a.timestamp >= ^cutoff
      )

    query =
      if resource_type do
        where(query, [a], a.resource_type == ^resource_type)
      else
        query
      end

    Repo.aggregate(query, :count)
  end

  defp count_rotation_results(window_minutes) do
    cutoff =
      DateTime.add(
        DateTime.utc_now() |> DateTime.truncate(:second),
        -window_minutes * 60,
        :second
      )

    success_count =
      from(a in "audit_logs",
        where: a.action == "rotate_secret",
        where: a.result == "success",
        where: a.timestamp >= ^cutoff
      )
      |> Repo.aggregate(:count)

    failure_count =
      from(a in "audit_logs",
        where: a.action == "rotate_secret",
        where: a.result == "failure",
        where: a.timestamp >= ^cutoff
      )
      |> Repo.aggregate(:count)

    {success_count, failure_count}
  end

  defp get_context_value(context, key) do
    Map.get(context, String.to_existing_atom(key))
  end

  defp evaluate_condition(actual, "equals", expected), do: actual == expected
  defp evaluate_condition(actual, "not_equals", expected), do: actual != expected
  defp evaluate_condition(actual, "greater_than", expected), do: actual > expected
  defp evaluate_condition(actual, "less_than", expected), do: actual < expected

  defp evaluate_condition(actual, "contains", expected),
    do: String.contains?(to_string(actual), expected)

  defp evaluate_condition(_actual, _operator, _expected), do: false
end
