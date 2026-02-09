defmodule SecretHub.Shared.Schemas.AnomalyDetectionRule do
  @moduledoc """
  Schema for anomaly detection rules.

  Defines rules for detecting unusual activity in audit logs and system behavior.
  Supports multiple rule types like failed_login_threshold, bulk_deletion, etc.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @rule_types [
    :failed_login_threshold,
    :bulk_deletion,
    :unusual_access_time,
    :mass_secret_access,
    :credential_export_spike,
    :rotation_failure_rate,
    :policy_violation,
    :custom
  ]

  @severities [:critical, :high, :medium, :low, :info]

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "anomaly_detection_rules" do
    field(:name, :string)
    field(:description, :string)
    field(:rule_type, Ecto.Enum, values: @rule_types)
    field(:enabled, :boolean, default: true)
    field(:severity, Ecto.Enum, values: @severities, default: :medium)
    field(:condition, :map)
    field(:threshold, :map, default: %{})
    field(:alert_on_trigger, :boolean, default: true)
    field(:cooldown_minutes, :integer, default: 60)
    field(:last_triggered_at, :utc_datetime)
    field(:trigger_count, :integer, default: 0)
    field(:metadata, :map, default: %{})

    timestamps(type: :utc_datetime)
  end

  @doc """
  Creates a changeset for creating a detection rule.
  """
  def changeset(rule, attrs) do
    rule
    |> cast(attrs, [
      :name,
      :description,
      :rule_type,
      :enabled,
      :severity,
      :condition,
      :threshold,
      :alert_on_trigger,
      :cooldown_minutes,
      :metadata
    ])
    |> validate_required([:name, :rule_type, :condition])
    |> validate_inclusion(:rule_type, @rule_types)
    |> validate_inclusion(:severity, @severities)
    |> validate_number(:cooldown_minutes, greater_than_or_equal_to: 0)
    |> validate_condition_structure()
    |> unique_constraint(:name)
  end

  @doc """
  Updates a detection rule.
  """
  def update_changeset(rule, attrs) do
    rule
    |> cast(attrs, [
      :description,
      :enabled,
      :severity,
      :condition,
      :threshold,
      :alert_on_trigger,
      :cooldown_minutes,
      :metadata
    ])
    |> validate_inclusion(:severity, @severities)
    |> validate_number(:cooldown_minutes, greater_than_or_equal_to: 0)
    |> validate_condition_structure()
  end

  @doc """
  Records that the rule was triggered at the current time.
  """
  def record_trigger(rule) do
    rule
    |> change(
      last_triggered_at: DateTime.utc_now() |> DateTime.truncate(:second),
      trigger_count: (rule.trigger_count || 0) + 1
    )
  end

  @doc """
  Checks if the rule is on cooldown.
  """
  def on_cooldown?(rule) do
    if rule.last_triggered_at && rule.cooldown_minutes && rule.cooldown_minutes > 0 do
      cooldown_until = DateTime.add(rule.last_triggered_at, rule.cooldown_minutes * 60, :second)
      DateTime.compare(DateTime.utc_now() |> DateTime.truncate(:second), cooldown_until) == :lt
    else
      false
    end
  end

  @doc """
  Gets the condition type (metric being monitored).
  """
  def condition_type(rule) do
    get_in(rule.condition, ["type"])
  end

  @doc """
  Gets the condition operator (e.g., :greater_than, :less_than).
  """
  def condition_operator(rule) do
    operator_str = get_in(rule.condition, ["operator"])
    if operator_str, do: String.to_existing_atom(operator_str), else: nil
  end

  @doc """
  Gets the condition value to compare against.
  """
  def condition_value(rule) do
    get_in(rule.condition, ["value"])
  end

  defp validate_condition_structure(changeset) do
    condition = get_field(changeset, :condition)

    if is_map(condition) and Map.has_key?(condition, "type") and
         Map.has_key?(condition, "operator") do
      changeset
    else
      add_error(changeset, :condition, "must be a map with 'type' and 'operator' keys")
    end
  end

  @doc """
  Toggle the enabled status of an anomaly detection rule.
  """
  def toggle(rule) do
    changeset(rule, %{enabled: !rule.enabled})
  end
end
