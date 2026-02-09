defmodule SecretHub.Shared.Schemas.AnomalyAlert do
  @moduledoc """
  Schema for anomaly detection alerts.

  Records individual alerts triggered by anomaly detection rules.
  Includes context about what triggered the alert and resolution information.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @severities [:critical, :high, :medium, :low, :info]
  @statuses [:open, :acknowledged, :investigating, :resolved, :false_positive]

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "anomaly_alerts" do
    field(:triggered_at, :utc_datetime)
    field(:severity, Ecto.Enum, values: @severities)
    field(:status, Ecto.Enum, values: @statuses, default: :open)
    field(:description, :string)
    field(:context, :map, default: %{})
    field(:resolved_at, :utc_datetime)
    field(:resolved_by, :string)
    field(:resolution_notes, :string)
    field(:metadata, :map, default: %{})

    belongs_to(:rule, SecretHub.Shared.Schemas.AnomalyDetectionRule)

    timestamps(type: :utc_datetime, updated_at: false)
  end

  @doc """
  Creates a changeset for creating an alert.
  """
  def changeset(alert, attrs) do
    alert
    |> cast(attrs, [
      :rule_id,
      :triggered_at,
      :severity,
      :description,
      :context,
      :metadata
    ])
    |> validate_required([:triggered_at, :severity, :description])
    |> validate_inclusion(:severity, @severities)
    |> foreign_key_constraint(:rule_id)
  end

  @doc """
  Updates alert status and resolution information.
  """
  def resolve(alert, status, opts \\ []) do
    resolved_by = Keyword.get(opts, :resolved_by)
    notes = Keyword.get(opts, :notes)

    alert
    |> change(
      status: status,
      resolved_at: DateTime.utc_now() |> DateTime.truncate(:second),
      resolved_by: resolved_by,
      resolution_notes: notes
    )
  end

  @doc """
  Marks an alert as acknowledged.
  """
  def acknowledge(alert) do
    change(alert, status: :acknowledged)
  end

  @doc """
  Marks an alert as being investigated.
  """
  def start_investigation(alert) do
    change(alert, status: :investigating)
  end

  @doc """
  Marks an alert as a false positive.
  """
  def mark_false_positive(alert, notes) do
    resolve(alert, :false_positive, notes: notes)
  end

  @doc """
  Checks if alert needs attention (not yet resolved).
  """
  def needs_attention?(alert) do
    alert.status in [:open, :acknowledged, :investigating]
  end

  @doc """
  Gets the time since alert was triggered.
  """
  def time_since_triggered(alert) do
    DateTime.diff(DateTime.utc_now() |> DateTime.truncate(:second), alert.triggered_at, :second)
  end

  @doc """
  Checks if alert is critical and unresolved.
  """
  def critical_unresolved?(alert) do
    alert.severity == :critical and needs_attention?(alert)
  end
end
