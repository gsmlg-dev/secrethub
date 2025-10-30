defmodule SecretHub.Shared.Schemas.HealthAlert do
  @moduledoc """
  Schema for health alert configurations.

  Defines alert rules that monitor node health metrics and trigger
  notifications when thresholds are exceeded.

  Alert types:
  - node_down: Node hasn't sent heartbeat
  - high_cpu: CPU usage exceeds threshold
  - high_memory: Memory usage exceeds threshold
  - database_latency: Database latency exceeds threshold
  - vault_sealed: Vault is sealed when it should be unsealed
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @alert_types ~w(node_down high_cpu high_memory database_latency vault_sealed)
  @threshold_operators ~w(> < == !=)
  @notification_channels ~w(email slack webhook)

  schema "health_alerts" do
    field(:name, :string)
    field(:alert_type, :string)
    field(:threshold_value, :float)
    field(:threshold_operator, :string)
    field(:enabled, :boolean, default: true)
    field(:cooldown_minutes, :integer, default: 5)
    field(:last_triggered_at, :utc_datetime)
    field(:notification_channels, {:array, :string}, default: [])
    field(:metadata, :map, default: %{})

    timestamps(type: :utc_datetime)
  end

  @doc """
  Changeset for creating/updating health alerts.
  """
  def changeset(alert, attrs) do
    alert
    |> cast(attrs, [
      :name,
      :alert_type,
      :threshold_value,
      :threshold_operator,
      :enabled,
      :cooldown_minutes,
      :last_triggered_at,
      :notification_channels,
      :metadata
    ])
    |> validate_required([:name, :alert_type, :enabled, :cooldown_minutes])
    |> validate_inclusion(:alert_type, @alert_types)
    |> validate_inclusion(:threshold_operator, @threshold_operators, allow_nil: true)
    |> validate_number(:cooldown_minutes, greater_than_or_equal_to: 0)
    |> validate_notification_channels(@notification_channels)
    |> unique_constraint(:name)
    |> validate_threshold_fields()
  end

  # Private validation functions

  defp validate_threshold_fields(changeset) do
    alert_type = get_field(changeset, :alert_type)

    case alert_type do
      type when type in ["high_cpu", "high_memory", "database_latency"] ->
        changeset
        |> validate_required([:threshold_value, :threshold_operator])
        |> validate_number(:threshold_value, greater_than: 0)

      _ ->
        changeset
    end
  end

  defp validate_notification_channels(changeset, valid_values) do
    channels = get_field(changeset, :notification_channels) || []

    invalid_channels = Enum.reject(channels, &(&1 in valid_values))

    if Enum.empty?(invalid_channels) do
      changeset
    else
      add_error(
        changeset,
        :notification_channels,
        "contains invalid values: #{Enum.join(invalid_channels, ", ")}"
      )
    end
  end

  @doc """
  Returns the list of valid alert types.
  """
  def alert_types, do: @alert_types

  @doc """
  Returns the list of valid threshold operators.
  """
  def threshold_operators, do: @threshold_operators

  @doc """
  Returns the list of valid notification channels.
  """
  def notification_channels, do: @notification_channels
end
