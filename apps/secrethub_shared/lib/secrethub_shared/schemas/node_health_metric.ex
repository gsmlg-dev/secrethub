defmodule SecretHub.Shared.Schemas.NodeHealthMetric do
  @moduledoc """
  Schema for node health metrics.

  Stores health check results for cluster nodes over time, enabling:
  - Historical health tracking
  - Performance trend analysis
  - Alert evaluation
  - Debugging and diagnostics
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @type health_status :: :healthy | :degraded | :unhealthy

  schema "node_health_metrics" do
    field(:node_id, :string)
    field(:timestamp, :utc_datetime)
    field(:health_status, :string)
    field(:cpu_percent, :float)
    field(:memory_percent, :float)
    field(:database_latency_ms, :float)
    field(:active_connections, :integer)
    field(:vault_sealed, :boolean)
    field(:vault_initialized, :boolean)
    field(:last_heartbeat_at, :utc_datetime)
    field(:metadata, :map, default: %{})

    timestamps(type: :utc_datetime)
  end

  @doc """
  Changeset for creating/updating node health metrics.
  """
  def changeset(metric, attrs) do
    metric
    |> cast(attrs, [
      :node_id,
      :timestamp,
      :health_status,
      :cpu_percent,
      :memory_percent,
      :database_latency_ms,
      :active_connections,
      :vault_sealed,
      :vault_initialized,
      :last_heartbeat_at,
      :metadata
    ])
    |> validate_required([:node_id, :timestamp, :health_status])
    |> validate_inclusion(:health_status, ["healthy", "degraded", "unhealthy"])
    |> validate_number(:cpu_percent, greater_than_or_equal_to: 0, less_than_or_equal_to: 100)
    |> validate_number(:memory_percent,
      greater_than_or_equal_to: 0,
      less_than_or_equal_to: 100
    )
    |> validate_number(:database_latency_ms, greater_than_or_equal_to: 0)
    |> validate_number(:active_connections, greater_than_or_equal_to: 0)
  end
end
