defmodule SecretHub.Shared.Schemas.EngineHealthCheck do
  @moduledoc """
  Schema for engine health check history records.

  Stores historical health check results for monitoring engine
  reliability, performance, and availability over time.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias SecretHub.Shared.Schemas.EngineConfiguration

  @health_statuses [:healthy, :degraded, :unhealthy, :unknown]

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "engine_health_checks" do
    belongs_to(:engine_configuration, EngineConfiguration)

    field(:checked_at, :utc_datetime)
    field(:status, Ecto.Enum, values: @health_statuses)
    field(:response_time_ms, :integer)
    field(:error_message, :string)
    field(:metadata, :map)
  end

  @doc false
  def changeset(health_check, attrs) do
    health_check
    |> cast(attrs, [
      :engine_configuration_id,
      :checked_at,
      :status,
      :response_time_ms,
      :error_message,
      :metadata
    ])
    |> validate_required([:engine_configuration_id, :checked_at, :status])
    |> validate_inclusion(:status, @health_statuses)
    |> validate_number(:response_time_ms, greater_than_or_equal_to: 0)
    |> foreign_key_constraint(:engine_configuration_id)
  end
end
