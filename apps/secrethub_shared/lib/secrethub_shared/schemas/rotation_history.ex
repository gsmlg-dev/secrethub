defmodule SecretHub.Shared.Schemas.RotationHistory do
  @moduledoc """
  Schema for rotation history records.

  Tracks the history of all rotation attempts, including successes,
  failures, and rollbacks.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias SecretHub.Shared.Schemas.RotationSchedule

  @rotation_statuses [:success, :failed, :in_progress, :rolled_back]

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "rotation_history" do
    belongs_to :rotation_schedule, RotationSchedule

    field :started_at, :utc_datetime
    field :completed_at, :utc_datetime
    field :status, Ecto.Enum, values: @rotation_statuses
    field :old_version, :string
    field :new_version, :string
    field :error_message, :string
    field :rollback_performed, :boolean, default: false
    field :duration_ms, :integer
    field :metadata, :map
  end

  @doc false
  def changeset(rotation_history, attrs) do
    rotation_history
    |> cast(attrs, [
      :rotation_schedule_id,
      :started_at,
      :completed_at,
      :status,
      :old_version,
      :new_version,
      :error_message,
      :rollback_performed,
      :duration_ms,
      :metadata
    ])
    |> validate_required([:rotation_schedule_id, :started_at, :status])
    |> validate_inclusion(:status, @rotation_statuses)
    |> validate_number(:duration_ms, greater_than_or_equal_to: 0)
    |> foreign_key_constraint(:rotation_schedule_id)
  end
end
