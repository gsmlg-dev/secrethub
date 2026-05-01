defmodule SecretHub.Shared.Schemas.RotationHistory do
  @moduledoc """
  Schema for rotation history records.

  Tracks the history of all rotation attempts, including successes,
  failures, and rollbacks.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias SecretHub.Shared.Schemas.{RotationSchedule, SecretRotator}

  @rotation_statuses [:success, :failed, :in_progress, :rolled_back]

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "rotation_history" do
    belongs_to(:rotation_schedule, RotationSchedule)
    belongs_to(:rotator, SecretRotator)

    field(:started_at, :utc_datetime)
    field(:completed_at, :utc_datetime)
    field(:status, Ecto.Enum, values: @rotation_statuses)
    field(:old_version, :string)
    field(:new_version, :string)
    field(:error_message, :string)
    field(:rollback_performed, :boolean, default: false)
    field(:duration_ms, :integer)
    field(:metadata, :map)
  end

  @doc false
  def changeset(rotation_history, attrs) do
    rotation_history
    |> cast(attrs, [
      :rotation_schedule_id,
      :rotator_id,
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
    |> validate_required([:started_at, :status])
    |> validate_rotation_target()
    |> validate_inclusion(:status, @rotation_statuses)
    |> validate_number(:duration_ms, greater_than_or_equal_to: 0)
    |> foreign_key_constraint(:rotation_schedule_id)
    |> foreign_key_constraint(:rotator_id)
  end

  defp validate_rotation_target(changeset) do
    schedule_id = get_field(changeset, :rotation_schedule_id)
    rotator_id = get_field(changeset, :rotator_id)

    if schedule_id || rotator_id do
      changeset
    else
      add_error(changeset, :rotator_id, "or rotation schedule is required")
    end
  end
end
