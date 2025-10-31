defmodule SecretHub.Shared.Schemas.RotationSchedule do
  @moduledoc """
  Schema for automatic secret rotation schedules.

  Rotation schedules define when and how secrets should be automatically rotated.
  Supports various rotation types including database passwords, AWS IAM keys,
  API keys, and other long-lived credentials.

  ## Rotation Types

  - `:database_password` - Rotate database user passwords
  - `:aws_iam_key` - Rotate AWS IAM access keys
  - `:api_key` - Rotate API keys in external systems
  - `:service_account` - Rotate service account credentials

  ## Target Types

  - `:database` - Database system (PostgreSQL, MySQL, etc.)
  - `:aws_account` - AWS account
  - `:external_service` - External API or service

  ## Schedule Format

  Uses cron syntax for scheduling rotations:
  - `0 2 * * *` - Daily at 2 AM
  - `0 0 * * 0` - Weekly on Sunday at midnight
  - `0 0 1 * *` - Monthly on the 1st at midnight
  """

  use Ecto.Schema
  import Ecto.Changeset

  @rotation_types [:database_password, :aws_iam_key, :api_key, :service_account]
  @target_types [:database, :aws_account, :external_service]
  @rotation_statuses [:success, :failed, :in_progress, :pending]

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "rotation_schedules" do
    field :name, :string
    field :description, :string
    field :rotation_type, Ecto.Enum, values: @rotation_types
    field :target_type, Ecto.Enum, values: @target_types
    field :target_id, :binary_id
    field :config, :map
    field :schedule_cron, :string
    field :enabled, :boolean, default: true
    field :grace_period_seconds, :integer, default: 300
    field :last_rotation_at, :utc_datetime
    field :last_rotation_status, Ecto.Enum, values: @rotation_statuses
    field :last_rotation_error, :string
    field :next_rotation_at, :utc_datetime
    field :rotation_count, :integer, default: 0
    field :metadata, :map

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(rotation_schedule, attrs) do
    rotation_schedule
    |> cast(attrs, [
      :name,
      :description,
      :rotation_type,
      :target_type,
      :target_id,
      :config,
      :schedule_cron,
      :enabled,
      :grace_period_seconds,
      :last_rotation_at,
      :last_rotation_status,
      :last_rotation_error,
      :next_rotation_at,
      :rotation_count,
      :metadata
    ])
    |> validate_required([:name, :rotation_type, :target_type, :config, :schedule_cron])
    |> validate_inclusion(:rotation_type, @rotation_types)
    |> validate_inclusion(:target_type, @target_types)
    |> validate_cron_expression(:schedule_cron)
    |> validate_number(:grace_period_seconds, greater_than_or_equal_to: 0)
    |> validate_number(:rotation_count, greater_than_or_equal_to: 0)
    |> unique_constraint(:name)
  end

  defp validate_cron_expression(changeset, field) do
    validate_change(changeset, field, fn _, cron ->
      try do
        case Crontab.CronExpression.Parser.parse(cron) do
          {:ok, _} -> []
          {:error, _} -> [{field, "is not a valid cron expression"}]
        end
      rescue
        _ -> [{field, "is not a valid cron expression"}]
      end
    end)
  end
end
