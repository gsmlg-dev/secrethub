defmodule SecretHub.Core.Workers.RotationWorker do
  @moduledoc """
  Oban worker for executing scheduled secret rotations.

  This worker is triggered by the rotation scheduler to perform rotations
  for secrets that are due to rotate based on their cron schedule.

  ## Configuration

  The worker supports the following options:
  - `:max_attempts` - Number of retry attempts (default: 3)
  - `:priority` - Job priority (default: 1)
  - `:queue` - The queue name (default: :rotation)

  ## Job Arguments

  - `rotator_id` - The ID of the per-secret rotator to execute
  - `schedule_id` - Legacy rotation schedule ID, still accepted during migration

  ## Example

      # Enqueue a rotation job
      %{rotator_id: rotator.id}
      |> RotationWorker.new()
      |> Oban.insert()

  ## Retries

  Failed rotations will be retried up to 3 times with exponential backoff.
  If all retries fail, the schedule's last_rotation_status will be set to :failed.

  ## Observability

  - Logs rotation start and completion
  - Records rotation history for audit trail
  - Updates schedule metadata with rotation results
  """

  use Oban.Worker,
    queue: :rotation,
    max_attempts: 3,
    priority: 1

  require Logger

  alias SecretHub.Core.RotationManager
  alias SecretHub.Shared.Schemas.{RotationSchedule, SecretRotator}

  @impl Oban.Worker
  def perform(%Oban.Job{args: %{"rotator_id" => rotator_id}}) do
    Logger.info("Starting rotator job", rotator_id: rotator_id)

    with {:ok, rotator} <- SecretHub.Core.Secrets.get_secret_rotator(rotator_id),
         :ok <- validate_rotator_enabled(rotator),
         {:ok, _history} <- RotationManager.perform_rotation(rotator, []) do
      Logger.info("Rotator job completed successfully",
        rotator_id: rotator_id,
        rotator_name: rotator.name
      )

      :ok
    else
      {:error, :not_found} ->
        Logger.warning("Rotator not found", rotator_id: rotator_id)
        {:discard, :rotator_not_found}

      {:error, :rotator_disabled} ->
        Logger.warning("Rotator is disabled", rotator_id: rotator_id)
        {:discard, :rotator_disabled}

      {:error, reason, _history} ->
        Logger.error("Rotator job failed",
          rotator_id: rotator_id,
          reason: inspect(reason)
        )

        {:error, reason}

      {:error, reason} ->
        Logger.error("Rotator job failed",
          rotator_id: rotator_id,
          reason: inspect(reason)
        )

        {:error, reason}
    end
  end

  @impl Oban.Worker
  def perform(%Oban.Job{args: %{"schedule_id" => schedule_id}}) do
    Logger.info("Starting rotation job", schedule_id: schedule_id)

    with {:ok, schedule} <- RotationManager.get_schedule(schedule_id),
         :ok <- validate_schedule_enabled(schedule),
         {:ok, _history} <- RotationManager.perform_rotation(schedule) do
      Logger.info("Rotation job completed successfully",
        schedule_id: schedule_id,
        schedule_name: schedule.name
      )

      :ok
    else
      {:error, :not_found} ->
        Logger.warning("Rotation schedule not found", schedule_id: schedule_id)
        {:discard, :schedule_not_found}

      {:error, :schedule_disabled} ->
        Logger.warning("Rotation schedule is disabled", schedule_id: schedule_id)
        {:discard, :schedule_disabled}

      {:error, reason, _history} ->
        Logger.error("Rotation job failed",
          schedule_id: schedule_id,
          reason: inspect(reason)
        )

        {:error, reason}

      {:error, reason} ->
        Logger.error("Rotation job failed",
          schedule_id: schedule_id,
          reason: inspect(reason)
        )

        {:error, reason}
    end
  end

  @impl Oban.Worker
  def perform(%Oban.Job{args: args}) do
    Logger.error("Invalid rotation job arguments", args: inspect(args))
    {:discard, :invalid_arguments}
  end

  @doc """
  Schedules a rotation for the given per-secret rotator or legacy schedule.

  Returns `{:ok, job}` on success or `{:error, changeset}` on failure.
  """
  def schedule_rotation(rotation_target, opts \\ [])

  def schedule_rotation(%SecretRotator{} = rotator, opts) do
    scheduled_at = Keyword.get(opts, :scheduled_at)

    args = %{rotator_id: rotator.id}

    job =
      if scheduled_at do
        new(args, scheduled_at: scheduled_at)
      else
        new(args)
      end

    Oban.insert(job)
  end

  def schedule_rotation(%RotationSchedule{} = schedule, opts) do
    scheduled_at = Keyword.get(opts, :scheduled_at)

    args = %{schedule_id: schedule.id}

    job =
      if scheduled_at do
        new(args, scheduled_at: scheduled_at)
      else
        new(args)
      end

    Oban.insert(job)
  end

  @doc """
  Schedules all due rotations.

  This is typically called by a periodic scheduler to check for
  schedules that need to be rotated.

  Returns the number of jobs scheduled.
  """
  def schedule_due_rotations do
    due_rotators = RotationManager.get_due_rotators()
    due_schedules = RotationManager.get_due_schedules()
    due_targets = due_rotators ++ due_schedules

    Logger.info("Scheduling due rotations", count: length(due_targets))

    results =
      Enum.map(due_targets, fn target ->
        schedule_rotation(target)
      end)

    success_count =
      Enum.count(results, fn
        {:ok, _job} -> true
        _ -> false
      end)

    Logger.info("Scheduled rotations",
      total: length(due_targets),
      successful: success_count,
      failed: length(due_targets) - success_count
    )

    success_count
  end

  defp validate_rotator_enabled(rotator) do
    if rotator.enabled do
      :ok
    else
      {:error, :rotator_disabled}
    end
  end

  defp validate_schedule_enabled(schedule) do
    if schedule.enabled do
      :ok
    else
      {:error, :schedule_disabled}
    end
  end
end
