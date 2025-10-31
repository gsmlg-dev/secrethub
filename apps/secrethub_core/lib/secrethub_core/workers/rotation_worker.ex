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

  - `schedule_id` - The ID of the rotation schedule to execute

  ## Example

      # Enqueue a rotation job
      %{schedule_id: schedule.id}
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
  Schedules a rotation for the given schedule.

  Returns `{:ok, job}` on success or `{:error, changeset}` on failure.
  """
  def schedule_rotation(schedule, opts \\ []) do
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
    due_schedules = RotationManager.get_due_schedules()

    Logger.info("Scheduling due rotations", count: length(due_schedules))

    results =
      Enum.map(due_schedules, fn schedule ->
        schedule_rotation(schedule)
      end)

    success_count =
      Enum.count(results, fn
        {:ok, _job} -> true
        _ -> false
      end)

    Logger.info("Scheduled rotations",
      total: length(due_schedules),
      successful: success_count,
      failed: length(due_schedules) - success_count
    )

    success_count
  end

  defp validate_schedule_enabled(schedule) do
    if schedule.enabled do
      :ok
    else
      {:error, :schedule_disabled}
    end
  end
end
