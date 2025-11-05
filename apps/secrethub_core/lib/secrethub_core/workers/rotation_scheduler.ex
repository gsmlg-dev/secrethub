defmodule SecretHub.Core.Workers.RotationScheduler do
  @moduledoc """
  Oban worker that periodically checks for due rotations and schedules them.

  This worker runs on a cron schedule (typically every 5 minutes) and:
  1. Queries all enabled rotation schedules
  2. Identifies schedules that are due for rotation
  3. Enqueues RotationWorker jobs for each due schedule

  ## Configuration

  The worker is configured to run every 5 minutes using Oban's cron plugin.
  This can be adjusted in the Oban configuration:

      config :secrethub_core, Oban,
        plugins: [
          {Oban.Plugins.Cron,
           crontab: [
             {"*/5 * * * *", SecretHub.Core.Workers.RotationScheduler}
           ]}
        ]

  ## Behavior

  - Only one instance of this job runs at a time (via unique constraint)
  - Skips schedules that already have pending rotation jobs
  - Updates schedule metadata after scheduling jobs
  - Logs scheduling activity for observability

  ## Example Configuration

      # In config/config.exs
      config :secrethub_core, Oban,
        repo: SecretHub.Core.Repo,
        plugins: [
          {Oban.Plugins.Cron,
           crontab: [
             # Check for due rotations every 5 minutes
             {"*/5 * * * *", SecretHub.Core.Workers.RotationScheduler},
             # Daily cleanup of old rotation history (optional)
             {"0 2 * * *", SecretHub.Core.Workers.RotationCleanup}
           ]}
        ],
        queues: [
          rotation: 10,
          default: 20
        ]
  """

  use Oban.Worker,
    queue: :rotation,
    max_attempts: 1,
    unique: [period: 60, states: [:available, :scheduled, :executing]]

  require Logger

  alias SecretHub.Core.Workers.RotationWorker

  @impl Oban.Worker
  def perform(%Oban.Job{}) do
    Logger.info("Starting rotation scheduler check")

    start_time = System.monotonic_time(:millisecond)

    scheduled_count = RotationWorker.schedule_due_rotations()

    duration_ms = System.monotonic_time(:millisecond) - start_time

    Logger.info("Rotation scheduler check completed",
      scheduled: scheduled_count,
      duration_ms: duration_ms
    )

    :ok
  rescue
    error ->
      Logger.error("Rotation scheduler check failed",
        error: inspect(error),
        stacktrace: Exception.format_stacktrace(__STACKTRACE__)
      )

      {:error, error}
  end
end
