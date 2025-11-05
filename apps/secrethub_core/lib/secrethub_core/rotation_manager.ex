defmodule SecretHub.Core.RotationManager do
  @moduledoc """
  Context for managing secret rotation schedules and history.

  Provides CRUD operations for rotation schedules and tracks rotation history.
  """

  import Ecto.Query
  require Logger

  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.{RotationSchedule, RotationHistory}

  ## Rotation Schedule Management

  @doc """
  Lists all rotation schedules.

  ## Options
  - `:enabled_only` - Only return enabled schedules (default: false)
  """
  def list_schedules(opts \\ []) do
    query = from(s in RotationSchedule, order_by: [desc: s.inserted_at])

    query =
      if Keyword.get(opts, :enabled_only, false) do
        where(query, [s], s.enabled == true)
      else
        query
      end

    Repo.all(query)
  end

  @doc """
  Gets a single rotation schedule by ID.
  """
  def get_schedule(id) do
    case Repo.get(RotationSchedule, id) do
      nil -> {:error, :not_found}
      schedule -> {:ok, schedule}
    end
  end

  @doc """
  Creates a rotation schedule.
  """
  def create_schedule(attrs) do
    %RotationSchedule{}
    |> RotationSchedule.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Updates a rotation schedule.
  """
  def update_schedule(%RotationSchedule{} = schedule, attrs) do
    schedule
    |> RotationSchedule.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Deletes a rotation schedule.
  """
  def delete_schedule(%RotationSchedule{} = schedule) do
    Repo.delete(schedule)
  end

  @doc """
  Enables a rotation schedule.
  """
  def enable_schedule(id) when is_binary(id) do
    with {:ok, schedule} <- get_schedule(id) do
      update_schedule(schedule, %{enabled: true})
    end
  end

  @doc """
  Disables a rotation schedule.
  """
  def disable_schedule(id) when is_binary(id) do
    with {:ok, schedule} <- get_schedule(id) do
      update_schedule(schedule, %{enabled: false})
    end
  end

  @doc """
  Gets schedules that are due for rotation.
  """
  def get_due_schedules do
    now = DateTime.utc_now()

    query =
      from(s in RotationSchedule,
        where: s.enabled == true,
        where: is_nil(s.next_rotation_at) or s.next_rotation_at <= ^now,
        order_by: [asc: s.next_rotation_at]
      )

    Repo.all(query)
  end

  @doc """
  Calculates the next rotation time for a schedule based on its cron expression.
  """
  def calculate_next_rotation(schedule) do
    try do
      case Crontab.Scheduler.get_next_run_date(schedule.schedule_cron) do
        {:ok, next_run} ->
          {:ok, DateTime.from_naive!(next_run, "Etc/UTC")}

        {:error, reason} ->
          {:error, reason}
      end
    rescue
      _ -> {:error, "Failed to calculate next rotation time"}
    end
  end

  @doc """
  Updates the next rotation time for a schedule.
  """
  def update_next_rotation(schedule) do
    case calculate_next_rotation(schedule) do
      {:ok, next_rotation_at} ->
        update_schedule(schedule, %{next_rotation_at: next_rotation_at})

      {:error, _reason} = error ->
        error
    end
  end

  ## Rotation History Management

  @doc """
  Lists rotation history for a schedule.

  ## Options
  - `:limit` - Maximum number of records (default: 100)
  - `:status` - Filter by status
  """
  def list_history(schedule_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, 100)

    query =
      from(h in RotationHistory,
        where: h.rotation_schedule_id == ^schedule_id,
        order_by: [desc: h.started_at],
        limit: ^limit
      )

    query =
      if status = Keyword.get(opts, :status) do
        where(query, [h], h.status == ^status)
      else
        query
      end

    Repo.all(query)
  end

  @doc """
  Creates a rotation history record.
  """
  def create_history(attrs) do
    %RotationHistory{}
    |> RotationHistory.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Updates a rotation history record.
  """
  def update_history(%RotationHistory{} = history, attrs) do
    history
    |> RotationHistory.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Gets rotation statistics for a schedule.
  """
  def get_rotation_stats(schedule_id) do
    query =
      from(h in RotationHistory,
        where: h.rotation_schedule_id == ^schedule_id,
        select: %{
          total: count(h.id),
          successful: fragment("COUNT(CASE WHEN ? = 'success' THEN 1 END)", h.status),
          failed: fragment("COUNT(CASE WHEN ? = 'failed' THEN 1 END)", h.status),
          avg_duration: avg(h.duration_ms)
        }
      )

    case Repo.one(query) do
      nil ->
        %{total: 0, successful: 0, failed: 0, avg_duration: nil, success_rate: 0.0}

      result ->
        success_rate =
          if result.total > 0 do
            result.successful / result.total * 100
          else
            0.0
          end

        %{
          total: result.total,
          successful: result.successful,
          failed: result.failed,
          avg_duration: result.avg_duration && Float.round(result.avg_duration, 2),
          success_rate: Float.round(success_rate, 2)
        }
    end
  end

  @doc """
  Performs a rotation for the given schedule.
  """
  def perform_rotation(schedule, opts \\ []) do
    # Create history record
    {:ok, history} =
      create_history(%{
        rotation_schedule_id: schedule.id,
        started_at: DateTime.utc_now(),
        status: :in_progress,
        metadata: %{}
      })

    start_time = System.monotonic_time(:millisecond)

    # Get the rotation engine module
    engine_module = get_rotation_engine(schedule.rotation_type)

    # Perform the rotation
    result =
      try do
        engine_module.rotate(schedule, opts)
      rescue
        e ->
          {:error, Exception.message(e)}
      end

    duration_ms = System.monotonic_time(:millisecond) - start_time

    # Update history based on result
    case result do
      {:ok, rotation_result} ->
        {:ok, history} =
          update_history(history, %{
            completed_at: DateTime.utc_now(),
            status: :success,
            old_version: rotation_result.old_version,
            new_version: rotation_result.new_version,
            duration_ms: duration_ms,
            metadata: rotation_result[:metadata] || %{}
          })

        # Update schedule
        {:ok, schedule} =
          update_schedule(schedule, %{
            last_rotation_at: DateTime.utc_now(),
            last_rotation_status: :success,
            last_rotation_error: nil,
            rotation_count: schedule.rotation_count + 1
          })

        # Calculate and update next rotation time
        update_next_rotation(schedule)

        {:ok, history}

      {:error, reason} ->
        {:ok, history} =
          update_history(history, %{
            completed_at: DateTime.utc_now(),
            status: :failed,
            error_message: to_string(reason),
            duration_ms: duration_ms
          })

        # Update schedule
        update_schedule(schedule, %{
          last_rotation_at: DateTime.utc_now(),
          last_rotation_status: :failed,
          last_rotation_error: to_string(reason)
        })

        {:error, reason, history}
    end
  end

  defp get_rotation_engine(:database_password), do: SecretHub.Core.Rotation.DatabasePassword
  defp get_rotation_engine(type), do: raise("Unknown rotation type: #{type}")
end
