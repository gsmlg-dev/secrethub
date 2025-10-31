defmodule SecretHub.Shared.Schemas.AuditArchivalJob do
  @moduledoc """
  Schema for tracking audit archival job execution.

  Records details about each archival job including what was archived,
  where it was stored, and the outcome.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @statuses [:success, :failed, :in_progress, :pending]

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "audit_archival_jobs" do
    field(:started_at, :utc_datetime)
    field(:completed_at, :utc_datetime)
    field(:status, Ecto.Enum, values: @statuses)
    field(:from_date, :utc_datetime)
    field(:to_date, :utc_datetime)
    field(:records_archived, :integer, default: 0)
    field(:archive_location, :string)
    field(:checksum, :string)
    field(:error_message, :string)
    field(:duration_ms, :integer)
    field(:metadata, :map, default: %{})

    belongs_to(:archival_config, SecretHub.Shared.Schemas.AuditArchivalConfig)

    timestamps(type: :utc_datetime, updated_at: false)
  end

  @doc """
  Creates a changeset for creating an archival job.
  """
  def changeset(job, attrs) do
    job
    |> cast(attrs, [
      :archival_config_id,
      :started_at,
      :status,
      :from_date,
      :to_date,
      :metadata
    ])
    |> validate_required([:archival_config_id, :started_at, :status, :from_date, :to_date])
    |> validate_inclusion(:status, @statuses)
    |> foreign_key_constraint(:archival_config_id)
  end

  @doc """
  Updates job with completion information.
  """
  def complete(job, opts \\ []) do
    status = Keyword.get(opts, :status, :success)
    error = Keyword.get(opts, :error)
    location = Keyword.get(opts, :location)
    records = Keyword.get(opts, :records, 0)
    checksum = Keyword.get(opts, :checksum)

    now = DateTime.utc_now()
    duration = DateTime.diff(now, job.started_at, :millisecond)

    job
    |> change(
      completed_at: now,
      status: status,
      error_message: error,
      archive_location: location,
      records_archived: records,
      checksum: checksum,
      duration_ms: duration
    )
  end

  @doc """
  Marks a job as in progress.
  """
  def mark_in_progress(job) do
    change(job, status: :in_progress)
  end

  @doc """
  Marks a job as failed with error message.
  """
  def mark_failed(job, error_message) do
    now = DateTime.utc_now()
    duration = DateTime.diff(now, job.started_at, :millisecond)

    change(job, status: :failed, error_message: error_message, duration_ms: duration)
  end
end
