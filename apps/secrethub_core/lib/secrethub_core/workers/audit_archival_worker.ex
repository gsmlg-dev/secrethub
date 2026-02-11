defmodule SecretHub.Core.Workers.AuditArchivalWorker do
  @moduledoc """
  Oban worker for archiving old audit logs to external storage (S3/GCS).

  This worker periodically archives audit logs that are older than the
  configured threshold to external storage, compresses them, computes
  checksums for integrity verification, and tracks the archival job.

  ## Configuration

  The worker is configured via AuditArchivalConfig and runs on a cron schedule.

  ## Archival Process

  1. Find logs older than archive_after_days
  2. Group by date range (daily batches)
  3. Export to JSON
  4. Compress with gzip
  5. Upload to configured provider (S3/GCS/Azure)
  6. Compute and store checksum
  7. Mark records as archived
  8. Track job completion

  ## Example

      # Schedule an archival job
      %{config_id: config.id}
      |> AuditArchivalWorker.new()
      |> Oban.insert()
  """

  use Oban.Worker,
    queue: :archival,
    max_attempts: 2,
    priority: 3

  require Logger

  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.{AuditArchivalConfig, AuditArchivalJob}
  alias SecretHub.Core.Audit

  @impl Oban.Worker
  def perform(%Oban.Job{args: %{"config_id" => config_id}}) do
    Logger.info("Starting audit archival job", config_id: config_id)

    with {:ok, config} <- get_config(config_id),
         :ok <- validate_config_enabled(config),
         {:ok, job} <- create_job(config),
         {:ok, logs} <- fetch_logs_to_archive(config),
         {:ok, archive_data} <- prepare_archive(logs),
         {:ok, location} <- upload_archive(config, archive_data),
         {:ok, checksum} <- compute_checksum(archive_data),
         :ok <- mark_logs_archived(logs),
         {:ok, _job} <- complete_job(job, location, checksum, length(logs)) do
      Logger.info("Audit archival completed successfully",
        config_id: config_id,
        records: length(logs),
        location: location
      )

      :ok
    else
      {:error, :not_found} ->
        Logger.warning("Archival config not found", config_id: config_id)
        {:discard, :config_not_found}

      {:error, :disabled} ->
        Logger.info("Archival config is disabled", config_id: config_id)
        {:discard, :config_disabled}

      {:error, reason} = error ->
        Logger.error("Audit archival failed",
          config_id: config_id,
          reason: inspect(reason)
        )

        error
    end
  end

  @impl Oban.Worker
  def perform(%Oban.Job{args: args}) do
    Logger.error("Invalid archival job arguments", args: inspect(args))
    {:discard, :invalid_arguments}
  end

  @doc """
  Schedules archival for all enabled configurations.
  """
  def schedule_archival do
    configs = list_enabled_configs()

    Logger.info("Scheduling archival for enabled configs", count: length(configs))

    results =
      Enum.map(configs, fn config ->
        %{config_id: config.id}
        |> new()
        |> Oban.insert()
      end)

    success_count =
      Enum.count(results, fn
        {:ok, _job} -> true
        _ -> false
      end)

    Logger.info("Archival jobs scheduled",
      total: length(configs),
      successful: success_count
    )

    success_count
  end

  defp get_config(config_id) do
    case Repo.get(AuditArchivalConfig, config_id) do
      nil -> {:error, :not_found}
      config -> {:ok, config}
    end
  end

  defp validate_config_enabled(config) do
    if config.enabled do
      :ok
    else
      {:error, :disabled}
    end
  end

  defp create_job(config) do
    cutoff_date =
      DateTime.add(
        DateTime.utc_now() |> DateTime.truncate(:second),
        -config.archive_after_days * 86400,
        :second
      )

    attrs = %{
      archival_config_id: config.id,
      started_at: DateTime.utc_now() |> DateTime.truncate(:second),
      status: :in_progress,
      from_date: DateTime.add(cutoff_date, -86400, :second),
      to_date: cutoff_date
    }

    %AuditArchivalJob{}
    |> AuditArchivalJob.changeset(attrs)
    |> Repo.insert()
  end

  defp fetch_logs_to_archive(config) do
    cutoff_date =
      DateTime.add(
        DateTime.utc_now() |> DateTime.truncate(:second),
        -config.archive_after_days * 86400,
        :second
      )

    # Fetch audit logs older than cutoff_date and not yet archived
    logs = Audit.list_logs_for_archival(cutoff_date, limit: 10_000)

    {:ok, logs}
  end

  defp prepare_archive(logs) do
    # Convert logs to JSON and compress
    json_data =
      logs
      |> Enum.map(&log_to_map/1)
      |> Jason.encode!()

    compressed_data = :zlib.gzip(json_data)

    {:ok, compressed_data}
  end

  defp log_to_map(log) do
    %{
      id: log.id,
      event_type: log.event_type,
      actor_type: log.actor_type,
      actor_id: log.actor_id,
      resource_type: log.resource_type,
      resource_id: log.resource_id,
      action: log.action,
      result: log.result,
      event_data: log.event_data,
      ip_address: log.ip_address,
      user_agent: log.user_agent,
      hash: log.hash,
      previous_hash: log.previous_hash,
      timestamp: log.timestamp
    }
  end

  defp upload_archive(config, archive_data) do
    case config.provider do
      :s3 -> upload_to_s3(config, archive_data)
      :gcs -> upload_to_gcs(config, archive_data)
      :azure_blob -> upload_to_azure(config, archive_data)
      _ -> {:error, :unsupported_provider}
    end
  end

  defp upload_to_s3(config, archive_data) do
    bucket = config.config["bucket"]
    region = config.config["region"]
    prefix = config.config["prefix"] || "audit-logs"

    filename = generate_filename()
    key = "#{prefix}/#{filename}"

    # Mock upload for now - will implement actual S3 upload
    Logger.info("Uploading to S3",
      bucket: bucket,
      region: region,
      key: key,
      size: byte_size(archive_data)
    )

    location = "s3://#{bucket}/#{key}"
    {:ok, location}
  end

  defp upload_to_gcs(config, archive_data) do
    bucket = config.config["bucket"]
    project_id = config.config["project_id"]
    prefix = config.config["prefix"] || "audit-logs"

    filename = generate_filename()
    path = "#{prefix}/#{filename}"

    # Mock upload for now - will implement actual GCS upload
    Logger.info("Uploading to GCS",
      bucket: bucket,
      project_id: project_id,
      path: path,
      size: byte_size(archive_data)
    )

    location = "gs://#{bucket}/#{path}"
    {:ok, location}
  end

  defp upload_to_azure(config, archive_data) do
    container = config.config["container"]
    account_name = config.config["account_name"]
    prefix = config.config["prefix"] || "audit-logs"

    filename = generate_filename()
    blob_name = "#{prefix}/#{filename}"

    # Mock upload for now - will implement actual Azure upload
    Logger.info("Uploading to Azure Blob",
      container: container,
      account_name: account_name,
      blob_name: blob_name,
      size: byte_size(archive_data)
    )

    location = "https://#{account_name}.blob.core.windows.net/#{container}/#{blob_name}"
    {:ok, location}
  end

  defp generate_filename do
    timestamp = DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_iso8601(:basic)
    "audit-logs-#{timestamp}.json.gz"
  end

  defp compute_checksum(data) do
    checksum =
      :crypto.hash(:sha256, data)
      |> Base.encode16(case: :lower)

    {:ok, checksum}
  end

  defp mark_logs_archived(logs) do
    log_ids = Enum.map(logs, & &1.id)

    # Update audit logs to mark them as archived
    Audit.mark_as_archived(log_ids)

    :ok
  end

  defp complete_job(job, location, checksum, record_count) do
    job
    |> AuditArchivalJob.complete(
      status: :success,
      location: location,
      checksum: checksum,
      records: record_count
    )
    |> Repo.update()
  end

  defp list_enabled_configs do
    import Ecto.Query

    AuditArchivalConfig
    |> where([c], c.enabled == true)
    |> Repo.all()
  end
end
