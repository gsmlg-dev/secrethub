defmodule SecretHub.Core.Workers.HashChainVerificationWorker do
  @moduledoc """
  Oban worker for verifying audit log hash chain integrity.

  This worker periodically verifies that the hash chain in audit logs
  has not been tampered with. Each audit log contains a hash of its
  own data plus the previous log's hash, creating an immutable chain.

  ## Verification Process

  1. Fetch a batch of audit logs in chronological order
  2. For each log, recompute the hash using its data + previous hash
  3. Compare computed hash with stored hash
  4. Report any discrepancies as critical security alerts
  5. Track verification statistics

  ## Example

      # Schedule verification
      HashChainVerificationWorker.new() |> Oban.insert()
  """

  use Oban.Worker,
    queue: :verification,
    max_attempts: 1,
    priority: 2

  require Logger

  alias SecretHub.Core.Audit
  alias SecretHub.Core.Alerting

  @batch_size 1000
  @verification_start_offset_days 1

  @impl Oban.Worker
  def perform(%Oban.Job{args: args}) do
    batch_size = Map.get(args, "batch_size", @batch_size)
    start_offset_days = Map.get(args, "start_offset_days", @verification_start_offset_days)

    Logger.info("Starting hash chain verification", batch_size: batch_size)

    start_time = System.monotonic_time(:millisecond)

    with {:ok, logs} <- fetch_logs_for_verification(batch_size, start_offset_days),
         {:ok, results} <- verify_hash_chain(logs),
         :ok <- handle_verification_results(results) do
      duration_ms = System.monotonic_time(:millisecond) - start_time

      Logger.info("Hash chain verification completed",
        total_logs: length(logs),
        valid: results.valid_count,
        invalid: results.invalid_count,
        duration_ms: duration_ms
      )

      :ok
    else
      {:error, reason} ->
        Logger.error("Hash chain verification failed", reason: inspect(reason))
        {:error, reason}
    end
  end

  @doc """
  Verifies a specific range of audit logs.
  """
  def verify_range(from_id, to_id) do
    %{from_id: from_id, to_id: to_id}
    |> new()
    |> Oban.insert()
  end

  defp fetch_logs_for_verification(batch_size, start_offset_days) do
    # Fetch logs older than start_offset_days (allow time for logs to stabilize)
    cutoff_date = DateTime.add(DateTime.utc_now() |> DateTime.truncate(:second), -start_offset_days * 86400, :second)

    logs = Audit.list_logs_for_verification(cutoff_date, limit: batch_size)

    {:ok, logs}
  end

  defp verify_hash_chain(logs) do
    results =
      logs
      |> Enum.reduce(
        %{valid_count: 0, invalid_count: 0, invalid_logs: [], previous_hash: nil},
        &verify_log/2
      )

    {:ok, results}
  end

  defp verify_log(log, acc) do
    # Recompute hash based on log data and previous hash
    computed_hash = compute_log_hash(log, acc.previous_hash)

    if computed_hash == log.hash do
      # Hash is valid
      %{
        acc
        | valid_count: acc.valid_count + 1,
          previous_hash: log.hash
      }
    else
      # Hash is INVALID - potential tampering!
      Logger.error("Hash chain integrity violation detected!",
        log_id: log.id,
        expected_hash: log.hash,
        computed_hash: computed_hash,
        timestamp: log.timestamp
      )

      %{
        acc
        | invalid_count: acc.invalid_count + 1,
          invalid_logs: [
            %{
              log_id: log.id,
              expected: log.hash,
              computed: computed_hash,
              timestamp: log.timestamp
            }
            | acc.invalid_logs
          ],
          previous_hash: log.hash
      }
    end
  end

  defp compute_log_hash(log, previous_hash) do
    # Recreate the exact hash computation from audit logging
    data_to_hash = %{
      event_type: log.event_type,
      actor_type: log.actor_type,
      actor_id: log.actor_id,
      resource_type: log.resource_type,
      resource_id: log.resource_id,
      action: log.action,
      result: log.result,
      timestamp: log.timestamp,
      previous_hash: previous_hash || ""
    }

    json = Jason.encode!(data_to_hash, sort_keys: true)

    :crypto.hash(:sha256, json)
    |> Base.encode16(case: :lower)
  end

  defp handle_verification_results(results) do
    if results.invalid_count > 0 do
      # CRITICAL: Hash chain has been compromised!
      create_critical_alert(results)
    end

    # Store verification results for audit trail
    store_verification_results(results)

    :ok
  end

  defp create_critical_alert(results) do
    Logger.critical("AUDIT LOG TAMPERING DETECTED",
      invalid_count: results.invalid_count,
      invalid_log_ids: Enum.map(results.invalid_logs, & &1.log_id)
    )

    # Create anomaly alert for tampered logs
    Alerting.create_anomaly_alert(%{
      rule_id: nil,
      triggered_at: DateTime.utc_now() |> DateTime.truncate(:second),
      severity: :critical,
      description: """
      Hash chain integrity violation detected!
      #{results.invalid_count} audit log(s) failed hash verification.
      This indicates potential tampering with audit logs.
      Immediate investigation required!
      """,
      context: %{
        invalid_count: results.invalid_count,
        invalid_logs: results.invalid_logs,
        verification_time: DateTime.utc_now() |> DateTime.truncate(:second)
      }
    })
  end

  defp store_verification_results(results) do
    # Store in metadata table for historical tracking
    metadata = %{
      timestamp: DateTime.utc_now() |> DateTime.truncate(:second),
      total_verified: results.valid_count + results.invalid_count,
      valid_count: results.valid_count,
      invalid_count: results.invalid_count,
      invalid_logs: results.invalid_logs
    }

    Logger.metadata(verification_results: metadata)

    # Could also store in a dedicated verification_history table
    :ok
  end
end
