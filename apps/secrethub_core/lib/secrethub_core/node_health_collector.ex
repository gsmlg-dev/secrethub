defmodule SecretHub.Core.NodeHealthCollector do
  @moduledoc """
  Collects health metrics for the current node.

  Gathers system-level metrics (CPU, memory), application-level metrics
  (database latency, active connections), and vault status to provide
  a comprehensive health snapshot.

  Metrics collected:
  - CPU usage percentage
  - Memory usage percentage
  - Database latency (ms)
  - Active connections count
  - Vault sealed status
  - Vault initialized status
  """

  require Logger
  alias SecretHub.Core.{Health, Shutdown, Vault.SealState}

  @doc """
  Collects all health metrics for the current node.

  Returns a map with health status and all collected metrics.
  """
  @spec collect() :: {:ok, map()} | {:error, term()}
  def collect do
    metrics = %{
      timestamp: DateTime.utc_now() |> DateTime.truncate(:second),
      health_status: determine_health_status(),
      cpu_percent: collect_cpu_usage(),
      memory_percent: collect_memory_usage(),
      database_latency_ms: collect_database_latency(),
      active_connections: collect_active_connections(),
      vault_sealed: vault_sealed?(),
      vault_initialized: vault_initialized?(),
      last_heartbeat_at: DateTime.utc_now() |> DateTime.truncate(:second),
      metadata: collect_metadata()
    }

    {:ok, metrics}
  rescue
    e ->
      Logger.error("Failed to collect health metrics: #{Exception.message(e)}")
      {:error, Exception.message(e)}
  end

  ## Private Functions

  # Collect CPU usage percentage
  defp collect_cpu_usage do
    # Get scheduler wall time before and after a small delay
    :erlang.statistics(:scheduler_wall_time)
    Process.sleep(100)
    scheduler_usage = :erlang.statistics(:scheduler_wall_time)

    total_time =
      Enum.reduce(scheduler_usage, {0, 0}, fn {_, active, total}, {acc_active, acc_total} ->
        {acc_active + active, acc_total + total}
      end)

    case total_time do
      {active, total} when total > 0 ->
        Float.round(active / total * 100, 2)

      _ ->
        0.0
    end
  rescue
    _ -> 0.0
  end

  # Collect memory usage percentage
  defp collect_memory_usage do
    memory_data = :erlang.memory()
    total = Keyword.get(memory_data, :total, 0)
    _system = Keyword.get(memory_data, :system, 0)

    # Get system total memory (this is approximate)
    # In production, you might want to use :recon or OS-specific commands
    system_total = get_system_total_memory()

    if system_total > 0 do
      Float.round(total / system_total * 100, 2)
    else
      Float.round(total / (1024 * 1024 * 1024), 2)
    end
  rescue
    _ -> 0.0
  end

  # Get total system memory (fallback approximation)
  defp get_system_total_memory do
    # This is a simple approximation
    # In production, consider using :recon or reading /proc/meminfo
    case :os.type() do
      {:unix, :linux} ->
        # Try to read from /proc/meminfo
        case File.read("/proc/meminfo") do
          {:ok, content} ->
            case Regex.run(~r/MemTotal:\s+(\d+)\s+kB/, content) do
              [_, total_kb] ->
                String.to_integer(total_kb) * 1024

              _ ->
                4 * 1024 * 1024 * 1024
            end

          _ ->
            4 * 1024 * 1024 * 1024
        end

      _ ->
        # Default to 4GB for non-Linux systems
        4 * 1024 * 1024 * 1024
    end
  end

  # Collect database latency
  defp collect_database_latency do
    case Health.check_database() do
      {:ok, %{latency_ms: latency}} -> latency
      _ -> nil
    end
  end

  # Collect active connections count
  defp collect_active_connections do
    Shutdown.active_connections()
  end

  # Check if vault is sealed
  defp vault_sealed? do
    SealState.sealed?()
  rescue
    _ -> true
  end

  # Check if vault is initialized
  defp vault_initialized? do
    SealState.initialized?()
  rescue
    _ -> false
  end

  # Determine overall health status
  defp determine_health_status do
    case Health.health(details: false) do
      {:ok, %{status: status}} -> to_string(status)
      _ -> "unhealthy"
    end
  end

  # Collect additional metadata
  defp collect_metadata do
    %{
      beam_version: :erlang.system_info(:otp_release) |> to_string(),
      elixir_version: System.version(),
      node_name: node() |> to_string(),
      uptime_seconds: :erlang.statistics(:wall_clock) |> elem(0) |> div(1000)
    }
  end
end
