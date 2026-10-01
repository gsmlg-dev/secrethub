defmodule SecretHub.Core.Health do
  @moduledoc "Bounded health checks for process, management and secret-serving availability."

  alias SecretHub.Core.{Repo, Shutdown, Vault.SealState}
  alias SecretHub.Core.Workers.ClientAuthCRLRefresher
  alias SecretHub.Shared.LaunchProfile

  @timeout 500

  def liveness, do: {:ok, %{status: "alive", timestamp: timestamp()}}

  def management_readiness do
    readiness_result("management", %{
      database: check_database(),
      vault: check_vault(),
      shutdown_state: check_shutdown()
    })
  end

  def readiness do
    readiness_result("secrets", %{
      database: check_database(),
      vault_initialized: check_vault_initialized(),
      seal_status: check_seal_status(),
      background_jobs: check_background_jobs(),
      shutdown_state: check_shutdown()
    })
  end

  def health(opts \\ []) do
    checks = %{
      database: check_database(),
      vault: check_vault(),
      seal_status: check_seal_status()
    }

    checks =
      if Keyword.get(opts, :details, true),
        do: Map.put(checks, :background_jobs, check_background_jobs()),
        else: checks

    vault =
      case checks.vault do
        {:ok, data} -> data
        {:error, _} -> %{initialized: false, sealed: true}
      end

    {:ok,
     %{
       status: overall_status(checks),
       initialized: vault.initialized,
       sealed: vault.sealed,
       shutting_down: Shutdown.shutting_down?(),
       checks: format_checks(checks),
       timestamp: timestamp(),
       version: Application.spec(:secrethub_core, :vsn) |> to_string()
     }}
  end

  def check_database do
    start = System.monotonic_time(:microsecond)

    case Repo.query("SELECT 1", [], timeout: @timeout, pool_timeout: @timeout) do
      {:ok, _} ->
        {:ok, %{latency_ms: Float.round((System.monotonic_time(:microsecond) - start) / 1000, 2)}}

      {:error, _} ->
        error("database_unavailable")
    end
  rescue
    _ -> error("database_unavailable")
  catch
    :exit, _ -> error("database_unavailable")
  end

  def check_vault do
    case GenServer.call(SealState, :status, @timeout) do
      %{state: state} when state in [:loading, :unavailable] ->
        error("vault_unavailable")

      status ->
        {:ok,
         Map.take(status, [
           :state,
           :initialized,
           :sealed,
           :threshold,
           :total_shares,
           :recovery_required
         ])}
    end
  rescue
    _ -> error("vault_unavailable")
  catch
    :exit, _ -> error("vault_unavailable")
  end

  def check_vault_initialized do
    case check_vault() do
      {:ok, %{initialized: true, recovery_required: false}} -> {:ok, %{initialized: true}}
      {:ok, _} -> error("vault_not_initialized_or_recovery_required")
      error -> error
    end
  end

  def check_seal_status do
    case GenServer.call(SealState, :get_master_key, @timeout) do
      {:ok, key} when is_binary(key) and byte_size(key) == 32 -> {:ok, %{sealed: false}}
      _ -> {:error, %{sealed: true, reason: "vault_sealed_or_key_unverified"}}
    end
  rescue
    _ -> error("vault_unavailable")
  catch
    :exit, _ -> error("vault_unavailable")
  end

  def check_background_jobs do
    if LaunchProfile.enabled?(:client_auth_pki) do
      ClientAuthCRLRefresher.health_status()
    else
      {:ok, %{required: false}}
    end
  end

  defp readiness_result(service, checks) do
    ready = Enum.all?(checks, fn {_name, result} -> match?({:ok, _}, result) end)

    result = %{
      ready: ready,
      service: service,
      shutting_down: Shutdown.shutting_down?(),
      checks: format_checks(checks),
      timestamp: timestamp()
    }

    if ready, do: {:ok, result}, else: {:error, result}
  end

  defp check_shutdown do
    if Shutdown.shutting_down?(), do: error("shutting_down"), else: {:ok, %{state: "ready"}}
  end

  defp overall_status(checks) do
    cond do
      Enum.all?(checks, fn {_key, result} -> match?({:ok, _}, result) end) -> :healthy
      match?({:error, _}, checks.database) or match?({:error, _}, checks.vault) -> :unhealthy
      true -> :degraded
    end
  end

  defp format_checks(checks) do
    Map.new(checks, fn {name, {status, data}} ->
      {name, Map.put(data, :status, if(status == :ok, do: "passing", else: "failing"))}
    end)
  end

  defp error(reason), do: {:error, %{reason: reason}}
  defp timestamp, do: DateTime.utc_now() |> DateTime.truncate(:second)
end
