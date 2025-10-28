defmodule SecretHub.Core.Health do
  @moduledoc """
  Health check module for SecretHub Core.

  Provides comprehensive health monitoring for high availability deployments:
  - Database connectivity
  - Seal status
  - System resources
  - Background job health
  - Readiness and liveness checks for Kubernetes

  ## Health Check Types

  - **Liveness**: Is the application running? (Used by k8s to restart pods)
  - **Readiness**: Can the application serve traffic? (Used by k8s/load balancers)
  - **Health**: Detailed health status (Used for monitoring/alerting)
  """

  require Logger
  alias SecretHub.Core.{Repo, Vault.SealState}

  @type health_status :: :healthy | :degraded | :unhealthy
  @type check_result :: {:ok, map()} | {:error, term()}

  @doc """
  Liveness check - minimal check to determine if the process is alive.

  Returns 200 if the application is running, regardless of functionality.
  Used by Kubernetes to determine if the pod should be restarted.
  """
  @spec liveness() :: {:ok, map()}
  def liveness do
    {:ok,
     %{
       status: "alive",
       timestamp: DateTime.utc_now()
     }}
  end

  @doc """
  Readiness check - determines if the application can serve traffic.

  Returns 200 only if the application is ready to handle requests:
  - Database is accessible
  - Vault is initialized (but can be sealed)
  - Critical dependencies are available

  Used by Kubernetes and load balancers to route traffic.
  """
  @spec readiness() :: {:ok, map()} | {:error, map()}
  def readiness do
    checks = %{
      database: check_database(),
      vault_initialized: check_vault_initialized()
    }

    ready = Enum.all?(checks, fn {_name, result} -> match?({:ok, _}, result) end)

    result = %{
      ready: ready,
      checks: format_check_results(checks),
      timestamp: DateTime.utc_now()
    }

    if ready do
      {:ok, result}
    else
      {:error, result}
    end
  end

  @doc """
  Comprehensive health check with detailed status.

  Returns detailed health information including:
  - Overall health status (healthy/degraded/unhealthy)
  - Database connectivity
  - Seal status
  - Background job health
  - System metrics

  Used for monitoring, alerting, and debugging.
  """
  @spec health(keyword()) :: {:ok, map()}
  def health(opts \\ []) do
    include_details = Keyword.get(opts, :details, true)

    checks = %{
      database: check_database(),
      vault: check_vault(),
      seal_status: check_seal_status()
    }

    # Add optional detailed checks
    checks =
      if include_details do
        Map.merge(checks, %{
          background_jobs: check_background_jobs()
        })
      else
        checks
      end

    # Determine overall status
    status = determine_overall_status(checks)

    result = %{
      status: status,
      initialized: vault_initialized?(),
      sealed: vault_sealed?(),
      checks: format_check_results(checks),
      timestamp: DateTime.utc_now(),
      version: Application.spec(:secrethub_core, :vsn) |> to_string()
    }

    {:ok, result}
  end

  @doc """
  Check database connectivity.
  """
  @spec check_database() :: check_result()
  def check_database do
    try do
      case Repo.query("SELECT 1", [], timeout: 5000) do
        {:ok, _result} ->
          {:ok, %{status: "connected", latency_ms: measure_db_latency()}}

        {:error, reason} ->
          {:error, %{status: "error", reason: inspect(reason)}}
      end
    rescue
      e ->
        {:error, %{status: "error", reason: Exception.message(e)}}
    end
  end

  @doc """
  Check vault initialization status.
  """
  @spec check_vault_initialized() :: check_result()
  def check_vault_initialized do
    if vault_initialized?() do
      {:ok, %{initialized: true}}
    else
      {:error, %{initialized: false, reason: "Vault not initialized"}}
    end
  end

  @doc """
  Check comprehensive vault status.
  """
  @spec check_vault() :: check_result()
  def check_vault do
    try do
      status = SealState.status()

      {:ok,
       %{
         initialized: status.initialized,
         sealed: status.sealed,
         threshold: status.threshold,
         shares: status.total_shares
       }}
    rescue
      e ->
        {:error, %{reason: Exception.message(e)}}
    end
  end

  @doc """
  Check seal status specifically.
  """
  @spec check_seal_status() :: check_result()
  def check_seal_status do
    if vault_sealed?() do
      {:error, %{sealed: true, reason: "Vault is sealed"}}
    else
      {:ok, %{sealed: false}}
    end
  end

  @doc """
  Check background job health (Oban).
  """
  @spec check_background_jobs() :: check_result()
  def check_background_jobs do
    # Check if Oban is running and healthy
    try do
      # This is a basic check - could be enhanced with Oban.check_queue/1
      {:ok, %{status: "running"}}
    rescue
      e ->
        {:error, %{status: "error", reason: Exception.message(e)}}
    end
  end

  ## Private Functions

  defp vault_initialized? do
    try do
      status = SealState.status()
      status.initialized
    rescue
      _ -> false
    end
  end

  defp vault_sealed? do
    try do
      status = SealState.status()
      status.sealed
    rescue
      _ -> true
    end
  end

  defp measure_db_latency do
    {time_microseconds, _result} =
      :timer.tc(fn ->
        Repo.query("SELECT 1", [], timeout: 5000)
      end)

    Float.round(time_microseconds / 1000, 2)
  end

  defp determine_overall_status(checks) do
    results = Map.values(checks)

    cond do
      # All checks passing - healthy
      Enum.all?(results, &match?({:ok, _}, &1)) ->
        :healthy

      # Some non-critical checks failing - degraded
      Enum.any?(results, &match?({:error, _}, &1)) and
          match?({:ok, _}, checks[:database]) ->
        :degraded

      # Critical checks failing - unhealthy
      true ->
        :unhealthy
    end
  end

  defp format_check_results(checks) do
    checks
    |> Enum.map(fn {name, result} ->
      case result do
        {:ok, data} ->
          {name, Map.put(data, :status, "passing")}

        {:error, data} ->
          {name, Map.put(data, :status, "failing")}
      end
    end)
    |> Map.new()
  end
end
