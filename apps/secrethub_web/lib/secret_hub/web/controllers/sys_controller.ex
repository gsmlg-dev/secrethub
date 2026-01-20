defmodule SecretHub.Web.SysController do
  @moduledoc """
  Controller for vault system operations (initialization, sealing, unsealing).

  These endpoints manage the vault's seal state and initialization.
  """

  use SecretHub.Web, :controller
  require Logger

  alias SecretHub.Core.{Health, Vault.SealState}
  alias SecretHub.Shared.Crypto.Shamir

  @doc """
  POST /v1/sys/init

  Initializes the vault with Shamir secret sharing.

  Request body:
  ```json
  {
    "secret_shares": 5,
    "secret_threshold": 3
  }
  ```

  Response:
  ```json
  {
    "shares": ["secrethub-share-xxx", "secrethub-share-yyy", ...],
    "threshold": 3,
    "total_shares": 5
  }
  ```
  """
  def init(conn, params) do
    total_shares = Map.get(params, "secret_shares", 5)
    threshold = Map.get(params, "secret_threshold", 3)

    with :ok <- validate_shares_param(total_shares),
         :ok <- validate_threshold_param(threshold, total_shares) do
      do_init(conn, total_shares, threshold)
    else
      {:error, error_msg} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: error_msg})
    end
  end

  defp validate_shares_param(total_shares) do
    if is_integer(total_shares) and total_shares >= 1 and total_shares <= 255 do
      :ok
    else
      {:error, "secret_shares must be between 1 and 255"}
    end
  end

  defp validate_threshold_param(threshold, total_shares) do
    if is_integer(threshold) and threshold >= 1 and threshold <= total_shares do
      :ok
    else
      {:error, "secret_threshold must be between 1 and secret_shares"}
    end
  end

  defp do_init(conn, total_shares, threshold) do
    case SealState.initialize(total_shares, threshold) do
      {:ok, shares} ->
        encoded_shares = Enum.map(shares, &Shamir.encode_share/1)
        Logger.info("Vault initialized with #{total_shares} shares (threshold: #{threshold})")

        conn
        |> put_status(:ok)
        |> json(%{
          shares: encoded_shares,
          threshold: threshold,
          total_shares: total_shares
        })

      {:error, reason} ->
        Logger.error("Vault initialization failed: #{reason}")

        conn
        |> put_status(:bad_request)
        |> json(%{error: reason})
    end
  end

  @doc """
  POST /v1/sys/unseal

  Provides an unseal share to progress vault unsealing.

  Request body:
  ```json
  {
    "share": "secrethub-share-xxx"
  }
  ```

  Response:
  ```json
  {
    "sealed": false,
    "progress": 3,
    "threshold": 3
  }
  ```
  """
  def unseal(conn, %{"share" => encoded_share}) do
    with {:ok, share} <- Shamir.decode_share(encoded_share),
         {:ok, status} <- SealState.unseal(share) do
      log_unseal_status(status)

      conn
      |> put_status(:ok)
      |> json(status)
    else
      {:error, reason} when is_binary(reason) ->
        handle_unseal_error(conn, reason)
    end
  end

  def unseal(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Missing 'share' parameter"})
  end

  defp log_unseal_status(%{sealed: false}), do: Logger.info("Vault successfully unsealed")

  defp log_unseal_status(%{progress: progress, threshold: threshold}) do
    Logger.info("Unseal progress: #{progress}/#{threshold}")
  end

  defp handle_unseal_error(conn, reason) do
    Logger.warning("Unseal attempt failed: #{reason}")

    conn
    |> put_status(:bad_request)
    |> json(%{error: reason})
  end

  @doc """
  POST /v1/sys/seal

  Seals the vault, clearing the master key from memory.

  Response:
  ```json
  {
    "sealed": true
  }
  ```
  """
  def seal(conn, _params) do
    :ok = SealState.seal()

    Logger.info("Vault sealed")

    conn
    |> put_status(:ok)
    |> json(%{sealed: true})
  end

  @doc """
  GET /v1/sys/seal-status

  Returns the current seal status of the vault.

  Response:
  ```json
  {
    "initialized": true,
    "sealed": false,
    "progress": 0,
    "threshold": 3,
    "total_shares": 5
  }
  ```
  """
  def status(conn, _params) do
    status = SealState.status()

    conn
    |> put_status(:ok)
    |> json(status)
  end

  @doc """
  GET /v1/sys/health

  Comprehensive health check endpoint.

  Returns detailed health information including:
  - Overall status (healthy/degraded/unhealthy)
  - Database connectivity
  - Vault status
  - Seal status
  - Background job health

  Query parameters:
  - `details`: Include detailed checks (default: true)

  Returns 200 if healthy or degraded, 503 if unhealthy.
  """
  def health(conn, params) do
    include_details = Map.get(params, "details", "true") != "false"

    case Health.health(details: include_details) do
      {:ok, health_data} ->
        status_code =
          case health_data.status do
            :healthy -> :ok
            :degraded -> :ok
            :unhealthy -> :service_unavailable
          end

        conn
        |> put_status(status_code)
        |> json(health_data)
    end
  end

  @doc """
  GET /v1/sys/health/ready

  Readiness check for Kubernetes and load balancers.

  Returns 200 if the service is ready to accept traffic:
  - Database is accessible
  - Vault is initialized

  Returns 503 if not ready.
  """
  def readiness(conn, _params) do
    case Health.readiness() do
      {:ok, ready_data} ->
        conn
        |> put_status(:ok)
        |> json(ready_data)

      {:error, not_ready_data} ->
        conn
        |> put_status(:service_unavailable)
        |> json(not_ready_data)
    end
  end

  @doc """
  GET /v1/sys/health/live

  Liveness check for Kubernetes.

  Always returns 200 if the application is running.
  Used by Kubernetes to determine if the pod should be restarted.
  """
  def liveness(conn, _params) do
    {:ok, liveness_data} = Health.liveness()

    conn
    |> put_status(:ok)
    |> json(liveness_data)
  end
end
