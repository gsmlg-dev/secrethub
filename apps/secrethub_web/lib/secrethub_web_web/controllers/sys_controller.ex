defmodule SecretHub.WebWeb.SysController do
  @moduledoc """
  Controller for vault system operations (initialization, sealing, unsealing).

  These endpoints manage the vault's seal state and initialization.
  """

  use SecretHub.WebWeb, :controller
  require Logger

  alias SecretHub.Core.Vault.SealState
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

    # Validate parameters
    cond do
      not is_integer(total_shares) or total_shares < 1 or total_shares > 255 ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "secret_shares must be between 1 and 255"})

      not is_integer(threshold) or threshold < 1 or threshold > total_shares ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "secret_threshold must be between 1 and secret_shares"})

      true ->
        case SealState.initialize(total_shares, threshold) do
          {:ok, shares} ->
            # Encode shares for safe transmission
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
    case Shamir.decode_share(encoded_share) do
      {:ok, share} ->
        case SealState.unseal(share) do
          {:ok, status} ->
            if not status.sealed do
              Logger.info("Vault successfully unsealed")
            else
              Logger.info("Unseal progress: #{status.progress}/#{status.threshold}")
            end

            conn
            |> put_status(:ok)
            |> json(status)

          {:error, reason} ->
            Logger.warning("Unseal attempt failed: #{reason}")

            conn
            |> put_status(:bad_request)
            |> json(%{error: reason})
        end

      {:error, reason} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Invalid share format: #{reason}"})
    end
  end

  def unseal(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Missing 'share' parameter"})
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

  Health check endpoint.

  Returns 200 if vault is initialized (regardless of seal status).
  Returns 501 if vault is not yet initialized.
  """
  def health(conn, _params) do
    status = SealState.status()

    if status.initialized do
      conn
      |> put_status(:ok)
      |> json(%{
        initialized: true,
        sealed: status.sealed
      })
    else
      conn
      |> put_status(:not_implemented)
      |> json(%{
        initialized: false,
        sealed: true
      })
    end
  end
end
