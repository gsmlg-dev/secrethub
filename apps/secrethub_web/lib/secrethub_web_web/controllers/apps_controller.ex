defmodule SecretHub.WebWeb.AppsController do
  @moduledoc """
  API Controller for application management.

  Handles:
  - Application registration
  - Application CRUD operations
  - Application lifecycle (suspend/activate)
  - Application certificate listing
  """

  use SecretHub.WebWeb, :controller
  require Logger

  alias SecretHub.Core.Apps

  @doc """
  POST /v1/apps

  Register a new application.

  Request body:
  ```json
  {
    "name": "payment-service",
    "description": "Payment processing service",
    "agent_id": "uuid",
    "policies": ["prod-payment-db-read", "prod-payment-db-write"]
  }
  ```

  Response:
  ```json
  {
    "app_id": "uuid",
    "app_token": "hvs.CAESIJ...",
    "token_expires_at": "2025-10-27T11:00:00Z",
    "name": "payment-service",
    "agent_id": "uuid",
    "policies": ["prod-payment-db-read", "prod-payment-db-write"],
    "created_at": "2025-10-27T10:00:00Z"
  }
  ```
  """
  def register_app(conn, params) do
    Logger.info("Application registration requested", name: params["name"])

    case Apps.register_app(params) do
      {:ok, %{app: app, token: token, token_expires_at: expires_at}} ->
        Logger.info("Application registered successfully", app_id: app.id, name: app.name)

        conn
        |> put_status(:created)
        |> json(%{
          app_id: app.id,
          app_token: token,
          token_expires_at: expires_at,
          name: app.name,
          description: app.description,
          agent_id: app.agent_id,
          status: app.status,
          policies: app.policies,
          created_at: app.inserted_at
        })

      {:error, %Ecto.Changeset{} = changeset} ->
        errors = translate_changeset_errors(changeset)

        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Validation failed", details: errors})

      {:error, reason} ->
        Logger.error("Failed to register application", reason: inspect(reason))

        conn
        |> put_status(:internal_server_error)
        |> json(%{error: "Application registration failed"})
    end
  end

  @doc """
  GET /v1/apps

  List all applications with optional filtering.

  Query parameters:
  - agent_id: Filter by agent ID
  - status: Filter by status (active, suspended, revoked)
  - limit: Maximum number of results
  - offset: Pagination offset
  """
  def list_apps(conn, params) do
    opts = build_list_options(params)
    {:ok, apps} = Apps.list_apps(opts)

    conn
    |> json(%{
      apps:
        Enum.map(apps, fn app ->
          %{
            app_id: app.id,
            name: app.name,
            description: app.description,
            agent_id: app.agent_id,
            status: app.status,
            policies: app.policies,
            created_at: app.inserted_at
          }
        end)
    })
  end

  @doc """
  GET /v1/apps/:id

  Get application details.
  """
  def get_app(conn, %{"id" => id}) do
    case Apps.get_app(id) do
      {:ok, app} ->
        conn
        |> json(%{
          app_id: app.id,
          name: app.name,
          description: app.description,
          agent_id: app.agent_id,
          status: app.status,
          policies: app.policies,
          metadata: app.metadata,
          created_at: app.inserted_at,
          updated_at: app.updated_at
        })

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Application not found"})
    end
  end

  @doc """
  PUT /v1/apps/:id

  Update application metadata or policies.

  Request body:
  ```json
  {
    "description": "Updated description",
    "policies": ["new-policy-1", "new-policy-2"],
    "metadata": {"key": "value"}
  }
  ```
  """
  def update_app(conn, %{"id" => id} = params) do
    Logger.info("Application update requested", app_id: id)

    case Apps.update_app(id, params) do
      {:ok, app} ->
        Logger.info("Application updated successfully", app_id: app.id)

        conn
        |> json(%{
          app_id: app.id,
          name: app.name,
          description: app.description,
          agent_id: app.agent_id,
          status: app.status,
          policies: app.policies,
          metadata: app.metadata,
          updated_at: app.updated_at
        })

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Application not found"})

      {:error, %Ecto.Changeset{} = changeset} ->
        errors = translate_changeset_errors(changeset)

        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Validation failed", details: errors})

      {:error, reason} ->
        Logger.error("Failed to update application", reason: inspect(reason))

        conn
        |> put_status(:internal_server_error)
        |> json(%{error: "Application update failed"})
    end
  end

  @doc """
  DELETE /v1/apps/:id

  Delete an application and revoke all its certificates.
  """
  def delete_app(conn, %{"id" => id}) do
    Logger.info("Application deletion requested", app_id: id)

    case Apps.delete_app(id) do
      {:ok, app} ->
        Logger.info("Application deleted successfully", app_id: app.id)

        conn
        |> json(%{message: "Application deleted", app_id: app.id})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Application not found"})

      {:error, reason} ->
        Logger.error("Failed to delete application", reason: inspect(reason))

        conn
        |> put_status(:internal_server_error)
        |> json(%{error: "Application deletion failed"})
    end
  end

  @doc """
  POST /v1/apps/:id/suspend

  Suspend an application (prevent new connections).
  """
  def suspend_app(conn, %{"id" => id}) do
    Logger.info("Application suspension requested", app_id: id)

    case Apps.suspend_app(id) do
      {:ok, app} ->
        Logger.info("Application suspended successfully", app_id: app.id)

        conn
        |> json(%{
          message: "Application suspended",
          app_id: app.id,
          status: app.status
        })

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Application not found"})

      {:error, reason} ->
        Logger.error("Failed to suspend application", reason: inspect(reason))

        conn
        |> put_status(:internal_server_error)
        |> json(%{error: "Application suspension failed"})
    end
  end

  @doc """
  POST /v1/apps/:id/activate

  Reactivate a suspended application.
  """
  def activate_app(conn, %{"id" => id}) do
    Logger.info("Application activation requested", app_id: id)

    case Apps.activate_app(id) do
      {:ok, app} ->
        Logger.info("Application activated successfully", app_id: app.id)

        conn
        |> json(%{
          message: "Application activated",
          app_id: app.id,
          status: app.status
        })

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Application not found"})

      {:error, reason} ->
        Logger.error("Failed to activate application", reason: inspect(reason))

        conn
        |> put_status(:internal_server_error)
        |> json(%{error: "Application activation failed"})
    end
  end

  @doc """
  GET /v1/apps/:id/certificates

  List all certificates for an application.
  """
  def list_certificates(conn, %{"id" => id}) do
    {:ok, certs} = Apps.list_app_certificates(id)

    conn
    |> json(%{
      app_id: id,
      certificates:
        Enum.map(certs, fn cert ->
          %{
            certificate_id: cert.certificate_id,
            issued_at: cert.issued_at,
            expires_at: cert.expires_at,
            revoked_at: cert.revoked_at,
            revocation_reason: cert.revocation_reason
          }
        end)
    })
  end

  # Private helper functions

  defp build_list_options(params) do
    []
    |> maybe_add_option(:agent_id, params["agent_id"])
    |> maybe_add_option(:status, params["status"])
    |> maybe_add_option(:limit, parse_int(params["limit"]))
    |> maybe_add_option(:offset, parse_int(params["offset"]))
  end

  defp maybe_add_option(opts, _key, nil), do: opts
  defp maybe_add_option(opts, key, value), do: Keyword.put(opts, key, value)

  defp parse_int(nil), do: nil
  defp parse_int(value) when is_integer(value), do: value

  defp parse_int(value) when is_binary(value) do
    case Integer.parse(value) do
      {int, ""} -> int
      _ -> nil
    end
  end

  defp translate_changeset_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end
end
