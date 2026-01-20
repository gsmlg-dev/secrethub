defmodule SecretHub.Web.AuthController do
  @moduledoc """
  Controller for authentication and AppRole management.

  Provides REST API for:
  - Creating and managing AppRoles
  - Rotating SecretIDs
  - Listing and viewing roles
  """

  use SecretHub.Web, :controller
  require Logger

  alias SecretHub.Core.Auth.AppRole

  @doc """
  POST /v1/auth/approle/role/:role_name

  Creates a new AppRole.

  Request body:
  ```json
  {
    "policies": ["policy-id-1", "policy-id-2"],
    "secret_id_ttl": 600,
    "secret_id_num_uses": 1,
    "bound_cidr_list": ["10.0.0.0/8"]
  }
  ```

  Response:
  ```json
  {
    "role_id": "uuid",
    "secret_id": "uuid",
    "role_name": "production-app"
  }
  ```
  """
  def create_role(conn, %{"role_name" => role_name} = params) do
    opts = [
      policies: Map.get(params, "policies", []),
      secret_id_ttl: Map.get(params, "secret_id_ttl", 600),
      secret_id_num_uses: Map.get(params, "secret_id_num_uses", 1),
      bound_cidr_list: Map.get(params, "bound_cidr_list", [])
    ]

    case AppRole.create_role(role_name, opts) do
      {:ok, result} ->
        Logger.info("Created AppRole: #{role_name}")

        conn
        |> put_status(:created)
        |> json(%{
          role_id: result.role_id,
          secret_id: result.secret_id,
          role_name: result.role_name
        })

      {:error, reason} ->
        Logger.error("Failed to create AppRole #{role_name}: #{reason}")

        conn
        |> put_status(:bad_request)
        |> json(%{error: reason})
    end
  end

  @doc """
  GET /v1/auth/approle/role/:role_name

  Gets AppRole details.

  Response:
  ```json
  {
    "role_id": "uuid",
    "role_name": "production-app",
    "policies": ["policy-1"],
    "secret_id_ttl": 600,
    "secret_id_num_uses": 1,
    "secret_id_uses": 0
  }
  ```
  """
  def get_role(conn, %{"role_name" => role_name}) do
    # Find role by name
    roles = AppRole.list_roles()

    case Enum.find(roles, fn r -> r.role_name == role_name end) do
      nil ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Role not found"})

      role ->
        conn
        |> put_status(:ok)
        |> json(role)
    end
  end

  @doc """
  GET /v1/auth/approle/role

  Lists all AppRoles.

  Response:
  ```json
  {
    "roles": [
      {
        "role_id": "uuid",
        "role_name": "production-app",
        "policies": ["policy-1"]
      }
    ]
  }
  ```
  """
  def list_roles(conn, _params) do
    roles = AppRole.list_roles()

    conn
    |> put_status(:ok)
    |> json(%{roles: roles})
  end

  @doc """
  DELETE /v1/auth/approle/role/:role_name

  Deletes an AppRole.

  Response:
  ```json
  {
    "deleted": true
  }
  ```
  """
  def delete_role(conn, %{"role_name" => role_name}) do
    # Find role by name to get role_id
    roles = AppRole.list_roles()

    case Enum.find(roles, fn r -> r.role_name == role_name end) do
      nil ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Role not found"})

      role ->
        case AppRole.delete_role(role.role_id) do
          :ok ->
            Logger.info("Deleted AppRole: #{role_name}")

            conn
            |> put_status(:ok)
            |> json(%{deleted: true})

          {:error, reason} ->
            conn
            |> put_status(:bad_request)
            |> json(%{error: reason})
        end
    end
  end

  @doc """
  POST /v1/auth/approle/role/:role_name/secret-id

  Rotates the SecretID for an AppRole.

  Response:
  ```json
  {
    "secret_id": "new-uuid"
  }
  ```
  """
  def rotate_secret_id(conn, %{"role_name" => role_name}) do
    # Find role by name to get role_id
    roles = AppRole.list_roles()

    case Enum.find(roles, fn r -> r.role_name == role_name end) do
      nil ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Role not found"})

      role ->
        case AppRole.rotate_secret_id(role.role_id) do
          {:ok, result} ->
            Logger.info("Rotated SecretID for AppRole: #{role_name}")

            conn
            |> put_status(:ok)
            |> json(result)

          {:error, reason} ->
            conn
            |> put_status(:bad_request)
            |> json(%{error: reason})
        end
    end
  end

  @doc """
  GET /v1/auth/approle/role/:role_name/role-id

  Gets the RoleID for an AppRole (safe to distribute).

  Response:
  ```json
  {
    "role_id": "uuid"
  }
  ```
  """
  def get_role_id(conn, %{"role_name" => role_name}) do
    roles = AppRole.list_roles()

    case Enum.find(roles, fn r -> r.role_name == role_name end) do
      nil ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Role not found"})

      role ->
        conn
        |> put_status(:ok)
        |> json(%{role_id: role.role_id})
    end
  end
end
