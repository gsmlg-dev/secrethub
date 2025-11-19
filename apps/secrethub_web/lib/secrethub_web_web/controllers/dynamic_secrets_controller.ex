defmodule SecretHub.WebWeb.DynamicSecretsController do
  @moduledoc """
  API controller for dynamic secret operations.

  Handles:
  - Generating dynamic credentials for configured roles
  - Renewing active leases
  - Revoking leases manually
  - Listing active leases
  """

  use SecretHub.WebWeb, :controller

  require Logger

  alias SecretHub.Core.LeaseManager
  alias SecretHub.Core.Engines.Dynamic.PostgreSQL

  @doc """
  Generate dynamic credentials for a role.

  POST /api/v1/secrets/dynamic/:role

  Request body:
  {
    "ttl": 3600,  // optional, uses role default if not provided
    "metadata": {...}  // optional
  }

  Response:
  {
    "lease_id": "lease_abc123",
    "credentials": {
      "username": "v_readonly_a3f9k2m1_1698765432",
      "password": "...",
      "host": "localhost",
      "port": 5432,
      "database": "myapp_production"
    },
    "lease_duration": 3600,
    "renewable": true
  }
  """
  def generate(conn, %{"role" => role_name} = params) do
    ttl = params["ttl"]
    metadata = params["metadata"] || %{}
    agent_id = get_session(conn, :agent_id)

    # FIXME: Load role configuration from database
    # For now, using a hardcoded config for development
    config = get_role_config(role_name)

    case config do
      nil ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Role not found: #{role_name}"})

      config ->
        opts = [
          config: config,
          ttl: ttl
        ]

        case PostgreSQL.generate_credentials(role_name, opts) do
          {:ok, credentials} ->
            # Create lease
            lease_attrs = %{
              engine_type: "postgresql",
              role_name: role_name,
              credentials: credentials,
              ttl: credentials.ttl,
              agent_id: agent_id,
              metadata: Map.merge(metadata, %{"config" => config})
            }

            case LeaseManager.create_lease(lease_attrs) do
              {:ok, lease} ->
                Logger.info("Generated dynamic credentials",
                  role: role_name,
                  lease_id: lease.id,
                  agent_id: agent_id
                )

                conn
                |> put_status(:ok)
                |> json(%{
                  lease_id: lease.id,
                  credentials: %{
                    username: credentials.username,
                    password: credentials.password,
                    host: credentials.metadata.host,
                    port: credentials.metadata.port,
                    database: credentials.metadata.database
                  },
                  lease_duration: credentials.ttl,
                  renewable: true
                })

              {:error, changeset} ->
                Logger.error("Failed to create lease",
                  role: role_name,
                  errors: inspect(changeset.errors)
                )

                conn
                |> put_status(:internal_server_error)
                |> json(%{error: "Failed to create lease"})
            end

          {:error, reason} ->
            Logger.error("Failed to generate credentials",
              role: role_name,
              error: inspect(reason)
            )

            conn
            |> put_status(:internal_server_error)
            |> json(%{error: "Failed to generate credentials: #{inspect(reason)}"})
        end
    end
  end

  @doc """
  Renew a lease.

  POST /api/v1/sys/leases/renew

  Request body:
  {
    "lease_id": "lease_abc123",
    "increment": 3600  // optional, uses default if not provided
  }

  Response:
  {
    "lease_id": "lease_abc123",
    "lease_duration": 3600,
    "renewable": true
  }
  """
  def renew(conn, %{"lease_id" => lease_id} = params) do
    increment = params["increment"]

    case LeaseManager.renew_lease(lease_id, increment) do
      {:ok, lease} ->
        ttl = DateTime.diff(lease.expires_at, DateTime.utc_now())

        Logger.info("Renewed lease", lease_id: lease_id, new_ttl: ttl)

        conn
        |> put_status(:ok)
        |> json(%{
          lease_id: lease.id,
          lease_duration: ttl,
          renewable: true
        })

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Lease not found"})

      {:error, :expired} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Lease has already expired"})

      {:error, reason} ->
        Logger.error("Failed to renew lease",
          lease_id: lease_id,
          error: inspect(reason)
        )

        conn
        |> put_status(:internal_server_error)
        |> json(%{error: "Failed to renew lease: #{inspect(reason)}"})
    end
  end

  @doc """
  Revoke a lease.

  POST /api/v1/sys/leases/revoke

  Request body:
  {
    "lease_id": "lease_abc123"
  }

  Response:
  {
    "message": "Lease revoked successfully"
  }
  """
  def revoke(conn, %{"lease_id" => lease_id}) do
    case LeaseManager.revoke_lease(lease_id) do
      :ok ->
        Logger.info("Revoked lease", lease_id: lease_id)

        conn
        |> put_status(:ok)
        |> json(%{message: "Lease revoked successfully"})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Lease not found"})

      {:error, reason} ->
        Logger.error("Failed to revoke lease",
          lease_id: lease_id,
          error: inspect(reason)
        )

        conn
        |> put_status(:internal_server_error)
        |> json(%{error: "Failed to revoke lease: #{inspect(reason)}"})
    end
  end

  @doc """
  List active leases.

  GET /api/v1/sys/leases?engine_type=postgresql&limit=50

  Query parameters:
  - engine_type: Filter by engine type (optional)
  - agent_id: Filter by agent ID (optional)
  - limit: Maximum number of results (default: 100)

  Response:
  {
    "leases": [
      {
        "lease_id": "lease_abc123",
        "engine_type": "postgresql",
        "role": "readonly",
        "expires_at": "2025-10-27T12:00:00Z",
        "renewable": true
      }
    ],
    "total": 10
  }
  """
  def list(conn, params) do
    opts = [
      engine_type: params["engine_type"],
      agent_id: params["agent_id"],
      limit: parse_limit(params["limit"])
    ]

    leases = LeaseManager.list_active_leases(opts)

    lease_data =
      Enum.map(leases, fn lease ->
        %{
          lease_id: lease.id,
          engine_type: lease.engine_type,
          role: lease.role_name,
          expires_at: DateTime.to_iso8601(lease.expires_at),
          renewable: lease.renewable,
          agent_id: lease.agent_id
        }
      end)

    conn
    |> put_status(:ok)
    |> json(%{
      leases: lease_data,
      total: length(lease_data)
    })
  end

  @doc """
  Get lease statistics.

  GET /api/v1/sys/leases/stats

  Response:
  {
    "total_active": 25,
    "by_engine": {
      "postgresql": 20,
      "redis": 5
    },
    "expiring_soon": 3
  }
  """
  def stats(conn, _params) do
    stats = LeaseManager.get_stats()

    conn
    |> put_status(:ok)
    |> json(stats)
  end

  # Private Functions

  defp parse_limit(nil), do: 100
  defp parse_limit(limit) when is_binary(limit), do: String.to_integer(limit)
  defp parse_limit(limit) when is_integer(limit), do: limit

  # FIXME: Load from database - this is temporary for development
  defp get_role_config("readonly") do
    %{
      "connection" => %{
        "host" => System.get_env("PG_HOST", "localhost"),
        "port" => String.to_integer(System.get_env("PG_PORT", "5432")),
        "database" => System.get_env("PG_DATABASE", "secrethub_dev"),
        "username" => System.get_env("PG_ADMIN_USER", "secrethub"),
        "password" => System.get_env("PG_ADMIN_PASSWORD", "secrethub_dev_password")
      },
      "creation_statements" => [
        "CREATE USER {{username}} WITH PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
        "GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{username}};"
      ],
      "revocation_statements" => [
        "REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM {{username}};",
        "DROP USER IF EXISTS {{username}};"
      ],
      "default_ttl" => 3600,
      "max_ttl" => 86_400
    }
  end

  defp get_role_config("readwrite") do
    %{
      "connection" => %{
        "host" => System.get_env("PG_HOST", "localhost"),
        "port" => String.to_integer(System.get_env("PG_PORT", "5432")),
        "database" => System.get_env("PG_DATABASE", "secrethub_dev"),
        "username" => System.get_env("PG_ADMIN_USER", "secrethub"),
        "password" => System.get_env("PG_ADMIN_PASSWORD", "secrethub_dev_password")
      },
      "creation_statements" => [
        "CREATE USER {{username}} WITH PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {{username}};"
      ],
      "revocation_statements" => [
        "REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM {{username}};",
        "DROP USER IF EXISTS {{username}};"
      ],
      "default_ttl" => 1800,
      "max_ttl" => 43_200
    }
  end

  defp get_role_config(_), do: nil
end
