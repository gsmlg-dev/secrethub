defmodule SecretHub.Core.Engines.Dynamic.PostgreSQL do
  @moduledoc """
  PostgreSQL dynamic secret engine.

  Generates temporary PostgreSQL database credentials with configurable TTL.
  Credentials are automatically revoked when leases expire.

  ## Configuration

  Each role requires:
  - `connection` - PostgreSQL connection parameters
    - `host` - Database host
    - `port` - Database port (default: 5432)
    - `database` - Database name
    - `username` - Admin username for creating temporary users
    - `password` - Admin password
  - `creation_statements` - SQL statements to execute when creating user
  - `revocation_statements` - SQL statements to execute when revoking user (optional)
  - `default_ttl` - Default TTL in seconds (default: 3600)
  - `max_ttl` - Maximum allowed TTL in seconds (default: 86400)

  ## Example Role Configuration

      %{
        "connection" => %{
          "host" => "localhost",
          "port" => 5432,
          "database" => "myapp_production",
          "username" => "secrethub_admin",
          "password" => "admin_password"
        },
        "creation_statements" => [
          "CREATE USER {{username}} WITH PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
          "GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{username}};"
        ],
        "revocation_statements" => [
          "REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {{username}};",
          "DROP USER IF EXISTS {{username}};"
        ],
        "default_ttl" => 3600,
        "max_ttl" => 86400
      }

  ## Template Variables

  The following template variables can be used in SQL statements:
  - `{{username}}` - Generated username (format: v_<role>_<random>_<timestamp>)
  - `{{password}}` - Generated password (secure random)
  - `{{expiration}}` - Expiration timestamp (ISO 8601)
  """

  @behaviour SecretHub.Core.Engines.Dynamic

  require Logger

  alias SecretHub.Core.Engines.Dynamic

  @default_ttl 3600
  @max_ttl 86_400
  @default_port 5432

  # Username format: v_<role>_<random_8_chars>_<unix_timestamp>
  # Example: v_readonly_a3f9k2m1_1698765432
  @username_prefix "v_"
  @username_length 8

  @impl Dynamic
  def generate_credentials(role_name, opts) do
    config = Keyword.fetch!(opts, :config)
    requested_ttl = Keyword.get(opts, :ttl)

    with {:ok, connection_config} <- validate_connection_config(config),
         {:ok, ttl} <- determine_ttl(requested_ttl, config),
         {:ok, username} <- generate_username(role_name),
         {:ok, password} <- generate_password(),
         {:ok, conn} <- connect(connection_config),
         :ok <- create_user(conn, config, username, password, ttl),
         :ok <- (GenServer.stop(conn); :ok) do
      Logger.info("Generated PostgreSQL credentials",
        role: role_name,
        username: username,
        ttl: ttl
      )

      {:ok,
       %{
         username: username,
         password: password,
         ttl: ttl,
         metadata: %{
           host: connection_config.host,
           port: connection_config.port,
           database: connection_config.database,
           role: role_name
         }
       }}
    else
      {:error, reason} = error ->
        Logger.error("Failed to generate PostgreSQL credentials",
          role: role_name,
          error: inspect(reason)
        )

        error
    end
  end

  @impl Dynamic
  def revoke_credentials(lease_id, credentials) do
    %{username: username, metadata: metadata} = credentials

    config = %{
      "connection" => %{
        "host" => metadata.host,
        "port" => metadata.port,
        "database" => metadata.database,
        # FIXME: Need to store admin credentials securely
        "username" => System.get_env("PG_ADMIN_USER", "postgres"),
        "password" => System.get_env("PG_ADMIN_PASSWORD", "")
      },
      "revocation_statements" => default_revocation_statements()
    }

    with {:ok, connection_config} <- validate_connection_config(config),
         {:ok, conn} <- connect(connection_config),
         :ok <- revoke_user(conn, config, username),
         :ok <- (GenServer.stop(conn); :ok) do
      Logger.info("Revoked PostgreSQL credentials",
        lease_id: lease_id,
        username: username
      )

      :ok
    else
      {:error, reason} = error ->
        Logger.error("Failed to revoke PostgreSQL credentials",
          lease_id: lease_id,
          username: username,
          error: inspect(reason)
        )

        error
    end
  end

  @impl Dynamic
  def renew_lease(lease_id, opts) do
    increment = Keyword.get(opts, :increment, @default_ttl)
    credentials = Keyword.fetch!(opts, :credentials)
    config = Keyword.fetch!(opts, :config)

    max_ttl = Map.get(config, "max_ttl", @max_ttl)
    current_ttl = Keyword.get(opts, :current_ttl, 0)

    new_ttl = min(current_ttl + increment, max_ttl)

    # PostgreSQL users created with VALID UNTIL cannot be extended
    # We'd need to ALTER USER to extend, but that requires reconnecting
    # For now, we just return the new TTL and let the lease manager track it
    Logger.info("Renewed PostgreSQL lease",
      lease_id: lease_id,
      username: credentials.username,
      new_ttl: new_ttl
    )

    {:ok, %{ttl: new_ttl}}
  end

  @impl Dynamic
  def validate_config(config) do
    errors = []

    errors =
      if is_nil(config["connection"]) do
        ["connection configuration is required" | errors]
      else
        validate_connection_fields(config["connection"], errors)
      end

    errors =
      if is_nil(config["creation_statements"]) or config["creation_statements"] == [] do
        ["creation_statements are required" | errors]
      else
        errors
      end

    errors =
      if config["default_ttl"] && !is_integer(config["default_ttl"]) do
        ["default_ttl must be an integer" | errors]
      else
        errors
      end

    errors =
      if config["max_ttl"] && !is_integer(config["max_ttl"]) do
        ["max_ttl must be an integer" | errors]
      else
        errors
      end

    case errors do
      [] -> :ok
      _ -> {:error, Enum.reverse(errors)}
    end
  end

  # Private Functions

  defp validate_connection_fields(connection, errors) do
    required_fields = ["host", "database", "username", "password"]

    Enum.reduce(required_fields, errors, fn field, acc ->
      if is_nil(connection[field]) or connection[field] == "" do
        ["connection.#{field} is required" | acc]
      else
        acc
      end
    end)
  end

  defp validate_connection_config(config) do
    connection = config["connection"]

    {:ok,
     %{
       host: connection["host"],
       port: connection["port"] || @default_port,
       database: connection["database"],
       username: connection["username"],
       password: connection["password"]
     }}
  end

  defp determine_ttl(requested_ttl, config) do
    default = Map.get(config, "default_ttl", @default_ttl)
    max = Map.get(config, "max_ttl", @max_ttl)

    ttl =
      case requested_ttl do
        nil -> default
        val when val > max -> max
        val -> val
      end

    {:ok, ttl}
  end

  defp generate_username(role_name) do
    # Format: v_<role>_<random_8>_<timestamp>
    # Example: v_readonly_a3f9k2m1_1698765432
    random_part =
      @username_length
      |> :crypto.strong_rand_bytes()
      |> Base.encode32(case: :lower, padding: false)
      |> binary_part(0, @username_length)

    timestamp = System.system_time(:second)

    # Sanitize role name (remove non-alphanumeric chars, limit length)
    safe_role =
      role_name
      |> String.replace(~r/[^a-z0-9_]/, "_")
      |> String.slice(0, 20)

    username = "#{@username_prefix}#{safe_role}_#{random_part}_#{timestamp}"

    {:ok, username}
  end

  defp generate_password do
    # Generate 32-character secure random password
    password =
      32
      |> :crypto.strong_rand_bytes()
      |> Base.encode64()
      |> binary_part(0, 32)

    {:ok, password}
  end

  defp connect(config) do
    Postgrex.start_link(
      hostname: config.host,
      port: config.port,
      database: config.database,
      username: config.username,
      password: config.password
    )
  end

  defp create_user(conn, config, username, password, ttl) do
    statements = config["creation_statements"] || default_creation_statements()
    expiration = DateTime.add(DateTime.utc_now(), ttl, :second)

    variables = %{
      "username" => username,
      "password" => password,
      "expiration" => DateTime.to_iso8601(expiration)
    }

    execute_statements(conn, statements, variables)
  end

  defp revoke_user(conn, config, username) do
    statements = config["revocation_statements"] || default_revocation_statements()

    variables = %{
      "username" => username
    }

    execute_statements(conn, statements, variables)
  end

  defp execute_statements(conn, statements, variables) do
    Enum.reduce_while(statements, :ok, fn statement, :ok ->
      rendered_sql = render_template(statement, variables)

      case Postgrex.query(conn, rendered_sql, []) do
        {:ok, _} ->
          {:cont, :ok}

        {:error, %Postgrex.Error{} = error} ->
          {:halt, {:error, "PostgreSQL error: #{error.postgres.message}"}}

        {:error, reason} ->
          {:halt, {:error, reason}}
      end
    end)
  end

  defp render_template(template, variables) do
    Enum.reduce(variables, template, fn {key, value}, acc ->
      String.replace(acc, "{{#{key}}}", to_string(value))
    end)
  end

  defp default_creation_statements do
    [
      "CREATE USER {{username}} WITH PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';"
    ]
  end

  defp default_revocation_statements do
    [
      "REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM {{username}};",
      "REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM {{username}};",
      "REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM {{username}};",
      "DROP USER IF EXISTS {{username}};"
    ]
  end
end
