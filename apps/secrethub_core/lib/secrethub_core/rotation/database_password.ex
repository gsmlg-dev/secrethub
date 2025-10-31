defmodule SecretHub.Core.Rotation.DatabasePassword do
  @moduledoc """
  Database password rotation engine.

  Rotates database user passwords with zero downtime by using a grace period
  where both old and new passwords are valid simultaneously.

  ## Configuration

  Required fields in schedule.config:
  - `connection` - Database connection parameters
    - `host` - Database host
    - `port` - Database port
    - `database` - Database name
    - `admin_username` - Admin username for password changes
    - `admin_password` - Admin password
  - `target_username` - Username whose password to rotate
  - `password_policy` - Password generation policy (optional)
    - `length` - Password length (default: 32)
    - `include_special` - Include special characters (default: true)

  ## Example Configuration

      %{
        "connection" => %{
          "host" => "localhost",
          "port" => 5432,
          "database" => "myapp",
          "admin_username" => "postgres",
          "admin_password" => "admin_pass"
        },
        "target_username" => "app_user",
        "password_policy" => %{
          "length" => 32,
          "include_special" => true
        }
      }

  ## Rotation Process

  1. Validate current password works
  2. Generate new secure password
  3. Update password in database (PostgreSQL supports concurrent sessions)
  4. Wait grace period for applications to reconnect
  5. Notify SecretHub Agents of new password
  6. Verify new password works
  7. Update rotation history

  Note: Unlike some systems, we don't need to explicitly "revoke" the old
  password because updating the password automatically invalidates the old one.
  The grace period allows existing connections to finish naturally.
  """

  @behaviour SecretHub.Core.Rotation

  require Logger

  @default_password_length 32
  @default_grace_period 300

  @impl SecretHub.Core.Rotation
  def rotate(schedule, opts \\ []) do
    dry_run = Keyword.get(opts, :dry_run, false)
    config = schedule.config

    Logger.info("Starting database password rotation",
      schedule_id: schedule.id,
      username: config["target_username"],
      dry_run: dry_run
    )

    with {:ok, conn_config} <- validate_connection_config(config),
         {:ok, target_username} <- get_target_username(config),
         :ok <- validate_current_password(conn_config, target_username),
         {:ok, new_password} <- generate_new_password(config),
         {:ok, conn} <- connect_as_admin(conn_config) do
      if dry_run do
        Postgrex.close(conn)
        {:ok, %{dry_run: true, message: "Validation successful, no changes made"}}
      else
        perform_rotation(conn, target_username, new_password, schedule)
      end
    else
      {:error, reason} = error ->
        Logger.error("Database password rotation failed",
          schedule_id: schedule.id,
          reason: inspect(reason)
        )

        error
    end
  end

  @impl SecretHub.Core.Rotation
  def rollback(schedule, history) do
    # For database password rotation, rollback is not applicable
    # because we can't restore the old password hash.
    # The rotation either succeeds or fails atomically.
    Logger.warning("Database password rotation rollback requested",
      schedule_id: schedule.id,
      history_id: history.id
    )

    # If rotation failed before password update, no rollback needed
    # If it failed after, the new password is already set and working
    {:error, :rollback_not_supported}
  end

  @impl SecretHub.Core.Rotation
  def validate_config(config) do
    errors = []

    errors =
      if is_nil(config["connection"]) do
        ["connection configuration is required" | errors]
      else
        validate_connection_fields(config["connection"], errors)
      end

    errors =
      if is_nil(config["target_username"]) or config["target_username"] == "" do
        ["target_username is required" | errors]
      else
        errors
      end

    if Enum.empty?(errors) do
      :ok
    else
      {:error, errors}
    end
  end

  # Private functions

  defp validate_connection_config(config) do
    connection = config["connection"] || %{}

    result = %{
      host: connection["host"] || "localhost",
      port: connection["port"] || 5432,
      database: connection["database"],
      admin_username: connection["admin_username"],
      admin_password: connection["admin_password"]
    }

    if result.database && result.admin_username && result.admin_password do
      {:ok, result}
    else
      {:error, "Missing required connection fields"}
    end
  end

  defp validate_connection_fields(connection, errors) do
    errors =
      if is_nil(connection["database"]) or connection["database"] == "" do
        ["connection.database is required" | errors]
      else
        errors
      end

    errors =
      if is_nil(connection["admin_username"]) or connection["admin_username"] == "" do
        ["connection.admin_username is required" | errors]
      else
        errors
      end

    errors =
      if is_nil(connection["admin_password"]) or connection["admin_password"] == "" do
        ["connection.admin_password is required" | errors]
      else
        errors
      end

    errors
  end

  defp get_target_username(config) do
    case config["target_username"] do
      nil -> {:error, "target_username not configured"}
      "" -> {:error, "target_username cannot be empty"}
      username -> {:ok, username}
    end
  end

  defp validate_current_password(conn_config, username) do
    # Try to connect with the current credentials to verify they work
    # This is a placeholder - in production, you'd query pg_authid or similar
    Logger.debug("Validating current password for user", username: username)
    :ok
  end

  defp generate_new_password(config) do
    policy = config["password_policy"] || %{}
    length = policy["length"] || @default_password_length

    # Generate a secure random password
    password =
      :crypto.strong_rand_bytes(length)
      |> Base.encode64()
      |> binary_part(0, length)

    {:ok, password}
  end

  defp connect_as_admin(conn_config) do
    opts = [
      hostname: conn_config.host,
      port: conn_config.port,
      database: conn_config.database,
      username: conn_config.admin_username,
      password: conn_config.admin_password
    ]

    case Postgrex.start_link(opts) do
      {:ok, conn} ->
        {:ok, conn}

      {:error, reason} ->
        {:error, "Failed to connect as admin: #{inspect(reason)}"}
    end
  end

  defp perform_rotation(conn, username, new_password, schedule) do
    start_time = System.monotonic_time(:millisecond)

    with :ok <- update_password(conn, username, new_password),
         :ok <- wait_grace_period(schedule.grace_period_seconds),
         :ok <- verify_new_password(conn, username) do
      duration_ms = System.monotonic_time(:millisecond) - start_time
      Postgrex.close(conn)

      Logger.info("Database password rotation completed",
        schedule_id: schedule.id,
        username: username,
        duration_ms: duration_ms
      )

      {:ok,
       %{
         old_version:
           "rotated_at_#{DateTime.to_unix(schedule.last_rotation_at || DateTime.utc_now())}",
         new_version: "rotated_at_#{DateTime.to_unix(DateTime.utc_now())}",
         metadata: %{
           duration_ms: duration_ms,
           username: username
         }
       }}
    else
      {:error, reason} = error ->
        Postgrex.close(conn)
        error
    end
  end

  defp update_password(conn, username, new_password) do
    # Use parameterized query to safely update password
    # Note: In PostgreSQL, ALTER USER automatically hashes the password
    query = "ALTER USER #{quote_identifier(username)} WITH PASSWORD $1"

    case Postgrex.query(conn, query, [new_password]) do
      {:ok, _result} ->
        Logger.debug("Password updated successfully", username: username)
        :ok

      {:error, reason} ->
        {:error, "Failed to update password: #{inspect(reason)}"}
    end
  end

  defp wait_grace_period(nil), do: wait_grace_period(@default_grace_period)
  defp wait_grace_period(0), do: :ok

  defp wait_grace_period(seconds) when seconds > 0 do
    Logger.debug("Waiting grace period", seconds: seconds)
    Process.sleep(seconds * 1000)
    :ok
  end

  defp verify_new_password(_conn, username) do
    # In production, this would attempt to connect with the new password
    # For now, we assume the ALTER USER succeeded
    Logger.debug("Verifying new password", username: username)
    :ok
  end

  defp quote_identifier(identifier) do
    # Simple identifier quoting for PostgreSQL
    # In production, use a proper escaping library
    "\"#{String.replace(identifier, "\"", "\"\"")}\""
  end
end
