defmodule SecretHub.Core.Engines.Dynamic.Redis do
  @moduledoc """
  Redis ACL dynamic secret engine.

  Generates temporary Redis ACL user credentials with configurable TTL.
  Credentials are automatically revoked when leases expire.

  ## Configuration

  Each role requires:
  - `connection` - Redis connection parameters
    - `host` - Redis host
    - `port` - Redis port (default: 6379)
    - `password` - Admin password (optional)
    - `database` - Database number (default: 0)
    - `tls` - Enable TLS connection (default: false)
  - `acl_rules` - Redis ACL rules for the user
  - `default_ttl` - Default TTL in seconds (default: 3600)
  - `max_ttl` - Maximum allowed TTL in seconds (default: 86400)

  ## Example Role Configuration

      %{
        "connection" => %{
          "host" => "localhost",
          "port" => 6379,
          "password" => "admin_password",
          "database" => 0,
          "tls" => false
        },
        "acl_rules" => [
          "~cached:*",
          "+get",
          "+set",
          "+del",
          "-@all"
        ],
        "default_ttl" => 3600,
        "max_ttl" => 86400
      }

  ## Template Variables

  The following template variables can be used in ACL rules:
  - `{{username}}` - Generated username (format: v_<role>_<random>_<timestamp>)
  - `{{password}}` - Generated password (secure random)

  ## Redis ACL Rules

  Common ACL patterns:
  - `~pattern` - Key pattern (e.g., `~cached:*` allows keys starting with `cached:`)
  - `+command` - Allow command (e.g., `+get` allows GET)
  - `-command` - Deny command (e.g., `-flushdb` denies FLUSHDB)
  - `+@category` - Allow command category (e.g., `+@read` allows all read commands)
  - `-@category` - Deny command category (e.g., `-@dangerous` denies dangerous commands)
  """

  @behaviour SecretHub.Core.Engines.Dynamic

  require Logger

  alias SecretHub.Core.Engines.Dynamic

  @default_ttl 3600
  @max_ttl 86_400
  @default_port 6379

  # Username format: v_<role>_<random_8_chars>_<unix_timestamp>
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
         :ok <- create_user(conn, config, username, password),
         :ok <- Redix.stop(conn) do
      Logger.info("Generated Redis ACL credentials",
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
        Logger.error("Failed to generate Redis credentials",
          role: role_name,
          reason: inspect(reason)
        )

        error
    end
  end

  @impl Dynamic
  def revoke_credentials(lease_id, credentials) do
    username = credentials["username"] || credentials[:username]
    metadata = credentials["metadata"] || credentials[:metadata] || %{}

    connection_config = %{
      host: metadata["host"] || metadata[:host] || "localhost",
      port: metadata["port"] || metadata[:port] || @default_port,
      password: metadata["admin_password"] || metadata[:admin_password],
      database: metadata["database"] || metadata[:database] || 0,
      tls: metadata["tls"] || metadata[:tls] || false
    }

    with {:ok, conn} <- connect(connection_config),
         :ok <- delete_user(conn, username),
         :ok <- Redix.stop(conn) do
      Logger.info("Revoked Redis ACL credentials",
        lease_id: lease_id,
        username: username
      )

      :ok
    else
      {:error, reason} = error ->
        Logger.error("Failed to revoke Redis credentials",
          lease_id: lease_id,
          username: username,
          reason: inspect(reason)
        )

        error
    end
  end

  @impl Dynamic
  def renew_lease(lease_id, opts) do
    requested_increment = Keyword.get(opts, :increment, @default_ttl)
    current_credentials = Keyword.get(opts, :credentials, %{})
    metadata = current_credentials["metadata"] || current_credentials[:metadata] || %{}

    max_ttl = metadata["max_ttl"] || metadata[:max_ttl] || @max_ttl
    new_ttl = min(requested_increment, max_ttl)

    Logger.info("Renewed Redis lease",
      lease_id: lease_id,
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
      if is_nil(config["acl_rules"]) or config["acl_rules"] == [] do
        ["acl_rules are required" | errors]
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
      port: connection["port"] || @default_port,
      password: connection["password"],
      database: connection["database"] || 0,
      tls: connection["tls"] || false
    }

    {:ok, result}
  end

  defp validate_connection_fields(connection, errors) do
    errors =
      if is_nil(connection["host"]) or connection["host"] == "" do
        ["connection.host is required" | errors]
      else
        errors
      end

    errors =
      case connection["port"] do
        nil ->
          errors

        port when is_integer(port) and port > 0 and port < 65_536 ->
          errors

        _ ->
          ["connection.port must be a valid port number (1-65535)" | errors]
      end

    errors
  end

  defp determine_ttl(requested_ttl, config) do
    default_ttl = config["default_ttl"] || @default_ttl
    max_ttl = config["max_ttl"] || @max_ttl

    ttl =
      case requested_ttl do
        nil -> default_ttl
        value when value > max_ttl -> max_ttl
        value -> value
      end

    {:ok, ttl}
  end

  defp generate_username(role_name) do
    random =
      :crypto.strong_rand_bytes(@username_length)
      |> Base.encode32(case: :lower, padding: false)
      |> binary_part(0, @username_length)

    timestamp = System.system_time(:second)
    username = "#{@username_prefix}#{sanitize_role_name(role_name)}_#{random}_#{timestamp}"

    {:ok, username}
  end

  defp sanitize_role_name(role_name) do
    role_name
    |> String.downcase()
    |> String.replace(~r/[^a-z0-9]/, "_")
    |> String.slice(0, 20)
  end

  defp generate_password do
    password =
      :crypto.strong_rand_bytes(32)
      |> Base.encode64()

    {:ok, password}
  end

  defp connect(config) do
    opts = [
      host: config.host,
      port: config.port,
      database: config.database
    ]

    opts =
      if config.password do
        Keyword.put(opts, :password, config.password)
      else
        opts
      end

    opts =
      if config.tls do
        Keyword.put(opts, :ssl, true)
      else
        opts
      end

    case Redix.start_link(opts) do
      {:ok, conn} ->
        {:ok, conn}

      {:error, reason} ->
        {:error, "Failed to connect to Redis: #{inspect(reason)}"}
    end
  end

  defp create_user(conn, config, username, password) do
    acl_rules = config["acl_rules"] || []

    # Build ACL command: ACL SETUSER <username> on >password ~pattern +command ...
    acl_parts =
      [
        "on",
        ">#{password}"
      ] ++ acl_rules

    command = ["ACL", "SETUSER", username] ++ acl_parts

    case Redix.command(conn, command) do
      {:ok, "OK"} ->
        :ok

      {:ok, response} ->
        {:error, "Unexpected response from ACL SETUSER: #{inspect(response)}"}

      {:error, reason} ->
        {:error, "Failed to create Redis user: #{inspect(reason)}"}
    end
  end

  defp delete_user(conn, username) do
    case Redix.command(conn, ["ACL", "DELUSER", username]) do
      {:ok, 1} ->
        :ok

      {:ok, 0} ->
        # User already deleted or never existed
        Logger.warning("Redis user not found during deletion", username: username)
        :ok

      {:ok, response} ->
        {:error, "Unexpected response from ACL DELUSER: #{inspect(response)}"}

      {:error, reason} ->
        {:error, "Failed to delete Redis user: #{inspect(reason)}"}
    end
  end
end
