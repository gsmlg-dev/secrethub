defmodule SecretHub.Core.HumanAccess.PostgreSQLBackend do
  @moduledoc "PostgreSQL-only Human leases with fixed SQL templates and server-owned privileges."

  def validate_config(%{connection: connection, roles: roles})
      when is_list(connection) and is_map(roles) and map_size(roles) > 0 do
    if Keyword.keyword?(connection) and identifier?(connection[:database]) and
         Enum.all?(roles, fn {id, role} -> role_id?(id) and role_config?(role) end),
       do: :ok,
       else: {:error, :invalid_backend_config}
  end

  def validate_config(_), do: {:error, :invalid_backend_config}

  def create(mount, role_id, username, expires_at) do
    with :ok <- validate_config(mount),
         true <- handle?(username),
         %{schema: schema, privileges: privileges} <- Map.get(mount.roles, role_id) do
      password = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)

      execute(mount, fn conn ->
        create_role(conn, mount, username, password, expires_at, schema, privileges)
      end)
    else
      _ -> {:error, :invalid_backend_config}
    end
  end

  def renew(mount, username, expires_at) do
    with :ok <- validate_config(mount), true <- handle?(username) do
      execute(
        mount,
        &formatted(&1, "ALTER ROLE %I VALID UNTIL %L", [username, DateTime.to_iso8601(expires_at)])
      )
    else
      _ -> {:error, :invalid_backend_config}
    end
  end

  def revoke(mount, username) do
    with :ok <- validate_config(mount), true <- handle?(username) do
      execute(mount, fn conn -> revoke_role(conn, username) end)
    else
      _ -> {:error, :invalid_backend_config}
    end
  end

  defp execute(mount, fun) do
    task =
      Task.Supervisor.async_nolink(SecretHub.Core.HumanAccess.BackendSupervisor, fn ->
        execute_connection(mount, fun)
      end)

    case Task.yield(task, 10_000) || Task.shutdown(task, :brutal_kill) do
      {:ok, result} -> result
      _ -> {:error, :backend_unavailable}
    end
  rescue
    _ -> {:error, :backend_unavailable}
  catch
    :exit, _ -> {:error, :backend_unavailable}
  end

  defp execute_connection(mount, fun) do
    {:ok, deadline} = :timer.kill_after(10_000)

    try do
      # Direct Postgrex does not invoke Ecto's query logger. Never return SQL/errors to callers.
      # Client death alone does not cancel PostgreSQL statements waiting on a database lock.
      parameters =
        Keyword.put(Keyword.get(mount.connection, :parameters, []), :statement_timeout, "9000")

      opts =
        mount.connection
        |> Keyword.drop([:pool, :pool_size, :name])
        |> Keyword.merge(
          sync_connect: true,
          backoff_type: :stop,
          timeout: 5000,
          connect_timeout: 5000,
          parameters: parameters
        )

      case Postgrex.start_link(opts) do
        {:ok, connection} ->
          try do
            case fun.(connection) do
              :ok -> :ok
              {:ok, result} -> {:ok, result}
              _ -> {:error, :backend_unavailable}
            end
          after
            if Process.alive?(connection), do: GenServer.stop(connection)
          end

        {:error, _} ->
          {:error, :backend_unavailable}
      end
    rescue
      _ -> {:error, :backend_unavailable}
    catch
      :exit, _ -> {:error, :backend_unavailable}
    after
      :timer.cancel(deadline)
    end
  end

  defp formatted(conn, template, values) do
    placeholders = Enum.map_join(1..length(values), ",", &"$#{&1}::text")
    # PostgreSQL utility DDL cannot bind arguments; format's %I/%L performs server escaping.
    with {:ok, %{rows: [[sql]]}} <-
           Postgrex.query(conn, "SELECT format('#{template}',#{placeholders})", values),
         {:ok, _} <- Postgrex.query(conn, sql, []) do
      :ok
    else
      _ -> {:error, :backend_unavailable}
    end
  end

  defp privileges(conn, schema, username, permissions) do
    Enum.reduce_while(permissions, :ok, fn permission, :ok ->
      template =
        case permission do
          :select -> "GRANT SELECT ON ALL TABLES IN SCHEMA %I TO %I"
          :insert -> "GRANT INSERT ON ALL TABLES IN SCHEMA %I TO %I"
          :update -> "GRANT UPDATE ON ALL TABLES IN SCHEMA %I TO %I"
          :delete -> "GRANT DELETE ON ALL TABLES IN SCHEMA %I TO %I"
        end

      case formatted(conn, template, [schema, username]) do
        :ok -> {:cont, :ok}
        {:error, _} = error -> {:halt, error}
      end
    end)
  end

  defp role_config?(%{schema: schema, privileges: permissions}) do
    identifier?(schema) and is_list(permissions) and permissions != [] and
      length(permissions) <= 4 and
      Enum.all?(permissions, &(&1 in [:select, :insert, :update, :delete]))
  end

  defp role_config?(_), do: false

  defp identifier?(value),
    do: is_binary(value) and Regex.match?(~r/\A[a-zA-Z_][a-zA-Z0-9_]{0,62}\z/, value)

  defp role_id?(value),
    do: is_binary(value) and Regex.match?(~r/\A[a-zA-Z0-9_\/-]{1,128}\z/, value)

  defp handle?(value), do: is_binary(value) and Regex.match?(~r/\Ahuman_[a-f0-9]{32}\z/, value)

  defp create_role(conn, mount, username, password, expires_at, schema, privileges) do
    with :ok <-
           formatted(
             conn,
             "CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION PASSWORD %L VALID UNTIL %L",
             [username, password, DateTime.to_iso8601(expires_at)]
           ),
         :ok <-
           formatted(conn, "GRANT CONNECT ON DATABASE %I TO %I", [
             mount.connection[:database],
             username
           ]),
         :ok <- formatted(conn, "GRANT USAGE ON SCHEMA %I TO %I", [schema, username]),
         :ok <- privileges(conn, schema, username, privileges) do
      {:ok,
       %{
         username: username,
         password: password,
         database: mount.connection[:database],
         host: mount.connection[:hostname] || "localhost",
         port: mount.connection[:port] || 5432
       }}
    end
  end

  defp revoke_role(conn, username) do
    case Postgrex.query(conn, "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)", [
           username
         ]) do
      {:ok, %{rows: [[false]]}} ->
        :ok

      {:ok, %{rows: [[true]]}} ->
        with :ok <- formatted(conn, "ALTER ROLE %I NOLOGIN", [username]),
             {:ok, _} <-
               Postgrex.query(
                 conn,
                 "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename=$1 AND pid <> pg_backend_pid()",
                 [username]
               ),
             :ok <- formatted(conn, "DROP OWNED BY %I", [username]),
             do: formatted(conn, "DROP ROLE %I", [username])

      _ ->
        {:error, :backend_unavailable}
    end
  end
end
