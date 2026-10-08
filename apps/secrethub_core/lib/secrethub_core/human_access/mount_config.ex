defmodule SecretHub.Core.HumanAccess.MountConfig do
  @moduledoc "Loads bounded, server-owned PostgreSQL mount JSON on each production boot."
  alias SecretHub.Core.HumanAccess.PostgreSQLBackend

  @max_bytes 1_048_576
  @connection_keys ~w(database username password hostname socket_dir port ssl)

  def load!(path) do
    case read(path) do
      {:ok, mounts} -> mounts
      {:error, _} -> raise ArgumentError, "HUMAN_DYNAMIC_MOUNTS_FILE: invalid_mount_config"
    end
  end

  def read(path) when is_binary(path) and byte_size(path) in 1..4096 do
    with {:ok, %{type: :regular}} <- File.stat(path),
         {:ok, json} <- File.open(path, [:read, :binary], &IO.binread(&1, @max_bytes + 1)),
         true <- is_binary(json) and byte_size(json) <= @max_bytes,
         {:ok, mounts} when is_map(mounts) and map_size(mounts) in 1..40 <- Jason.decode(json) do
      map_values(mounts, &mount/1)
    else
      _ -> {:error, :invalid_mount_config}
    end
  rescue
    _ -> {:error, :invalid_mount_config}
  end

  def read(_), do: {:error, :invalid_mount_config}

  defp mount(%{"engine" => "postgresql", "connection" => connection, "roles" => roles} = input)
       when map_size(input) == 3 and is_map(connection) and is_map(roles) and
              map_size(roles) in 1..50 do
    with {:ok, connection} <- connection(connection),
         {:ok, roles} <- map_values(roles, &role/1),
         backend = %{engine: PostgreSQLBackend, connection: connection, roles: roles},
         :ok <- PostgreSQLBackend.validate_config(backend) do
      {:ok, backend}
    else
      _ -> {:error, :invalid_mount_config}
    end
  end

  defp mount(_), do: {:error, :invalid_mount_config}

  defp connection(input) do
    valid =
      Enum.all?(input, fn {key, value} ->
        key in @connection_keys and connection_value?(key, value)
      end)

    location =
      case {Map.get(input, "hostname"), Map.get(input, "socket_dir")} do
        {hostname, nil} when is_binary(hostname) -> true
        {nil, socket} when is_binary(socket) -> true
        _ -> false
      end

    if valid and location and is_binary(input["database"]) and is_binary(input["username"]) do
      {:ok,
       Enum.map(input, fn
         {"database", value} -> {:database, value}
         {"username", value} -> {:username, value}
         {"password", value} -> {:password, value}
         {"hostname", value} -> {:hostname, value}
         {"socket_dir", value} -> {:socket_dir, value}
         {"port", value} -> {:port, value}
         {"ssl", value} -> {:ssl, value}
       end)}
    else
      {:error, :invalid_mount_config}
    end
  end

  defp connection_value?("database", value), do: identifier?(value)
  defp connection_value?("username", value), do: string?(value, 1, 128)
  defp connection_value?("password", value), do: string?(value, 0, 4096)

  defp connection_value?("hostname", value),
    do: is_binary(value) and Regex.match?(~r/\A[a-zA-Z0-9_.:\-]{1,253}\z/, value)

  defp connection_value?("socket_dir", value),
    do: string?(value, 1, 4096) and String.starts_with?(value, "/")

  defp connection_value?("port", value), do: is_integer(value) and value in 1..65_535
  defp connection_value?("ssl", value), do: is_boolean(value)
  defp connection_value?(_, _), do: false

  defp role(%{"schema" => schema, "privileges" => privileges} = input)
       when map_size(input) == 2 and is_list(privileges) and length(privileges) in 1..4 do
    if identifier?(schema) and Enum.all?(privileges, &(&1 in ~w(select insert update delete))) do
      permissions =
        Enum.map(privileges, fn
          "select" -> :select
          "insert" -> :insert
          "update" -> :update
          "delete" -> :delete
        end)

      {:ok, %{schema: schema, privileges: permissions}}
    else
      {:error, :invalid_mount_config}
    end
  end

  defp role(_), do: {:error, :invalid_mount_config}

  defp map_values(input, transform) do
    Enum.reduce_while(input, {:ok, %{}}, &map_entry(&1, &2, transform))
  end

  defp map_entry({id, value}, {:ok, acc}, transform) do
    with true <- is_binary(id) and Regex.match?(~r/\A[a-zA-Z0-9_\/-]{1,128}\z/, id),
         {:ok, parsed} <- transform.(value) do
      {:cont, {:ok, Map.put(acc, id, parsed)}}
    else
      _ -> {:halt, {:error, :invalid_mount_config}}
    end
  end

  defp identifier?(value),
    do: is_binary(value) and Regex.match?(~r/\A[a-zA-Z_][a-zA-Z0-9_]{0,62}\z/, value)

  defp string?(value, min, max),
    do:
      is_binary(value) and byte_size(value) in min..max and String.valid?(value) and
        not String.contains?(value, <<0>>)
end
