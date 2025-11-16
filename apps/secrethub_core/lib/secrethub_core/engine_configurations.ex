defmodule SecretHub.Core.EngineConfigurations do
  @moduledoc """
  Context for managing dynamic secret engine configurations.

  Provides functions to create, read, update, and delete engine configurations,
  as well as health check management and engine-specific operations.
  """

  import Ecto.Query
  require Logger

  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.{EngineConfiguration, EngineHealthCheck}

  @doc """
  Lists all engine configurations.

  ## Options
  - `:enabled_only` - Only return enabled configurations (default: false)
  - `:engine_type` - Filter by specific engine type
  """
  def list_configurations(opts \\ []) do
    query = from(e in EngineConfiguration, order_by: [desc: e.inserted_at])

    query =
      if opts[:enabled_only] do
        where(query, [e], e.enabled == true)
      else
        query
      end

    query =
      if engine_type = opts[:engine_type] do
        where(query, [e], e.engine_type == ^engine_type)
      else
        query
      end

    Repo.all(query)
  end

  @doc """
  Gets a single engine configuration by ID.
  """
  def get_configuration(id) do
    case Repo.get(EngineConfiguration, id) do
      nil -> {:error, :not_found}
      config -> {:ok, config}
    end
  end

  @doc """
  Gets an engine configuration by name.
  """
  def get_configuration_by_name(name) do
    case Repo.get_by(EngineConfiguration, name: name) do
      nil -> {:error, :not_found}
      config -> {:ok, config}
    end
  end

  @doc """
  Creates a new engine configuration.
  """
  def create_configuration(attrs) do
    %EngineConfiguration{}
    |> EngineConfiguration.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Updates an existing engine configuration.
  """
  def update_configuration(%EngineConfiguration{} = config, attrs) do
    config
    |> EngineConfiguration.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Deletes an engine configuration.
  """
  def delete_configuration(%EngineConfiguration{} = config) do
    Repo.delete(config)
  end

  @doc """
  Enables an engine configuration.
  """
  def enable_configuration(id) when is_binary(id) do
    with {:ok, config} <- get_configuration(id) do
      update_configuration(config, %{enabled: true})
    end
  end

  @doc """
  Disables an engine configuration.
  """
  def disable_configuration(id) when is_binary(id) do
    with {:ok, config} <- get_configuration(id) do
      update_configuration(config, %{enabled: false})
    end
  end

  @doc """
  Updates the health status of an engine configuration.
  """
  def update_health_status(id, status, message \\ nil) when is_binary(id) do
    with {:ok, config} <- get_configuration(id) do
      update_configuration(config, %{
        health_status: status,
        health_message: message,
        last_health_check_at: DateTime.utc_now()
      })
    end
  end

  @doc """
  Records a health check result in the history table.
  """
  def record_health_check(config_id, status, opts \\ []) do
    attrs = %{
      engine_configuration_id: config_id,
      checked_at: DateTime.utc_now(),
      status: status,
      response_time_ms: opts[:response_time_ms],
      error_message: opts[:error_message],
      metadata: opts[:metadata] || %{}
    }

    %EngineHealthCheck{}
    |> EngineHealthCheck.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Gets health check history for a configuration.

  ## Options
  - `:limit` - Maximum number of records to return (default: 100)
  - `:since` - Only return checks after this timestamp
  """
  def get_health_history(config_id, opts \\ []) do
    limit = opts[:limit] || 100

    query =
      from(h in EngineHealthCheck,
        where: h.engine_configuration_id == ^config_id,
        order_by: [desc: h.checked_at],
        limit: ^limit
      )

    query =
      if since = opts[:since] do
        where(query, [h], h.checked_at >= ^since)
      else
        query
      end

    Repo.all(query)
  end

  @doc """
  Gets health statistics for a configuration.

  Returns a map with:
  - `total_checks`: Total number of checks
  - `healthy_count`: Number of healthy checks
  - `unhealthy_count`: Number of unhealthy checks
  - `uptime_percentage`: Percentage of healthy checks
  - `avg_response_time`: Average response time in ms
  """
  def get_health_stats(config_id, opts \\ []) do
    since = opts[:since] || DateTime.add(DateTime.utc_now(), -7 * 24 * 3600, :second)

    query =
      from(h in EngineHealthCheck,
        where: h.engine_configuration_id == ^config_id and h.checked_at >= ^since,
        select: %{
          total: count(h.id),
          healthy: fragment("COUNT(CASE WHEN ? = 'healthy' THEN 1 END)", h.status),
          unhealthy: fragment("COUNT(CASE WHEN ? = 'unhealthy' THEN 1 END)", h.status),
          avg_response_time: avg(h.response_time_ms)
        }
      )

    case Repo.one(query) do
      nil ->
        %{
          total_checks: 0,
          healthy_count: 0,
          unhealthy_count: 0,
          uptime_percentage: 0.0,
          avg_response_time: nil
        }

      result ->
        uptime =
          if result.total > 0 do
            result.healthy / result.total * 100
          else
            0.0
          end

        %{
          total_checks: result.total,
          healthy_count: result.healthy,
          unhealthy_count: result.unhealthy,
          uptime_percentage: Float.round(uptime, 2),
          avg_response_time: result.avg_response_time && Float.round(result.avg_response_time, 2)
        }
    end
  end

  @doc """
  Performs a health check on an engine configuration.

  Returns `{:ok, status}` where status is :healthy, :degraded, or :unhealthy.
  """
  def perform_health_check(%EngineConfiguration{} = config) do
    if not config.health_check_enabled do
      {:ok, :unknown}
    else
      case config.engine_type do
        :postgresql -> check_postgresql_health(config)
        :redis -> check_redis_health(config)
        :aws_sts -> check_aws_sts_health(config)
        _ -> {:ok, :unknown}
      end
    end
  end

  @doc """
  Performs health checks on all enabled configurations.

  Returns a list of {config_id, status} tuples.
  """
  def perform_all_health_checks do
    list_configurations(enabled_only: true)
    |> Enum.filter(& &1.health_check_enabled)
    |> Enum.map(fn config ->
      start_time = System.monotonic_time(:millisecond)

      case perform_health_check(config) do
        {:ok, status} ->
          response_time = System.monotonic_time(:millisecond) - start_time
          update_health_status(config.id, status)
          record_health_check(config.id, status, response_time_ms: response_time)
          {config.id, status}

        {:error, reason} ->
          response_time = System.monotonic_time(:millisecond) - start_time
          Logger.error("Health check failed for #{config.name}: #{inspect(reason)}")
          update_health_status(config.id, :unhealthy, inspect(reason))

          record_health_check(config.id, :unhealthy,
            response_time_ms: response_time,
            error_message: inspect(reason)
          )

          {config.id, :unhealthy}
      end
    end)
  end

  @doc """
  Tests a connection with the given configuration without saving it.

  Returns `:ok` if the connection succeeds, `{:error, reason}` otherwise.
  """
  def test_connection(engine_type, config) when is_map(config) do
    case engine_type do
      :postgresql -> test_postgresql_connection(config)
      :redis -> test_redis_connection(config)
      :aws_sts -> test_aws_sts_connection(config)
      _ -> {:error, "Unsupported engine type"}
    end
  end

  # Private helper functions

  defp check_postgresql_health(_config) do
    # TODO: Implement actual PostgreSQL health check
    # For now, return healthy
    {:ok, :healthy}
  rescue
    e ->
      Logger.error("PostgreSQL health check failed: #{Exception.message(e)}")
      {:error, Exception.message(e)}
  end

  defp check_redis_health(config) do
    connection = config["connection"] || %{}

    opts = [
      host: connection["host"] || "localhost",
      port: connection["port"] || 6379,
      database: connection["database"] || 0
    ]

    opts =
      if connection["password"] do
        Keyword.put(opts, :password, connection["password"])
      else
        opts
      end

    opts =
      if connection["tls"] do
        Keyword.put(opts, :ssl, true)
      else
        opts
      end

    case Redix.start_link(opts) do
      {:ok, conn} ->
        result =
          case Redix.command(conn, ["PING"]) do
            {:ok, "PONG"} ->
              {:ok, :healthy}

            {:ok, response} ->
              {:error, "Unexpected PING response: #{inspect(response)}"}

            {:error, reason} ->
              {:error, inspect(reason)}
          end

        Redix.stop(conn)
        result

      {:error, reason} ->
        {:error, "Connection failed: #{inspect(reason)}"}
    end
  rescue
    e ->
      Logger.error("Redis health check failed: #{Exception.message(e)}")
      {:error, Exception.message(e)}
  end

  defp check_aws_sts_health(config) do
    connection = config["connection"] || %{}

    aws_config = [
      region: connection["region"] || "us-east-1"
    ]

    aws_config =
      if connection["access_key_id"] && connection["secret_access_key"] do
        Keyword.merge(aws_config,
          access_key_id: connection["access_key_id"],
          secret_access_key: connection["secret_access_key"]
        )
      else
        aws_config
      end

    # Test AWS STS by calling GetCallerIdentity
    case ExAws.STS.get_caller_identity()
         |> ExAws.request(aws_config) do
      {:ok, _response} ->
        {:ok, :healthy}

      {:error, {:http_error, _status, _response}} ->
        {:error, "AWS STS API call failed"}

      {:error, reason} ->
        {:error, inspect(reason)}
    end
  rescue
    e ->
      Logger.error("AWS STS health check failed: #{Exception.message(e)}")
      {:error, Exception.message(e)}
  end

  defp test_postgresql_connection(_config) do
    # TODO: Implement actual connection test
    :ok
  rescue
    e ->
      {:error, Exception.message(e)}
  end

  defp test_redis_connection(config) do
    case check_redis_health(config) do
      {:ok, :healthy} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  defp test_aws_sts_connection(config) do
    case check_aws_sts_health(config) do
      {:ok, :healthy} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end
end
