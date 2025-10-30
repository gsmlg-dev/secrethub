defmodule SecretHub.Core.EngineConfigurations do
  @moduledoc """
  Context for managing dynamic secret engine configurations.

  Provides functions to create, read, update, and delete engine configurations,
  as well as health check management and engine-specific operations.
  """

  import Ecto.Query
  require Logger

  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.EngineConfiguration

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
      case perform_health_check(config) do
        {:ok, status} ->
          update_health_status(config.id, status)
          {config.id, status}

        {:error, reason} ->
          Logger.error("Health check failed for #{config.name}: #{inspect(reason)}")
          update_health_status(config.id, :unhealthy, inspect(reason))
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

  defp check_postgresql_health(config) do
    # TODO: Implement actual PostgreSQL health check
    # For now, return healthy
    {:ok, :healthy}
  rescue
    e ->
      Logger.error("PostgreSQL health check failed: #{Exception.message(e)}")
      {:error, Exception.message(e)}
  end

  defp check_redis_health(config) do
    # TODO: Implement actual Redis health check
    # For now, return healthy
    {:ok, :healthy}
  rescue
    e ->
      Logger.error("Redis health check failed: #{Exception.message(e)}")
      {:error, Exception.message(e)}
  end

  defp check_aws_sts_health(config) do
    # TODO: Implement actual AWS STS health check
    # For now, return healthy
    {:ok, :healthy}
  rescue
    e ->
      Logger.error("AWS STS health check failed: #{Exception.message(e)}")
      {:error, Exception.message(e)}
  end

  defp test_postgresql_connection(config) do
    # TODO: Implement actual connection test
    :ok
  rescue
    e ->
      {:error, Exception.message(e)}
  end

  defp test_redis_connection(config) do
    # TODO: Implement actual connection test
    :ok
  rescue
    e ->
      {:error, Exception.message(e)}
  end

  defp test_aws_sts_connection(config) do
    # TODO: Implement actual connection test
    :ok
  rescue
    e ->
      {:error, Exception.message(e)}
  end
end
