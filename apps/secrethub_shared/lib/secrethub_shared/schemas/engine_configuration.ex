defmodule SecretHub.Shared.Schemas.EngineConfiguration do
  @moduledoc """
  Schema for dynamic secret engine configurations.

  Stores configuration for various dynamic secret engines like PostgreSQL,
  Redis, and AWS. Each configuration includes connection details, health
  check settings, and engine-specific parameters.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @engine_types [:postgresql, :redis, :aws_sts]
  @health_statuses [:healthy, :degraded, :unhealthy, :unknown]

  schema "engine_configurations" do
    field :name, :string
    field :engine_type, Ecto.Enum, values: @engine_types
    field :description, :string
    field :enabled, :boolean, default: true
    field :config, :map
    field :health_check_enabled, :boolean, default: true
    field :health_check_interval_seconds, :integer, default: 60
    field :last_health_check_at, :utc_datetime
    field :health_status, Ecto.Enum, values: @health_statuses, default: :unknown
    field :health_message, :string
    field :metadata, :map

    timestamps(type: :utc_datetime)
  end

  @doc """
  Changeset for creating/updating engine configurations.
  """
  def changeset(engine_config, attrs) do
    engine_config
    |> cast(attrs, [
      :name,
      :engine_type,
      :description,
      :enabled,
      :config,
      :health_check_enabled,
      :health_check_interval_seconds,
      :last_health_check_at,
      :health_status,
      :health_message,
      :metadata
    ])
    |> validate_required([:name, :engine_type, :config])
    |> validate_length(:name, min: 3, max: 100)
    |> validate_length(:description, max: 500)
    |> validate_number(:health_check_interval_seconds, greater_than_or_equal_to: 10)
    |> validate_engine_config()
    |> unique_constraint(:name)
  end

  @doc """
  Returns list of supported engine types.
  """
  def engine_types, do: @engine_types

  @doc """
  Returns list of possible health statuses.
  """
  def health_statuses, do: @health_statuses

  # Private functions

  defp validate_engine_config(changeset) do
    engine_type = get_field(changeset, :engine_type)
    config = get_field(changeset, :config)

    case {engine_type, config} do
      {nil, _} ->
        changeset

      {_, nil} ->
        add_error(changeset, :config, "cannot be nil")

      {:postgresql, config} ->
        validate_postgresql_config(changeset, config)

      {:redis, config} ->
        validate_redis_config(changeset, config)

      {:aws_sts, config} ->
        validate_aws_sts_config(changeset, config)

      _ ->
        changeset
    end
  end

  defp validate_postgresql_config(changeset, config) do
    required_fields = [:hostname, :port, :database, :username]

    missing_fields =
      Enum.filter(required_fields, fn field ->
        is_nil(Map.get(config, field)) and is_nil(Map.get(config, to_string(field)))
      end)

    if Enum.empty?(missing_fields) do
      changeset
    else
      add_error(
        changeset,
        :config,
        "PostgreSQL config missing required fields: #{inspect(missing_fields)}"
      )
    end
  end

  defp validate_redis_config(changeset, config) do
    has_host = Map.has_key?(config, :hostname) or Map.has_key?(config, "hostname")
    has_port = Map.has_key?(config, :port) or Map.has_key?(config, "port")

    cond do
      not has_host ->
        add_error(changeset, :config, "Redis config missing hostname")

      not has_port ->
        add_error(changeset, :config, "Redis config missing port")

      true ->
        changeset
    end
  end

  defp validate_aws_sts_config(changeset, config) do
    has_role = Map.has_key?(config, :role_arn) or Map.has_key?(config, "role_arn")
    has_region = Map.has_key?(config, :region) or Map.has_key?(config, "region")

    cond do
      not has_role ->
        add_error(changeset, :config, "AWS STS config missing role_arn")

      not has_region ->
        add_error(changeset, :config, "AWS STS config missing region")

      true ->
        changeset
    end
  end
end
