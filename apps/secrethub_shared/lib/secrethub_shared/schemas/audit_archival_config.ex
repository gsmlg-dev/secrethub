defmodule SecretHub.Shared.Schemas.AuditArchivalConfig do
  @moduledoc """
  Schema for audit log archival configuration.

  Stores configuration for archiving audit logs to external storage providers
  like AWS S3 or Google Cloud Storage.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @providers [:s3, :gcs, :azure_blob]
  @statuses [:success, :failed, :pending, :in_progress]

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "audit_archival_configs" do
    field(:provider, Ecto.Enum, values: @providers)
    field(:enabled, :boolean, default: false)
    field(:config, :map, default: %{})
    field(:retention_days, :integer, default: 90)
    field(:archive_after_days, :integer, default: 30)
    field(:last_archival_at, :utc_datetime)
    field(:last_archival_status, Ecto.Enum, values: @statuses)
    field(:last_archival_error, :string)
    field(:metadata, :map, default: %{})

    timestamps(type: :utc_datetime)
  end

  @doc """
  Creates a changeset for creating an archival configuration.
  """
  def changeset(archival_config, attrs) do
    archival_config
    |> cast(attrs, [
      :provider,
      :enabled,
      :config,
      :retention_days,
      :archive_after_days,
      :metadata
    ])
    |> validate_required([:provider, :config])
    |> validate_inclusion(:provider, @providers)
    |> validate_number(:retention_days, greater_than: 0)
    |> validate_number(:archive_after_days, greater_than_or_equal_to: 0)
    |> validate_number(:archive_after_days, less_than: :retention_days)
    |> validate_config_for_provider()
    |> unique_constraint(:provider)
  end

  @doc """
  Creates a changeset for updating archival configuration.
  """
  def update_changeset(archival_config, attrs) do
    archival_config
    |> cast(attrs, [:enabled, :config, :retention_days, :archive_after_days, :metadata])
    |> validate_number(:retention_days, greater_than: 0)
    |> validate_number(:archive_after_days, greater_than_or_equal_to: 0)
    |> validate_number(:archive_after_days, less_than: :retention_days)
    |> validate_config_for_provider()
  end

  @doc """
  Updates archival status after a job completes.
  """
  def update_status(archival_config, status, opts \\ []) do
    error = Keyword.get(opts, :error)

    archival_config
    |> change(
      last_archival_at: DateTime.utc_now(),
      last_archival_status: status,
      last_archival_error: error
    )
  end

  defp validate_config_for_provider(changeset) do
    provider = get_field(changeset, :provider)
    config = get_field(changeset, :config)

    case provider do
      :s3 -> validate_s3_config(changeset, config)
      :gcs -> validate_gcs_config(changeset, config)
      :azure_blob -> validate_azure_config(changeset, config)
      _ -> changeset
    end
  end

  defp validate_s3_config(changeset, config) when is_map(config) do
    required_keys = ["bucket", "region"]

    if Enum.all?(required_keys, &Map.has_key?(config, &1)) do
      changeset
    else
      add_error(changeset, :config, "S3 config must include: bucket, region")
    end
  end

  defp validate_s3_config(changeset, _config) do
    add_error(changeset, :config, "config must be a map")
  end

  defp validate_gcs_config(changeset, config) when is_map(config) do
    required_keys = ["bucket", "project_id"]

    if Enum.all?(required_keys, &Map.has_key?(config, &1)) do
      changeset
    else
      add_error(changeset, :config, "GCS config must include: bucket, project_id")
    end
  end

  defp validate_gcs_config(changeset, _config) do
    add_error(changeset, :config, "config must be a map")
  end

  defp validate_azure_config(changeset, config) when is_map(config) do
    required_keys = ["container", "account_name"]

    if Enum.all?(required_keys, &Map.has_key?(config, &1)) do
      changeset
    else
      add_error(changeset, :config, "Azure config must include: container, account_name")
    end
  end

  defp validate_azure_config(changeset, _config) do
    add_error(changeset, :config, "config must be a map")
  end
end
