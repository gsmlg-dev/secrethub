defmodule SecretHub.Shared.Schemas.SecretRotator do
  @moduledoc """
  Defines how a secret is allowed to be updated.

  A secret has exactly one rotator. The rotator can represent an internal
  workflow, a connected agent, an API-driven update path, or a manual web UI
  update path.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @rotator_types [:built_in, :agent, :api, :manual]

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "secret_rotators" do
    field(:slug, :string)
    field(:name, :string)
    field(:description, :string)
    field(:rotator_type, Ecto.Enum, values: @rotator_types)
    field(:config, :map, default: %{})
    field(:enabled, :boolean, default: true)
    field(:trigger_mode, Ecto.Enum, values: [:manual, :scheduled], default: :manual)
    field(:schedule_cron, :string)
    field(:grace_period_seconds, :integer, default: 300)
    field(:last_rotation_at, :utc_datetime)
    field(:last_rotation_status, Ecto.Enum, values: [:success, :failed, :in_progress, :pending])
    field(:last_rotation_error, :string)
    field(:next_rotation_at, :utc_datetime)
    field(:rotation_count, :integer, default: 0)
    field(:metadata, :map, default: %{})

    belongs_to(:secret, SecretHub.Shared.Schemas.Secret)
    belongs_to(:engine_configuration, SecretHub.Shared.Schemas.EngineConfiguration)

    timestamps(type: :utc_datetime)
  end

  def rotator_types, do: @rotator_types

  @doc false
  def changeset(rotator, attrs) do
    rotator
    |> cast(attrs, [
      :slug,
      :name,
      :description,
      :rotator_type,
      :config,
      :enabled,
      :secret_id,
      :engine_configuration_id,
      :trigger_mode,
      :schedule_cron,
      :grace_period_seconds,
      :last_rotation_at,
      :last_rotation_status,
      :last_rotation_error,
      :next_rotation_at,
      :rotation_count,
      :metadata
    ])
    |> validate_required([:slug, :name, :rotator_type])
    |> validate_format(:slug, ~r/^[a-z0-9][a-z0-9\-_]*$/,
      message: "must use lowercase letters, numbers, hyphens, or underscores"
    )
    |> validate_inclusion(:rotator_type, @rotator_types)
    |> validate_inclusion(:trigger_mode, [:manual, :scheduled])
    |> validate_number(:grace_period_seconds, greater_than_or_equal_to: 0)
    |> validate_number(:rotation_count, greater_than_or_equal_to: 0)
    |> foreign_key_constraint(:secret_id)
    |> foreign_key_constraint(:engine_configuration_id)
    |> unique_constraint(:slug)
    |> unique_constraint(:secret_id)
  end
end
