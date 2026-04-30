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

    has_many(:secrets, SecretHub.Shared.Schemas.Secret, foreign_key: :rotator_id)

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
      :enabled
    ])
    |> validate_required([:slug, :name, :rotator_type])
    |> validate_format(:slug, ~r/^[a-z0-9][a-z0-9\-_]*$/,
      message: "must use lowercase letters, numbers, hyphens, or underscores"
    )
    |> validate_inclusion(:rotator_type, @rotator_types)
    |> unique_constraint(:slug)
  end
end
