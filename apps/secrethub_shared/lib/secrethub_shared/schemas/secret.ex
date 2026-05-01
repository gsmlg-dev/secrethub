defmodule SecretHub.Shared.Schemas.Secret do
  @moduledoc """
  Schema for encrypted secret storage (both static and dynamic).

  Secrets follow reverse domain name notation:
  - prod.db.postgres.billing-db.password
  - staging.api.payment-gateway.apikey
  - dev.db.postgres.readonly.creds (dynamic secret role)

  All secret values are encrypted at the application layer using AES-256-GCM
  before being stored in the database.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @type secret_type :: :static | :dynamic

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "secrets" do
    field(:name, :string)
    field(:secret_path, :string)
    field(:value, :string, virtual: true)
    field(:secret_type, Ecto.Enum, values: [:static, :dynamic])
    field(:engine_type, :string, default: "static")
    field(:encrypted_data, :binary)
    field(:version, :integer, default: 1)
    field(:metadata, :map, default: %{})
    field(:description, :string)
    # 0 means the secret is always alive.
    field(:ttl_seconds, :integer, default: 0)
    field(:rotation_enabled, :boolean, default: false)
    field(:rotation_schedule, :string)
    # 7 days
    field(:rotation_period_hours, :integer, default: 168)
    field(:ttl_hours, :integer, default: 24)
    field(:last_rotated_at, :utc_datetime)
    field(:next_rotation_at, :utc_datetime)
    # active, rotating, error
    field(:status, :string, default: "active")

    # Version tracking
    field(:version_count, :integer, default: 1)
    field(:last_version_at, :utc_datetime)

    # Relationships
    belongs_to(:rotator, SecretHub.Shared.Schemas.SecretRotator)
    many_to_many(:policies, SecretHub.Shared.Schemas.Policy, join_through: "secrets_policies")
    has_many(:versions, SecretHub.Shared.Schemas.SecretVersion)
    belongs_to(:current_version, SecretHub.Shared.Schemas.SecretVersion)

    timestamps(type: :utc_datetime)
  end

  @doc """
  Changeset for creating or updating a secret.
  """
  def changeset(secret, attrs) do
    secret
    |> cast(attrs, [
      :name,
      :secret_path,
      :value,
      :rotator_id,
      :secret_type,
      :engine_type,
      :encrypted_data,
      :version,
      :metadata,
      :description,
      :ttl_seconds,
      :rotation_enabled,
      :rotation_schedule,
      :rotation_period_hours,
      :ttl_hours,
      :last_rotated_at,
      :next_rotation_at,
      :status
    ])
    |> put_secret_defaults()
    |> validate_required([:name, :secret_path])
    |> validate_secret_path()
    |> validate_format(:name, ~r/^[a-zA-Z0-9\s\-_]+$/,
      message: "must contain only letters, numbers, spaces, hyphens, and underscores"
    )
    |> validate_length(:name, min: 1, max: 100)
    |> validate_inclusion(:secret_type, [:static, :dynamic])
    |> validate_inclusion(:engine_type, ["static", "postgresql", "redis", "aws", "gcp"])
    |> validate_number(:ttl_seconds, greater_than_or_equal_to: 0)
    |> validate_number(:rotation_period_hours, greater_than: 0)
    |> validate_number(:ttl_hours, greater_than: 0)
    |> foreign_key_constraint(:rotator_id)
    |> unique_constraint(:secret_path)
  end

  defp put_secret_defaults(changeset) do
    changeset
    |> put_default(:secret_type, :static)
    |> put_default(:engine_type, "static")
    |> put_default(:ttl_seconds, 0)
  end

  defp put_default(changeset, field, default) do
    case get_field(changeset, field) do
      nil -> put_change(changeset, field, default)
      "" -> put_change(changeset, field, default)
      _value -> changeset
    end
  end

  defp validate_secret_path(changeset) do
    changeset
    |> validate_format(:secret_path, ~r/^[a-z0-9\-]+(\.[a-z0-9\-]+)*$/,
      message: "must follow reverse domain notation (e.g., prod.db.postgres.password)"
    )
    |> validate_length(:secret_path, max: 500)
  end
end
