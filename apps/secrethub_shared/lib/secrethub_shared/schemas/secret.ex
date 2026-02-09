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
    field(:secret_type, Ecto.Enum, values: [:static, :dynamic])
    field(:engine_type, :string, default: "static")
    field(:encrypted_data, :binary)
    field(:version, :integer, default: 1)
    field(:metadata, :map, default: %{})
    field(:description, :string)
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
      :secret_type,
      :engine_type,
      :encrypted_data,
      :version,
      :metadata,
      :description,
      :rotation_enabled,
      :rotation_schedule,
      :rotation_period_hours,
      :ttl_hours,
      :last_rotated_at,
      :next_rotation_at,
      :status
    ])
    |> validate_required([:name, :secret_path, :secret_type, :engine_type])
    |> validate_secret_path()
    |> validate_format(:name, ~r/^[a-zA-Z0-9\s\-_]+$/,
      message: "must contain only letters, numbers, spaces, hyphens, and underscores"
    )
    |> validate_length(:name, min: 1, max: 100)
    |> validate_inclusion(:secret_type, [:static, :dynamic])
    |> validate_inclusion(:engine_type, ["static", "postgresql", "redis", "aws", "gcp"])
    |> validate_number(:rotation_period_hours, greater_than: 0)
    |> validate_number(:ttl_hours, greater_than: 0)
    |> unique_constraint(:secret_path)
  end

  @doc """
  Create a new secret in the database.

  Note: This is a mock implementation. Actual creation logic will be
  implemented in SecretHub.Core.Secrets module.
  """
  def create(changeset) do
    case changeset.valid? do
      true ->
        # Mock successful creation - use get_field to get merged changes + data values
        secret = %{
          id: Ecto.UUID.generate(),
          name: get_field(changeset, :name),
          secret_path: get_field(changeset, :secret_path),
          secret_type: get_field(changeset, :secret_type),
          engine_type: get_field(changeset, :engine_type, "static"),
          description: get_field(changeset, :description),
          rotation_period_hours: get_field(changeset, :rotation_period_hours, 168),
          ttl_hours: get_field(changeset, :ttl_hours, 24),
          status: "active",
          last_rotated_at: DateTime.utc_now() |> DateTime.truncate(:second),
          next_rotation_at:
            calculate_next_rotation(get_field(changeset, :rotation_period_hours, 168))
        }

        {:ok, secret}

      false ->
        {:error, changeset}
    end
  end

  @doc """
  Update an existing secret.

  Note: This is a mock implementation. Actual update logic will be
  implemented in SecretHub.Core.Secrets module.
  """
  def update(secret_id, attrs) do
    secret = %{
      id: secret_id,
      name: Map.get(attrs, "name"),
      secret_path: Map.get(attrs, "secret_path"),
      secret_type: String.to_atom(Map.get(attrs, "type", "static")),
      engine_type: Map.get(attrs, "engine_type"),
      description: Map.get(attrs, "description"),
      rotation_period_hours: String.to_integer(Map.get(attrs, "rotation_period_hours", "168")),
      ttl_hours: String.to_integer(Map.get(attrs, "ttl_hours", "24")),
      status: "active",
      updated_at: DateTime.utc_now() |> DateTime.truncate(:second)
    }

    {:ok, secret}
  end

  @doc """
  Delete a secret.

  Note: This is a mock implementation. Actual deletion logic will be
  implemented in SecretHub.Core.Secrets module.
  """
  def delete(_secret_id) do
    :ok
  end

  defp calculate_next_rotation(rotation_hours) do
    DateTime.add(DateTime.utc_now() |> DateTime.truncate(:second), rotation_hours * 3600, :second)
  end

  defp validate_secret_path(changeset) do
    changeset
    |> validate_format(:secret_path, ~r/^[a-z0-9\-]+(\.[a-z0-9\-]+)*$/,
      message: "must follow reverse domain notation (e.g., prod.db.postgres.password)"
    )
    |> validate_length(:secret_path, max: 500)
  end
end
