defmodule SecretHub.Shared.Schemas.SecretVersion do
  @moduledoc """
  Schema for tracking historical versions of secrets.

  Each time a secret is updated, the previous version is archived in this table.
  This enables:
  - Full version history tracking
  - Rollback to previous versions
  - Version comparison
  - Audit trail of secret changes
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias SecretHub.Shared.Schemas.Secret

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "secret_versions" do
    belongs_to(:secret, Secret)
    field(:version_number, :integer)
    field(:encrypted_data, :binary)
    field(:metadata, :map)
    field(:description, :string)
    field(:created_by, :string)
    field(:change_description, :string)
    field(:archived_at, :utc_datetime)

    timestamps(type: :utc_datetime, updated_at: false)
  end

  @doc """
  Changeset for creating a new secret version.
  """
  def changeset(secret_version, attrs) do
    secret_version
    |> cast(attrs, [
      :secret_id,
      :version_number,
      :encrypted_data,
      :metadata,
      :description,
      :created_by,
      :change_description,
      :archived_at
    ])
    |> validate_required([:secret_id, :version_number, :encrypted_data, :archived_at])
    |> validate_number(:version_number, greater_than: 0)
    |> unique_constraint([:secret_id, :version_number])
    |> foreign_key_constraint(:secret_id)
  end

  @doc """
  Creates a version from the current state of a secret.
  """
  def from_secret(secret, created_by, change_description) do
    %__MODULE__{
      secret_id: secret.id,
      version_number: secret.version,
      encrypted_data: secret.encrypted_data,
      metadata: secret.metadata || %{},
      description: secret.description,
      created_by: created_by,
      change_description: change_description,
      archived_at: DateTime.utc_now()
    }
  end

  @doc """
  Gets the size of the encrypted data in bytes.
  """
  def data_size(%__MODULE__{encrypted_data: data}) when is_binary(data) do
    byte_size(data)
  end

  def data_size(_), do: 0

  @doc """
  Checks if this version is older than the given datetime.
  """
  def older_than?(%__MODULE__{archived_at: archived_at}, datetime) do
    DateTime.compare(archived_at, datetime) == :lt
  end

  @doc """
  Formats the version for display.
  """
  def format_version(%__MODULE__{version_number: version}), do: "v#{version}"
end
