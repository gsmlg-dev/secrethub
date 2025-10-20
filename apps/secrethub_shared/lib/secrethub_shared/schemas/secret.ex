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

  @type secret_type :: :static | :dynamic_role

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "secrets" do
    field(:secret_path, :string)
    field(:secret_type, Ecto.Enum, values: [:static, :dynamic_role])
    field(:encrypted_data, :binary)
    field(:version, :integer, default: 1)
    field(:metadata, :map, default: %{})
    field(:description, :string)
    field(:rotation_enabled, :boolean, default: false)
    field(:rotation_schedule, :string)
    field(:last_rotated_at, :utc_datetime)

    timestamps(type: :utc_datetime)
  end

  @doc """
  Changeset for creating or updating a secret.
  """
  def changeset(secret, attrs) do
    secret
    |> cast(attrs, [
      :secret_path,
      :secret_type,
      :encrypted_data,
      :version,
      :metadata,
      :description,
      :rotation_enabled,
      :rotation_schedule,
      :last_rotated_at
    ])
    |> validate_required([:secret_path, :secret_type, :encrypted_data])
    |> validate_secret_path()
    |> unique_constraint(:secret_path)
  end

  defp validate_secret_path(changeset) do
    changeset
    |> validate_format(:secret_path, ~r/^[a-z0-9\-]+(\.[a-z0-9\-]+)*$/,
      message: "must follow reverse domain notation (e.g., prod.db.postgres.password)"
    )
    |> validate_length(:secret_path, max: 500)
  end
end
