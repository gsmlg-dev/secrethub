defmodule SecretHub.Shared.Schemas.AppBootstrapToken do
  @moduledoc """
  Ecto schema for application bootstrap tokens.

  Bootstrap tokens are one-time use tokens that allow applications to
  obtain their first certificate from Core PKI.

  Token lifecycle:
  1. Generated when application is registered
  2. Token given to admin (valid for 1 hour by default)
  3. Application uses token to request certificate
  4. Token is marked as used and cannot be reused
  5. Expired tokens are cleaned up after 24 hours
  """
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "app_bootstrap_tokens" do
    field(:token_hash, :string)
    field(:used, :boolean, default: false)
    field(:used_at, :utc_datetime)
    field(:expires_at, :utc_datetime)

    belongs_to(:app, SecretHub.Shared.Schemas.Application, foreign_key: :app_id, type: :binary_id)

    timestamps(type: :utc_datetime, updated_at: false)
  end

  @doc """
  Changeset for bootstrap token.
  """
  def changeset(token, attrs) do
    token
    |> cast(attrs, [:app_id, :token_hash, :used, :used_at, :expires_at])
    |> validate_required([:app_id, :token_hash, :expires_at])
    |> unique_constraint(:token_hash)
    |> foreign_key_constraint(:app_id)
  end
end
