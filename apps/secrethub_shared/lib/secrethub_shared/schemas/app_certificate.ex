defmodule SecretHub.Shared.Schemas.AppCertificate do
  @moduledoc """
  Ecto schema for application certificate associations.

  Tracks which certificates belong to which applications for:
  - Certificate lifecycle management (renewal, revocation)
  - Audit trail of certificate issuance
  - Policy enforcement
  """
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "app_certificates" do
    field(:issued_at, :utc_datetime)
    field(:expires_at, :utc_datetime)
    field(:revoked_at, :utc_datetime)
    field(:revocation_reason, :string)

    belongs_to(:app, SecretHub.Shared.Schemas.Application, foreign_key: :app_id, type: :binary_id)

    belongs_to(:certificate, SecretHub.Shared.Schemas.Certificate,
      foreign_key: :certificate_id,
      type: :binary_id
    )

    timestamps(type: :utc_datetime, updated_at: false)
  end

  @doc """
  Changeset for app certificate association.
  """
  def changeset(app_cert, attrs) do
    app_cert
    |> cast(attrs, [
      :app_id,
      :certificate_id,
      :issued_at,
      :expires_at,
      :revoked_at,
      :revocation_reason
    ])
    |> validate_required([:app_id, :certificate_id, :issued_at, :expires_at])
    |> unique_constraint([:app_id, :certificate_id])
    |> foreign_key_constraint(:app_id)
    |> foreign_key_constraint(:certificate_id)
  end
end
