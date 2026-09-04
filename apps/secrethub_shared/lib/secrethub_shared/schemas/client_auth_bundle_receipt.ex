defmodule SecretHub.Shared.Schemas.ClientAuthBundleReceipt do
  @moduledoc """
  Schema for tracking Agent trust bundle convergence and errors.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @allowed_statuses ["applied", "failed"]

  schema "client_auth_bundle_receipts" do
    field(:agent_id, :string)
    field(:generation, :integer)
    field(:crl_number, :integer)
    field(:bundle_sha256, :string)
    field(:status, :string, default: "applied")
    field(:last_error_code, :string)
    field(:last_error_detail, :string)
    field(:applied_at, :utc_datetime)

    belongs_to(:authority, SecretHub.Shared.Schemas.ClientAuthAuthority,
      foreign_key: :client_auth_authority_id
    )

    timestamps(type: :utc_datetime)
  end

  @type t :: %__MODULE__{}

  def changeset(receipt, attrs) do
    receipt
    |> cast(attrs, [
      :agent_id,
      :client_auth_authority_id,
      :generation,
      :crl_number,
      :bundle_sha256,
      :status,
      :last_error_code,
      :last_error_detail,
      :applied_at
    ])
    |> validate_required([
      :agent_id,
      :client_auth_authority_id,
      :generation,
      :crl_number,
      :bundle_sha256,
      :status
    ])
    |> validate_inclusion(:status, @allowed_statuses)
    |> unique_constraint([:agent_id, :client_auth_authority_id])
  end
end
