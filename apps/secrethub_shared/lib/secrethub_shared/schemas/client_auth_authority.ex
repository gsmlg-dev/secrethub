defmodule SecretHub.Shared.Schemas.ClientAuthAuthority do
  @moduledoc """
  Schema for the Client Authentication PKI Authority.

  Manages the singleton `client-auth` CA authority and tracks current CRL
  number and generation for deterministic trust bundles.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @allowed_statuses ["initializing", "active", "disabled", "failed"]
  @allowed_key_algorithms ["ecdsa_p384", "rsa_4096"]

  schema "client_auth_authorities" do
    field(:slug, :string, default: "client-auth")
    field(:name, :string)
    field(:status, :string, default: "initializing")
    field(:current_generation, :integer, default: 0)
    field(:current_crl_number, :integer, default: 0)
    field(:key_algorithm, :string, default: "ecdsa_p384")
    field(:default_ttl_seconds, :integer, default: 2_592_000)
    field(:max_ttl_seconds, :integer, default: 7_776_000)

    belongs_to(:ca_certificate, SecretHub.Shared.Schemas.Certificate,
      foreign_key: :ca_certificate_id
    )

    belongs_to(:current_crl, SecretHub.Shared.Schemas.ClientAuthCrl, foreign_key: :current_crl_id)

    has_many(:crls, SecretHub.Shared.Schemas.ClientAuthCrl, foreign_key: :authority_id)

    has_many(:certificates, SecretHub.Shared.Schemas.Certificate,
      foreign_key: :client_auth_authority_id
    )

    has_many(:bundle_receipts, SecretHub.Shared.Schemas.ClientAuthBundleReceipt,
      foreign_key: :client_auth_authority_id
    )

    timestamps(type: :utc_datetime)
  end

  @type t :: %__MODULE__{}

  def changeset(authority, attrs) do
    authority
    |> cast(attrs, [
      :slug,
      :name,
      :status,
      :ca_certificate_id,
      :current_crl_id,
      :current_generation,
      :current_crl_number,
      :key_algorithm,
      :default_ttl_seconds,
      :max_ttl_seconds
    ])
    |> validate_required([
      :slug,
      :name,
      :status,
      :current_generation,
      :current_crl_number,
      :key_algorithm,
      :default_ttl_seconds,
      :max_ttl_seconds
    ])
    |> validate_inclusion(:status, @allowed_statuses)
    |> validate_inclusion(:key_algorithm, @allowed_key_algorithms)
    |> validate_number(:default_ttl_seconds, greater_than: 0)
    |> validate_number(:max_ttl_seconds, greater_than: 0)
    |> validate_ttl_bounds()
    |> unique_constraint(:slug)
  end

  defp validate_ttl_bounds(changeset) do
    default_ttl = get_field(changeset, :default_ttl_seconds)
    max_ttl = get_field(changeset, :max_ttl_seconds)

    if default_ttl && max_ttl && default_ttl > max_ttl do
      add_error(changeset, :default_ttl_seconds, "cannot be greater than max_ttl_seconds")
    else
      changeset
    end
  end
end
