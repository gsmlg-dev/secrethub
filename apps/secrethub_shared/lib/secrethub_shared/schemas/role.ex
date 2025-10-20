defmodule SecretHub.Shared.Schemas.Role do
  @moduledoc """
  Schema for AppRole authentication.

  AppRole is the primary authentication method for Agents during bootstrap.
  It uses a RoleID (identifier) and SecretID (secret) pair to authenticate.

  Bootstrap flow:
  1. Administrator creates a Role with specific policies
  2. RoleID and SecretID are generated
  3. RoleID is configured in Agent
  4. SecretID is securely delivered to Agent (one-time use recommended)
  5. Agent authenticates with RoleID + SecretID
  6. Agent receives client certificate for mTLS
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "roles" do
    # Role identification
    field :role_id, :binary_id
    field :role_name, :string

    # SecretID is hashed and stored (never stored in plaintext)
    # The actual SecretID is only shown once during generation
    field :secret_id_hash, :string
    field :secret_id_accessor, :string

    # Policy bindings
    field :policies, {:array, :string}, default: []
    field :token_policies, {:array, :string}, default: []

    # TTL configuration
    field :ttl_seconds, :integer, default: 3600
    field :max_ttl_seconds, :integer, default: 86400

    # Secret ID configuration
    field :bind_secret_id, :boolean, default: true
    field :secret_id_num_uses, :integer, default: 0
    field :secret_id_ttl_seconds, :integer

    # CIDR restrictions (optional)
    field :bound_cidr_list, {:array, :string}, default: []

    # Metadata
    field :metadata, :map, default: %{}
    field :description, :string

    # Enable/disable role
    field :enabled, :boolean, default: true

    timestamps(type: :utc_datetime)
  end

  @doc """
  Changeset for creating or updating a role.
  """
  def changeset(role, attrs) do
    role
    |> cast(attrs, [
      :role_id,
      :role_name,
      :secret_id_hash,
      :secret_id_accessor,
      :policies,
      :token_policies,
      :ttl_seconds,
      :max_ttl_seconds,
      :bind_secret_id,
      :secret_id_num_uses,
      :secret_id_ttl_seconds,
      :bound_cidr_list,
      :metadata,
      :description,
      :enabled
    ])
    |> validate_required([:role_id, :role_name, :policies])
    |> validate_ttl()
    |> unique_constraint(:role_id)
    |> unique_constraint(:role_name)
    |> unique_constraint(:secret_id_accessor)
  end

  defp validate_ttl(changeset) do
    ttl = get_field(changeset, :ttl_seconds)
    max_ttl = get_field(changeset, :max_ttl_seconds)

    if ttl && max_ttl && ttl > max_ttl do
      add_error(changeset, :ttl_seconds, "cannot be greater than max_ttl_seconds")
    else
      changeset
    end
  end
end
