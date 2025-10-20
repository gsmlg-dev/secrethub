defmodule SecretHub.Shared.Schemas.Lease do
  @moduledoc """
  Schema for tracking dynamic secret leases.

  Leases manage the lifecycle of temporary credentials:
  - Issued when dynamic secret is generated
  - Can be renewed before expiration
  - Automatically revoked on expiry
  - Manual revocation supported

  Lease renewal strategy: Renew at 50% of TTL to prevent expiry.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "leases" do
    # Lease identification
    field :lease_id, :binary_id
    field :secret_id, :string

    # Entity information (who requested this lease)
    field :agent_id, :string
    field :app_id, :string
    field :app_cert_fingerprint, :string

    # Lease timing
    field :issued_at, :utc_datetime
    field :expires_at, :utc_datetime
    field :ttl_seconds, :integer

    # Renewal tracking
    field :renewed_count, :integer, default: 0
    field :last_renewed_at, :utc_datetime
    field :max_renewals, :integer

    # Revocation
    field :revoked, :boolean, default: false
    field :revoked_at, :utc_datetime
    field :revocation_reason, :string

    # Encrypted credentials (stored for lease renewal/revocation)
    # Format depends on secret engine:
    # PostgreSQL: %{"username" => "...", "password" => "..."}
    # Redis: %{"username" => "...", "password" => "..."}
    # AWS: %{"access_key_id" => "...", "secret_access_key" => "...", "session_token" => "..."}
    field :credentials, :map

    # Engine-specific data for revocation
    field :engine_type, :string
    field :engine_metadata, :map, default: %{}

    # Context
    field :source_ip, EctoNetwork.INET
    field :correlation_id, :binary_id

    timestamps(type: :utc_datetime)
  end

  @doc """
  Changeset for creating a new lease.
  """
  def changeset(lease, attrs) do
    lease
    |> cast(attrs, [
      :lease_id,
      :secret_id,
      :agent_id,
      :app_id,
      :app_cert_fingerprint,
      :issued_at,
      :expires_at,
      :ttl_seconds,
      :max_renewals,
      :credentials,
      :engine_type,
      :engine_metadata,
      :source_ip,
      :correlation_id
    ])
    |> validate_required([
      :lease_id,
      :secret_id,
      :agent_id,
      :issued_at,
      :expires_at,
      :ttl_seconds,
      :credentials,
      :engine_type
    ])
    |> unique_constraint(:lease_id)
    |> validate_expiry()
  end

  @doc """
  Changeset for renewing a lease.
  """
  def renew_changeset(lease, new_expires_at) do
    lease
    |> cast(
      %{
        expires_at: new_expires_at,
        renewed_count: (lease.renewed_count || 0) + 1,
        last_renewed_at: DateTime.utc_now()
      },
      [:expires_at, :renewed_count, :last_renewed_at]
    )
    |> validate_required([:expires_at, :renewed_count, :last_renewed_at])
    |> validate_max_renewals()
  end

  @doc """
  Changeset for revoking a lease.
  """
  def revoke_changeset(lease, reason) do
    lease
    |> cast(
      %{
        revoked: true,
        revoked_at: DateTime.utc_now(),
        revocation_reason: reason
      },
      [:revoked, :revoked_at, :revocation_reason]
    )
    |> validate_required([:revoked, :revoked_at])
  end

  defp validate_expiry(changeset) do
    issued_at = get_field(changeset, :issued_at)
    expires_at = get_field(changeset, :expires_at)

    if issued_at && expires_at && DateTime.compare(issued_at, expires_at) != :lt do
      add_error(changeset, :expires_at, "must be after issued_at")
    else
      changeset
    end
  end

  defp validate_max_renewals(changeset) do
    renewed_count = get_field(changeset, :renewed_count)
    max_renewals = get_field(changeset, :max_renewals)

    if max_renewals && renewed_count && renewed_count > max_renewals do
      add_error(changeset, :renewed_count, "exceeded maximum renewals")
    else
      changeset
    end
  end
end
