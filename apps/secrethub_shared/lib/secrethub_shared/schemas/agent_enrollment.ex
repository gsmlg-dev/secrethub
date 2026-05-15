defmodule SecretHub.Shared.Schemas.AgentEnrollment do
  @moduledoc """
  Pending Agent enrollment workflow state.

  The pending token protects only enrollment polling/CSR/finalization. It never
  authorizes runtime secret access.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @statuses [
    :pending_registered,
    :approved_waiting_for_csr,
    :csr_submitted,
    :certificate_issued,
    :connect_info_delivered,
    :trusted_connecting,
    :trusted_connected,
    :finalized,
    :rejected,
    :csr_invalid,
    :certificate_issue_failed,
    :trusted_endpoint_failed,
    :expired,
    :revoked
  ]

  schema "agent_enrollments" do
    field(:agent_id, :string)
    field(:status, Ecto.Enum, values: @statuses, default: :pending_registered)

    field(:hostname, :string)
    field(:fqdn, :string)
    field(:machine_id, :string)
    field(:os, :string)
    field(:arch, :string)
    field(:agent_version, :string)
    field(:ssh_host_key_algorithm, :string)
    field(:ssh_host_key_fingerprint, :string)
    field(:source_ip, :string)
    field(:capabilities, :map, default: %{})

    field(:pending_token_hash, :string)
    field(:required_csr_fields, :map, default: %{})
    field(:csr_pem, :string)
    field(:last_error, :map)

    field(:approved_by, :string)
    field(:approved_at, :utc_datetime)
    field(:rejected_by, :string)
    field(:rejected_at, :utc_datetime)
    field(:expires_at, :utc_datetime)

    timestamps(type: :utc_datetime)
  end

  def statuses, do: @statuses

  def pending_changeset(enrollment, attrs) do
    enrollment
    |> cast(attrs, [
      :hostname,
      :fqdn,
      :machine_id,
      :os,
      :arch,
      :agent_version,
      :ssh_host_key_algorithm,
      :ssh_host_key_fingerprint,
      :source_ip,
      :capabilities,
      :pending_token_hash,
      :expires_at
    ])
    |> validate_required([
      :ssh_host_key_algorithm,
      :ssh_host_key_fingerprint,
      :pending_token_hash,
      :expires_at
    ])
    |> validate_inclusion(:ssh_host_key_algorithm, ["rsa", "ecdsa"])
    |> put_change(:status, :pending_registered)
  end

  def changeset(enrollment, attrs) do
    enrollment
    |> cast(attrs, [
      :agent_id,
      :status,
      :hostname,
      :fqdn,
      :machine_id,
      :os,
      :arch,
      :agent_version,
      :ssh_host_key_algorithm,
      :ssh_host_key_fingerprint,
      :source_ip,
      :capabilities,
      :pending_token_hash,
      :required_csr_fields,
      :csr_pem,
      :last_error,
      :approved_by,
      :approved_at,
      :rejected_by,
      :rejected_at,
      :expires_at
    ])
    |> validate_required([:status])
  end
end
