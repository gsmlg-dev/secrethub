defmodule SecretHub.Shared.Schemas.AuditLog do
  @moduledoc """
  Schema for tamper-evident audit logging with hash chains.

  Every security-relevant event is logged with:
  - Complete actor information (agent, app, admin)
  - Secret access details
  - Authorization results
  - Source context (IP, hostname, K8s pod)
  - Hash chain fields for tamper detection

  The table is partitioned by timestamp for performance.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "audit_logs" do
    # Event identification
    field(:event_id, :binary_id)
    field(:sequence_number, :integer)
    field(:timestamp, :utc_datetime)
    field(:event_type, :string)

    # Actor information
    field(:actor_type, :string)
    field(:actor_id, :string)
    field(:agent_id, :string)
    field(:app_id, :string)
    field(:admin_id, :string)

    # Certificate fingerprints for non-repudiation
    field(:agent_cert_fingerprint, :string)
    field(:app_cert_fingerprint, :string)

    # Secret information
    field(:secret_id, :string)
    field(:secret_version, :integer)
    field(:secret_type, :string)
    field(:lease_id, :binary_id)

    # Access control
    field(:access_granted, :boolean)
    field(:policy_matched, :string)
    field(:denial_reason, :string)

    # Source context
    field(:source_ip, EctoNetwork.INET)
    field(:hostname, :string)
    field(:kubernetes_namespace, :string)
    field(:kubernetes_pod, :string)

    # Full event data (flexible storage for event-specific fields)
    field(:event_data, :map)

    # Tamper-evidence fields (hash chain)
    field(:previous_hash, :string)
    field(:current_hash, :string)
    field(:signature, :string)

    # Performance tracking
    field(:response_time_ms, :integer)
    field(:correlation_id, :binary_id)

    field(:created_at, :utc_datetime)
  end

  @doc """
  Changeset for creating an audit log entry.
  """
  def changeset(audit_log, attrs) do
    audit_log
    |> cast(attrs, [
      :event_id,
      :sequence_number,
      :timestamp,
      :event_type,
      :actor_type,
      :actor_id,
      :agent_id,
      :app_id,
      :admin_id,
      :agent_cert_fingerprint,
      :app_cert_fingerprint,
      :secret_id,
      :secret_version,
      :secret_type,
      :lease_id,
      :access_granted,
      :policy_matched,
      :denial_reason,
      :source_ip,
      :hostname,
      :kubernetes_namespace,
      :kubernetes_pod,
      :event_data,
      :previous_hash,
      :current_hash,
      :signature,
      :response_time_ms,
      :correlation_id,
      :created_at
    ])
    |> validate_required([:event_id, :sequence_number, :timestamp, :event_type])
    |> validate_inclusion(:event_type, valid_event_types())
    |> unique_constraint(:event_id, name: :unique_event_id_timestamp)
    |> unique_constraint([:sequence_number, :timestamp], name: :unique_sequence_number_timestamp)
  end

  @doc """
  Valid event types for audit logging.
  """
  def valid_event_types do
    [
      # Secret access events
      "secret.accessed",
      "secret.dynamic_issued",
      "secret.lease_renewed",
      "secret.access_denied",
      # Secret mutation events
      "secret.created",
      "secret.updated",
      "secret.rotated",
      "secret.deleted",
      # Authentication events
      "auth.agent_bootstrap",
      "auth.agent_certificate_issued",
      "auth.agent_login",
      "auth.admin_login",
      "auth.failed",
      # Policy changes
      "policy.created",
      "policy.updated",
      "policy.deleted",
      "policy.bound",
      # System events
      "system.unsealed",
      "system.sealed",
      "system.backup_created",
      "system.certificate_revoked"
    ]
  end
end
