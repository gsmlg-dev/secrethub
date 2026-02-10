defmodule SecretHub.Shared.Schemas.Agent do
  @moduledoc """
  Schema for Agent registration and management.

  Agents are lightweight daemons deployed alongside applications that maintain
  persistent WebSocket connections to SecretHub Core for secure secret delivery.

  Agent lifecycle:
  - Bootstrap with RoleID/SecretID (secret-zero) to obtain client certificates
  - Maintain persistent WebSocket connection with heartbeat
  - Local caching with automatic renewal
  - Template-based secret rendering for applications
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "agents" do
    # Agent identification
    # Unique agent identifier
    field(:agent_id, :string)
    # Human-readable name
    field(:name, :string)
    field(:description, :string)

    # Bootstrap credentials (RoleID/SecretID)
    field(:role_id, :string)
    field(:secret_id, :string)

    # Authentication status
    field(:status, Ecto.Enum,
      values: [:pending_bootstrap, :active, :disconnected, :suspended, :revoked]
    )

    field(:authenticated_at, :utc_datetime)
    field(:last_seen_at, :utc_datetime)
    field(:last_heartbeat_at, :utc_datetime)

    # Network information
    field(:ip_address, :string)
    field(:hostname, :string)
    field(:user_agent, :string)

    # Certificate binding
    belongs_to(:certificate, SecretHub.Shared.Schemas.Certificate)

    # Policy access
    many_to_many(:policies, SecretHub.Shared.Schemas.Policy, join_through: "agents_policies")

    # Configuration
    field(:config, :map, default: %{})
    field(:metadata, :map, default: %{})

    # Statistics
    field(:connection_count, :integer, default: 0)
    field(:secret_access_count, :integer, default: 0)
    field(:last_secret_access_at, :utc_datetime)

    timestamps(type: :utc_datetime)
  end

  @doc """
  Changeset for creating or updating an agent.
  """
  def changeset(agent, attrs) do
    agent
    |> cast(attrs, [
      :agent_id,
      :name,
      :description,
      :role_id,
      :secret_id,
      :status,
      :authenticated_at,
      :last_seen_at,
      :last_heartbeat_at,
      :ip_address,
      :hostname,
      :user_agent,
      :certificate_id,
      :config,
      :metadata,
      :connection_count,
      :secret_access_count,
      :last_secret_access_at
    ])
    |> validate_required([:agent_id, :name, :status])
    |> validate_format(:agent_id, ~r/^[a-z0-9\-]+$/,
      message: "must contain only lowercase letters, numbers, and hyphens"
    )
    |> validate_length(:name, min: 1, max: 100)
    |> validate_length(:description, max: 500)
    |> unique_constraint(:agent_id)
    |> validate_bootstrap_credentials()
    |> validate_status_transition()
  end

  @doc """
  Changeset for agent registration (creates agent in pending_bootstrap state).
  Unlike bootstrap_changeset, does not require role_id/secret_id upfront.
  """
  def registration_changeset(agent, attrs) do
    agent
    |> cast(attrs, [:agent_id, :name, :description, :metadata])
    |> validate_required([:agent_id, :name])
    |> validate_format(:agent_id, ~r/^[a-z0-9\-]+$/,
      message: "must contain only lowercase letters, numbers, and hyphens"
    )
    |> validate_length(:name, min: 1, max: 100)
    |> validate_length(:description, max: 500)
    |> put_change(:status, :pending_bootstrap)
    |> unique_constraint(:agent_id)
  end

  @doc """
  Changeset for agent bootstrap (initial registration).
  """
  def bootstrap_changeset(agent, attrs) do
    agent
    |> cast(attrs, [:agent_id, :name, :description, :role_id, :secret_id, :ip_address, :hostname, :user_agent, :metadata])
    |> validate_required([:agent_id, :role_id, :secret_id])
    |> validate_format(
      :role_id,
      ~r/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/,
      message: "must be a valid UUID"
    )
    |> validate_format(
      :secret_id,
      ~r/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/,
      message: "must be a valid UUID"
    )
    |> put_change(:status, :pending_bootstrap)
  end

  @doc """
  Changeset for updating agent heartbeat.
  """
  def heartbeat_changeset(agent) do
    change(agent, %{
      last_heartbeat_at: DateTime.utc_now() |> DateTime.truncate(:second),
      last_seen_at: DateTime.utc_now() |> DateTime.truncate(:second)
    })
  end

  @doc """
  Changeset for authenticating an agent (certificate issued).
  """
  def authenticate_changeset(agent, certificate) do
    change(agent, %{
      status: :active,
      authenticated_at: DateTime.utc_now() |> DateTime.truncate(:second),
      last_seen_at: DateTime.utc_now() |> DateTime.truncate(:second),
      last_heartbeat_at: DateTime.utc_now() |> DateTime.truncate(:second),
      certificate_id: certificate.id
    })
  end

  @doc """
  Changeset for suspending an agent.
  """
  def suspend_changeset(agent, reason \\ nil) do
    change(agent, %{
      status: :suspended,
      metadata: Map.merge(agent.metadata || %{}, %{"suspension_reason" => reason})
    })
  end

  @doc """
  Changeset for revoking an agent.
  """
  def revoke_changeset(agent, reason \\ nil) do
    change(agent, %{
      status: :revoked,
      metadata: Map.merge(agent.metadata || %{}, %{"revocation_reason" => reason})
    })
  end

  @doc """
  Check if agent is currently active and can access secrets.
  """
  def active?(agent) do
    agent.status == :active and
      DateTime.compare(
        agent.last_heartbeat_at || DateTime.add(DateTime.utc_now() |> DateTime.truncate(:second), -3600, :second),
        DateTime.add(DateTime.utc_now() |> DateTime.truncate(:second), -300, :second)
      ) != :lt
  end

  @doc """
  Check if agent needs re-authentication due to stale heartbeat.
  """
  def stale_heartbeat?(agent, timeout_seconds \\ 300) do
    cutoff = DateTime.add(DateTime.utc_now() |> DateTime.truncate(:second), -timeout_seconds, :second)
    DateTime.compare(agent.last_heartbeat_at || DateTime.utc_now() |> DateTime.truncate(:second), cutoff) == :lt
  end

  # Private validation functions

  defp validate_bootstrap_credentials(changeset) do
    role_id = get_field(changeset, :role_id)
    secret_id = get_field(changeset, :secret_id)
    status = get_field(changeset, :status)

    if status == :pending_bootstrap and (is_nil(role_id) or is_nil(secret_id)) do
      add_error(changeset, :role_id, "role_id and secret_id are required for bootstrap")
    else
      changeset
    end
  end

  defp validate_status_transition(changeset) do
    current_status = get_field(changeset, :status)

    if current_status do
      validate_transition(changeset, current_status)
    else
      changeset
    end
  end

  defp validate_transition(changeset, :pending_bootstrap) do
    # Can only transition to active (after certificate issuance)
    changeset
  end

  defp validate_transition(changeset, :active) do
    # Can transition to disconnected, suspended, or revoked
    changeset
  end

  defp validate_transition(changeset, :disconnected) do
    # Can transition back to active or to suspended/revoked
    changeset
  end

  defp validate_transition(changeset, :suspended) do
    # Can transition back to active or to revoked
    changeset
  end

  defp validate_transition(changeset, :revoked) do
    # Final state - cannot transition
    add_error(changeset, :status, "cannot transition from revoked state")
  end

  defp validate_transition(changeset, _other) do
    changeset
  end
end
