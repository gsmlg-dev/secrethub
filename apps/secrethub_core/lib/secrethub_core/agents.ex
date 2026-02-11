defmodule SecretHub.Core.Agents do
  @moduledoc """
  Core service for agent management and lifecycle operations.

  This module provides the business logic for:
  - Agent bootstrap and authentication
  - WebSocket connection management
  - Policy-based access control for agents
  - Agent monitoring and health checks
  - Certificate issuance and revocation
  - Integration with audit logging
  """

  require Logger
  import Ecto.Query

  alias SecretHub.Core.{Audit, Repo}
  alias SecretHub.Shared.Schemas.{Agent, Certificate, Lease, Policy}

  @type result :: {:ok, term()} | {:error, term()}

  @doc """
  Bootstrap a new agent using RoleID/SecretID authentication.
  """
  def bootstrap_agent(role_id, secret_id, metadata \\ %{}) do
    with :ok <- validate_bootstrap_credentials(role_id, secret_id) do
      agent_id = generate_agent_id(metadata)

      case Repo.get_by(Agent, agent_id: agent_id) do
        nil ->
          bootstrap_new_agent(agent_id, role_id, secret_id, metadata)

        %Agent{} = existing_agent ->
          bootstrap_existing_agent(existing_agent, agent_id)
      end
    end
  end

  @doc """
  Authenticate an agent using its client certificate.
  """
  def authenticate_agent(client_cert_pem) do
    with {:ok, cert} <- parse_certificate(client_cert_pem),
         {:ok, certificate} <- find_valid_certificate(cert),
         {:ok, agent} <- find_agent_for_certificate(certificate),
         :ok <- verify_agent_active(agent) do
      Agent.heartbeat_changeset(agent)
      |> Repo.update()

      {:ok, agent}
    end
  end

  @doc """
  Update agent heartbeat (called from WebSocket connection).
  """
  def update_heartbeat(agent_id) do
    case Repo.get_by(Agent, agent_id: agent_id) do
      %Agent{} = agent ->
        Agent.heartbeat_changeset(agent)
        |> Repo.update()

      nil ->
        {:error, "Agent not found"}
    end
  end

  @doc """
  Mark agent as disconnected.
  """
  def mark_disconnected(agent_id) do
    case Repo.get_by(Agent, agent_id: agent_id) do
      %Agent{} = agent ->
        agent
        |> Ecto.Changeset.change(%{
          status: :disconnected,
          last_seen_at: DateTime.utc_now() |> DateTime.truncate(:second)
        })
        |> Repo.update()

      nil ->
        {:error, "Agent not found"}
    end
  end

  @doc """
  Suspend an agent (temporary disable).
  """
  def suspend_agent(agent_id, reason \\ nil) do
    case Repo.get_by(Agent, agent_id: agent_id) do
      %Agent{} = agent ->
        Agent.suspend_changeset(agent, reason)
        |> Repo.update()

        revoke_agent_cert_if_exists(agent.certificate_id, "Agent suspended")
        cancel_agent_leases(agent_id)
        audit_agent_action(agent_id, "agent_suspended", false, %{reason: reason})

        Logger.info("Suspended agent: #{agent_id}")

        {:ok, agent}

      nil ->
        {:error, "Agent not found"}
    end
  end

  @doc """
  Revoke an agent (permanent disable).
  """
  def revoke_agent(agent_id, reason \\ nil) do
    case Repo.get_by(Agent, agent_id: agent_id) do
      %Agent{} = agent ->
        Agent.revoke_changeset(agent, reason)
        |> Repo.update()

        revoke_agent_cert_if_exists(agent.certificate_id, "Agent revoked")
        cancel_agent_leases(agent_id)
        audit_agent_action(agent_id, "agent_revoked", false, %{reason: reason})

        Logger.info("Revoked agent: #{agent_id}")

        {:ok, agent}

      nil ->
        {:error, "Agent not found"}
    end
  end

  @doc """
  List all agents with optional filtering.
  """
  def list_agents(filters \\ %{}) do
    query = from(a in Agent, preload: [:certificate, :policies])

    query =
      Enum.reduce(filters, query, fn
        {:status, status}, q ->
          where(q, [a], a.status == ^status)

        {:policy_id, policy_id}, q ->
          q
          |> join(:inner, [a], p in assoc(a, :policies))
          |> where([a, p], p.id == ^policy_id)

        {:search, search_term}, q ->
          search_term = "%#{search_term}%"
          where(q, [a], ilike(a.name, ^search_term) or ilike(a.agent_id, ^search_term))

        _, q ->
          q
      end)

    Repo.all(query)
  end

  @doc """
  Get agent by ID with preloaded relationships.
  """
  def get_agent(agent_id) do
    Repo.get_by(Agent, agent_id: agent_id)
    |> Repo.preload([:certificate, :policies])
  end

  @doc """
  Update agent configuration.
  """
  def update_agent_config(agent_id, config) do
    case Repo.get_by(Agent, agent_id: agent_id) do
      %Agent{} = agent ->
        agent
        |> Ecto.Changeset.change(%{config: config})
        |> Repo.update()

      nil ->
        {:error, "Agent not found"}
    end
  end

  @doc """
  Assign policies to an agent.
  """
  def assign_policies(agent_id, policy_ids) when is_list(policy_ids) do
    case Repo.get_by(Agent, agent_id: agent_id) do
      %Agent{} = agent ->
        policies = Repo.all(from(p in Policy, where: p.id in ^policy_ids))

        agent
        |> Repo.preload(:policies)
        |> Ecto.Changeset.change()
        |> Ecto.Changeset.put_assoc(:policies, policies)
        |> Repo.update()

      nil ->
        {:error, "Agent not found"}
    end
  end

  @doc """
  Check if agent has access to a specific secret.
  """
  def check_secret_access(agent_id, secret) do
    with {:ok, agent} <- fetch_active_agent(agent_id) do
      case evaluate_agent_policies(agent, secret) do
        :ok ->
          audit_agent_action(agent_id, "secret_access_granted", true, %{
            secret_path: secret.secret_path
          })

          :ok

        {:error, reason} ->
          audit_agent_action(agent_id, "secret_access_denied", false, %{
            secret_path: secret.secret_path,
            reason: reason
          })

          {:error, reason}
      end
    end
  end

  @doc """
  Get agent statistics for monitoring.
  """
  def get_agent_stats do
    query =
      from(a in Agent,
        select: %{
          total: count(a.id),
          active: count(fragment("CASE WHEN ? = 'active' THEN 1 END", a.status)),
          disconnected: count(fragment("CASE WHEN ? = 'disconnected' THEN 1 END", a.status)),
          pending_bootstrap:
            count(fragment("CASE WHEN ? = 'pending_bootstrap' THEN 1 END", a.status)),
          suspended: count(fragment("CASE WHEN ? = 'suspended' THEN 1 END", a.status)),
          revoked: count(fragment("CASE WHEN ? = 'revoked' THEN 1 END", a.status))
        }
      )

    Repo.one(query)
  end

  @doc """
  Cleanup stale agents (no heartbeat for extended period).
  """
  def cleanup_stale_agents(timeout_hours \\ 24) do
    cutoff =
      DateTime.add(
        DateTime.utc_now() |> DateTime.truncate(:second),
        -timeout_hours * 3600,
        :second
      )

    from(a in Agent,
      where: a.last_heartbeat_at < ^cutoff and a.status in [:active, :disconnected]
    )
    |> Repo.update_all(set: [status: :disconnected])
  end

  @doc """
  Register a new agent with the given attributes.

  Creates the agent in `:pending_bootstrap` status. Policies are assigned
  via the join table if `policy_ids` are provided.

  ## Parameters

  - `attrs` - Map with:
    - `:agent_id` - Unique agent identifier (required)
    - `:name` - Human-readable name (required)
    - `:description` - Optional description
    - `:policy_ids` - List of policy UUIDs to assign
    - `:auth_method` - Authentication method (e.g., "approle")
    - `:metadata` - Additional metadata map
  """
  def register_agent(attrs) do
    agent_attrs = %{
      agent_id: attrs[:agent_id],
      name: attrs[:name],
      description: attrs[:description],
      metadata:
        Map.merge(attrs[:metadata] || %{}, %{
          "auth_method" => attrs[:auth_method] || "approle"
        })
    }

    changeset = Agent.registration_changeset(%Agent{}, agent_attrs)

    case Repo.insert(changeset) do
      {:ok, agent} ->
        # Assign policies if provided
        if policy_ids = attrs[:policy_ids] do
          policies = Repo.all(from(p in Policy, where: p.id in ^policy_ids))

          agent
          |> Repo.preload(:policies)
          |> Ecto.Changeset.change()
          |> Ecto.Changeset.put_assoc(:policies, policies)
          |> Repo.update()
        else
          {:ok, Repo.preload(agent, [:policies, :certificate])}
        end

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  @doc """
  Generate AppRole credentials (role_id/secret_id) for a registered agent.

  Returns `{:ok, role_id, secret_id}` on success.
  """
  def generate_approle_credentials(agent_db_id) do
    case Repo.get(Agent, agent_db_id) do
      nil ->
        {:error, "Agent not found"}

      agent ->
        role_id = Ecto.UUID.generate()
        secret_id = Ecto.UUID.generate()

        agent
        |> Ecto.Changeset.change(%{role_id: role_id, secret_id: secret_id})
        |> Repo.update()
        |> case do
          {:ok, _updated} -> {:ok, role_id, secret_id}
          {:error, reason} -> {:error, reason}
        end
    end
  end

  @doc """
  Revoke an agent's certificate by database ID.

  Sets agent status to `:revoked` and revokes any associated certificate.
  """
  def revoke_agent_certificate(agent_db_id, reason \\ nil) do
    case Repo.get(Agent, agent_db_id) do
      nil ->
        {:error, "Agent not found"}

      agent ->
        result =
          Agent.revoke_changeset(agent, reason)
          |> Repo.update()

        revoke_agent_cert_if_exists(agent.certificate_id, reason || "Agent certificate revoked")

        result
    end
  end

  @doc """
  Get an agent by database ID (bang version). Preloads certificate and policies.

  Raises Ecto.NoResultsError if not found.
  """
  def get_agent!(agent_db_id) do
    Repo.get!(Agent, agent_db_id)
    |> Repo.preload([:certificate, :policies])
  end

  @doc """
  Authenticate an agent using AppRole credentials (role_id/secret_id).

  Validates the credentials, issues a certificate, and activates the agent.
  Returns the updated agent and certificate. Token generation is left to the web layer.
  """
  def authenticate_with_approle(role_id, secret_id) do
    case Repo.get_by(Agent, role_id: role_id, secret_id: secret_id) do
      nil ->
        {:error, "Invalid credentials"}

      %Agent{status: :revoked} ->
        {:error, "Agent has been revoked"}

      %Agent{} = agent ->
        # Issue certificate for the agent
        case issue_agent_certificate(agent) do
          {:ok, certificate} ->
            # Update agent to active status
            {:ok, updated_agent} =
              Agent.authenticate_changeset(agent, certificate)
              |> Repo.update()

            {:ok,
             %{
               certificate: certificate,
               agent: updated_agent
             }}

          {:error, reason} ->
            {:error, "Failed to issue certificate: #{inspect(reason)}"}
        end
    end
  end

  # Private helper functions

  defp bootstrap_new_agent(agent_id, role_id, secret_id, metadata) do
    agent_attrs = %{
      agent_id: agent_id,
      name: Map.get(metadata, "name", agent_id),
      description: Map.get(metadata, "description", ""),
      role_id: role_id,
      secret_id: secret_id,
      ip_address: Map.get(metadata, "ip_address"),
      hostname: Map.get(metadata, "hostname"),
      user_agent: Map.get(metadata, "user_agent"),
      metadata: metadata
    }

    agent_changeset = Agent.bootstrap_changeset(%Agent{}, agent_attrs)

    case Repo.insert(agent_changeset) do
      {:ok, agent} ->
        issue_and_authenticate(agent, agent_id, "issue")

      {:error, changeset_error} ->
        {:error, "Failed to create agent: #{inspect(changeset_error)}"}
    end
  end

  defp bootstrap_existing_agent(existing_agent, agent_id) do
    if should_reissue_certificate?(existing_agent) do
      issue_and_authenticate(existing_agent, agent_id, "re-issue")
    else
      {:ok, existing_agent}
    end
  end

  defp issue_and_authenticate(agent, agent_id, action) do
    case issue_agent_certificate(agent) do
      {:ok, certificate} ->
        Agent.authenticate_changeset(agent, certificate)
        |> Repo.update()

      {:error, cert_error} ->
        Logger.error(
          "Failed to #{action} certificate for agent #{agent_id}: #{inspect(cert_error)}"
        )

        {:error, "Failed to #{action} certificate"}
    end
  end

  defp parse_certificate(client_cert_pem) do
    case Certificate.from_pem(client_cert_pem) do
      {:ok, _cert} = result -> result
      {:error, cert_error} -> {:error, "Invalid certificate: #{inspect(cert_error)}"}
    end
  end

  defp find_valid_certificate(cert) do
    fingerprint = Certificate.fingerprint(cert)

    case Repo.get_by(Certificate, fingerprint: fingerprint, revoked: false) do
      %Certificate{} = certificate -> {:ok, certificate}
      nil -> {:error, "Certificate not found or revoked"}
    end
  end

  defp find_agent_for_certificate(certificate) do
    case Repo.get_by(Agent, certificate_id: certificate.id) do
      %Agent{} = agent -> {:ok, agent}
      nil -> {:error, "No agent found for certificate"}
    end
  end

  defp verify_agent_active(agent) do
    if Agent.active?(agent), do: :ok, else: {:error, "Agent is not active"}
  end

  defp fetch_active_agent(agent_id) do
    case get_agent(agent_id) do
      %Agent{} = agent ->
        if Agent.active?(agent), do: {:ok, agent}, else: {:error, "Agent is not active"}

      nil ->
        {:error, "Agent not found"}
    end
  end

  defp revoke_agent_cert_if_exists(nil, _reason), do: :ok

  defp revoke_agent_cert_if_exists(certificate_id, reason) do
    case Repo.get(Certificate, certificate_id) do
      nil ->
        :ok

      certificate ->
        Certificate.revoke_changeset(certificate, reason)
        |> Repo.update()
    end
  end

  defp validate_bootstrap_credentials(role_id, secret_id) do
    # TODO: Implement actual RoleID/SecretID validation
    # For now, accept any valid UUID format
    with true <- valid_uuid?(role_id),
         true <- valid_uuid?(secret_id) do
      :ok
    else
      _ -> {:error, "Invalid RoleID or SecretID format"}
    end
  end

  defp valid_uuid?(string) do
    case Regex.run(~r/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i, string) do
      [_match] -> true
      _ -> false
    end
  end

  defp generate_agent_id(metadata) do
    hostname = Map.get(metadata, "hostname", "unknown")
    sanitized_hostname = String.replace(hostname, "[^a-zA-Z0-9\-]", "-")
    timestamp = :erlang.system_time(:millisecond)
    "#{sanitized_hostname}-#{timestamp}"
  end

  defp issue_agent_certificate(agent) do
    # TODO: Implement actual certificate issuance using PKI module
    cert_data = %{
      serial_number: :crypto.strong_rand_bytes(16) |> Base.encode16(),
      subject: "CN=#{agent.agent_id}",
      common_name: agent.agent_id,
      organization: "SecretHub Agents",
      valid_from: DateTime.utc_now() |> DateTime.truncate(:second),
      # 90 days
      valid_until:
        DateTime.add(DateTime.utc_now() |> DateTime.truncate(:second), 90 * 24 * 3600, :second),
      cert_type: :agent_client,
      entity_id: agent.id,
      entity_type: "agent"
    }

    # Generate temporary certificate (mock implementation)
    certificate_pem =
      "-----BEGIN CERTIFICATE-----\nMOCK_CERTIFICATE_DATA_#{cert_data.serial_number}\n-----END CERTIFICATE-----"

    # Add certificate_pem and other required fields
    cert_attrs = Map.put(cert_data, :certificate_pem, certificate_pem)

    cert_attrs =
      Map.put(
        cert_attrs,
        :fingerprint,
        "SHA256:" <> (:crypto.hash(:sha256, certificate_pem) |> Base.encode16(case: :lower))
      )

    cert_attrs = Map.put(cert_attrs, :issuer, "CN=SecretHub CA")

    certificate_changeset =
      %Certificate{}
      |> Certificate.changeset(cert_attrs)

    Repo.insert(certificate_changeset)
  end

  defp should_reissue_certificate?(agent) do
    if agent.certificate_id do
      certificate = Repo.get(Certificate, agent.certificate_id)
      certificate && should_reissue_cert?(certificate)
    else
      true
    end
  end

  defp should_reissue_cert?(certificate) do
    # Reissue if certificate expires within 7 days or is revoked
    expires_soon? =
      DateTime.compare(
        certificate.valid_until,
        DateTime.add(DateTime.utc_now() |> DateTime.truncate(:second), 7 * 24 * 3600, :second)
      ) != :gt

    revoked? = certificate.revoked
    expires_soon? or revoked?
  end

  defp cancel_agent_leases(agent_id) do
    from(l in Lease,
      where:
        l.agent_id == ^agent_id and
          l.expires_at > ^(DateTime.utc_now() |> DateTime.truncate(:second))
    )
    |> Repo.update_all(set: [expires_at: DateTime.utc_now() |> DateTime.truncate(:second)])
  end

  defp evaluate_agent_policies(agent, secret) do
    # Check if agent has any policies that allow access to this secret
    agent_policies = agent.policies || []

    case Enum.find(agent_policies, fn policy ->
           # TODO: Implement actual policy evaluation logic
           # For now, check if secret path matches policy patterns
           secret_matches_policy?(secret, policy)
         end) do
      nil -> {:error, "No policy allows access to this secret"}
      _policy -> :ok
    end
  end

  defp secret_matches_policy?(secret, policy) do
    # TODO: Implement sophisticated policy matching
    # For now, simple path prefix matching
    policy_paths = Map.get(policy.metadata, "allowed_paths", [])

    Enum.any?(policy_paths, fn path ->
      String.starts_with?(secret.secret_path, path)
    end)
  end

  defp audit_agent_action(agent_id, action, success, event_data) do
    Audit.log_event(%{
      agent_id: agent_id,
      event_type: action,
      actor_type: "agent",
      actor_id: agent_id,
      access_granted: success,
      response_time_ms: 0,
      event_data: event_data
    })

    status = if success, do: "SUCCESS", else: "FAILED"
    Logger.info("Agent #{agent_id} #{action}: #{status}")
  end
end
