defmodule SecretHub.Core.Secrets do
  @moduledoc """
  Core service for secret management operations.

  Provides CRUD operations for secrets with encryption, policy-based access control,
  and rotation scheduling.

  ## Secret Types

  - **Static Secrets**: Long-lived credentials stored and encrypted
  - **Dynamic Secrets**: Temporary credentials generated on-demand

  ## Encryption

  All secret values are encrypted using AES-256-GCM before storage.
  The master key is obtained from the SealState (vault must be unsealed).
  """

  require Logger
  import Ecto.Query

  alias Ecto.{Changeset, Multi}
  alias SecretHub.Core.{Audit, Policies, Repo}
  alias SecretHub.Core.Vault.SealState
  alias SecretHub.Shared.Crypto.Encryption
  alias SecretHub.Shared.Schemas.{AuditLog, Policy, Secret}

  @doc """
  Create a new static secret with encryption.

  ## Parameters

  - `attrs` - Map containing secret attributes including:
    - `name` - Display name for the secret
    - `secret_path` - Path in reverse domain notation
    - `secret_data` - Map of key-value pairs to encrypt
    - `description` - Optional description
    - `rotation_enabled` - Enable automatic rotation
    - `rotation_period_hours` - Hours between rotations

  ## Examples

      iex> create_secret(%{
        name: "Production DB Password",
        secret_path: "prod.db.postgres.password",
        secret_data: %{"username" => "admin", "password" => "secret123"},
        description: "Main database credentials"
      })
      {:ok, %Secret{}}
  """
  def create_secret(attrs) do
    with {:ok, master_key} <- SealState.get_master_key(),
         {:ok, encrypted_data} <- encrypt_secret_data(attrs["secret_data"] || %{}, master_key) do
      attrs = Map.put(attrs, "encrypted_data", encrypted_data)

      %Secret{}
      |> Secret.changeset(attrs)
      |> Repo.insert()
      |> case do
        {:ok, secret} = result ->
          Logger.info("Secret created", secret_id: secret.id, secret_path: secret.secret_path)
          result

        error ->
          error
      end
    else
      {:error, reason} ->
        Logger.error("Failed to create secret", reason: inspect(reason))
        {:error, reason}
    end
  end

  @doc """
  Update an existing secret.
  """
  def update_secret(secret_id, attrs) do
    case Repo.get(Secret, secret_id) do
      nil ->
        {:error, "Secret not found"}

      secret ->
        secret
        |> Secret.changeset(attrs)
        |> Repo.update()
    end
  end

  @doc """
  Delete a secret.
  """
  def delete_secret(secret_id) do
    case Repo.get(Secret, secret_id) do
      nil ->
        {:error, "Secret not found"}

      secret ->
        Repo.delete(secret)
    end
  end

  @doc """
  Get a secret by ID.
  """
  def get_secret(secret_id) do
    case Repo.get(Secret, secret_id) do
      nil -> {:error, "Secret not found"}
      secret -> {:ok, secret}
    end
  end

  @doc """
  List all secrets with optional filtering.
  """
  def list_secrets(filters \\ %{}) do
    query = from(s in Secret, preload: [:policies])

    query =
      Enum.reduce(filters, query, fn
        {:secret_type, type}, q ->
          where(q, [s], s.secret_type == ^type)

        {:engine_type, engine}, q ->
          where(q, [s], s.engine_type == ^engine)

        {:search, term}, q ->
          search_term = "%#{term}%"
          where(q, [s], ilike(s.name, ^search_term) or ilike(s.secret_path, ^search_term))

        _, q ->
          q
      end)

    Repo.all(query)
  end

  @doc """
  Get secret statistics.
  """
  def get_secret_stats do
    %{
      total: Repo.aggregate(Secret, :count, :id),
      static: Repo.aggregate(from(s in Secret, where: s.secret_type == :static), :count, :id),
      dynamic: Repo.aggregate(from(s in Secret, where: s.secret_type == :dynamic), :count, :id)
    }
  end

  @doc """
  Get a secret by path.
  """
  @spec get_secret_by_path(String.t()) :: {:ok, Secret.t()} | {:error, term()}
  def get_secret_by_path(secret_path) do
    case Repo.get_by(Secret, secret_path: secret_path) do
      nil -> {:error, "Secret not found"}
      secret -> {:ok, secret}
    end
  end

  @doc """
  Retrieve and decrypt a secret for an entity with policy evaluation.

  ## Parameters

  - `entity_id` - ID of the requesting entity (agent, app)
  - `secret_path` - Path of the secret to retrieve
  - `context` - Additional context for policy evaluation (IP, TTL, etc.)

  ## Returns

  - `{:ok, secret_data}` - Decrypted secret data
  - `{:error, reason}` - Access denied or error

  ## Examples

      iex> get_secret_for_entity("agent-001", "prod.db.postgres.password", %{})
      {:ok, %{"username" => "admin", "password" => "secret123"}}
  """
  @spec get_secret_for_entity(String.t(), String.t(), map()) ::
          {:ok, map()} | {:error, term()}
  def get_secret_for_entity(entity_id, secret_path, context \\ %{}) do
    start_time = System.monotonic_time(:millisecond)

    with {:ok, policy} <- Policies.evaluate_access(entity_id, secret_path, "read", context),
         {:ok, secret} <- get_secret_by_path(secret_path),
         {:ok, master_key} <- SealState.get_master_key(),
         {:ok, decrypted_data} <- decrypt_secret_data(secret.encrypted_data, master_key) do
      response_time = System.monotonic_time(:millisecond) - start_time

      Logger.info("Secret accessed",
        entity_id: entity_id,
        secret_path: secret_path
      )

      # Log successful access to audit log
      Audit.log_event(%{
        event_type: "secret.accessed",
        actor_type: determine_actor_type(entity_id),
        actor_id: entity_id,
        secret_id: secret.id,
        secret_version: 1,
        secret_type: to_string(secret.secret_type),
        access_granted: true,
        policy_matched: policy.name,
        source_ip: Map.get(context, :ip_address),
        hostname: Map.get(context, :hostname),
        kubernetes_namespace: Map.get(context, :k8s_namespace),
        kubernetes_pod: Map.get(context, :k8s_pod),
        response_time_ms: response_time,
        correlation_id: Map.get(context, :correlation_id),
        event_data: %{
          secret_path: secret_path,
          ttl_hours: secret.ttl_hours
        }
      })

      {:ok, decrypted_data}
    else
      {:error, reason} = error ->
        response_time = System.monotonic_time(:millisecond) - start_time

        Logger.warning("Secret access denied",
          entity_id: entity_id,
          secret_path: secret_path,
          reason: inspect(reason)
        )

        # Log access denial to audit log
        Audit.log_event(%{
          event_type: "secret.access_denied",
          actor_type: determine_actor_type(entity_id),
          actor_id: entity_id,
          access_granted: false,
          denial_reason: inspect(reason),
          source_ip: Map.get(context, :ip_address),
          hostname: Map.get(context, :hostname),
          response_time_ms: response_time,
          correlation_id: Map.get(context, :correlation_id),
          event_data: %{
            secret_path: secret_path,
            reason: inspect(reason)
          }
        })

        error
    end
  end

  @doc """
  Bind a policy to a secret.
  """
  @spec bind_policy_to_secret(binary(), binary()) :: {:ok, Secret.t()} | {:error, term()}
  def bind_policy_to_secret(secret_id, policy_id) do
    with {:ok, secret} <- get_secret(secret_id),
         {:ok, policy} <- Policies.get_policy(policy_id) do
      # Use Ecto's many_to_many association
      secret
      |> Repo.preload(:policies)
      |> Ecto.Changeset.change()
      |> Ecto.Changeset.put_assoc(:policies, [policy | secret.policies])
      |> Repo.update()
    end
  end

  ## Private Functions

  defp encrypt_secret_data(data, master_key) when is_map(data) do
    # Serialize the secret data to JSON
    json_data = Jason.encode!(data)

    # Encrypt using the master key
    Encryption.encrypt(json_data, master_key)
  rescue
    e ->
      {:error, "Encryption failed: #{inspect(e)}"}
  end

  defp decrypt_secret_data(encrypted_blob, master_key) when is_binary(encrypted_blob) do
    with {:ok, json_data} <- Encryption.decrypt_from_blob(encrypted_blob, master_key),
         {:ok, data} <- Jason.decode(json_data) do
      {:ok, data}
    else
      {:error, reason} ->
        {:error, "Decryption failed: #{inspect(reason)}"}
    end
  end

  defp decrypt_secret_data(nil, _master_key) do
    {:ok, %{}}
  end

  defp determine_actor_type(entity_id) do
    cond do
      String.starts_with?(entity_id, "agent-") -> "agent"
      String.starts_with?(entity_id, "app-") -> "app"
      String.starts_with?(entity_id, "admin-") -> "admin"
      true -> "unknown"
    end
  end
end
