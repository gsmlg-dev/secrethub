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

  alias Ecto.Multi
  alias SecretHub.Core.{Audit, Policies, Repo}
  alias SecretHub.Core.Vault.SealState
  alias SecretHub.Shared.Crypto.Encryption
  alias SecretHub.Shared.Schemas.{Secret, SecretVersion}

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
  Update an existing secret with version tracking.

  Archives the current version before updating.

  ## Parameters

  - `secret_id` - UUID of the secret to update
  - `attrs` - Map of attributes to update
  - `opts` - Optional keyword list:
    - `:created_by` - Actor performing the update (default: "system")
    - `:change_description` - Description of the change (default: "Secret updated")

  ## Examples

      iex> update_secret(secret_id, %{"secret_data" => %{"password" => "new_pass"}},
             created_by: "admin@example.com",
             change_description: "Password rotation")
      {:ok, %Secret{version: 2}}
  """
  def update_secret(secret_id, attrs, opts \\ []) do
    created_by = Keyword.get(opts, :created_by, "system")
    change_description = Keyword.get(opts, :change_description, "Secret updated")

    case Repo.get(Secret, secret_id) do
      nil ->
        {:error, "Secret not found"}

      secret ->
        encrypted_attrs = maybe_encrypt_secret_data(attrs)

        Multi.new()
        |> Multi.run(:archive_version, fn repo, _changes ->
          archive_current_version(repo, secret, created_by, change_description)
        end)
        |> Multi.update(:secret, fn %{archive_version: _version} ->
          # Increment version and update timestamps
          attrs_with_version =
            encrypted_attrs
            |> Map.put("version", secret.version + 1)
            |> Map.put("version_count", secret.version_count + 1)
            |> Map.put("last_version_at", DateTime.utc_now() |> DateTime.truncate(:second))

          secret
          |> Secret.changeset(attrs_with_version)
        end)
        |> Repo.transaction()
        |> case do
          {:ok, %{secret: updated_secret}} ->
            Logger.info("Secret updated with version tracking",
              secret_id: secret_id,
              new_version: updated_secret.version
            )

            {:ok, updated_secret}

          {:error, _step, reason, _changes} ->
            Logger.error("Failed to update secret",
              secret_id: secret_id,
              reason: inspect(reason)
            )

            {:error, reason}
        end
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
  Read a secret by path and return decrypted data.

  Unlike `get_secret_for_entity/3`, this does not evaluate policies.
  Use when policy has already been checked (e.g., in controllers).
  """
  @spec read_decrypted(String.t()) :: {:ok, map(), Secret.t()} | {:error, term()}
  def read_decrypted(secret_path) do
    with {:ok, secret} <- get_secret_by_path(secret_path),
         {:ok, master_key} <- SealState.get_master_key(),
         {:ok, decrypted_data} <- decrypt_secret_data(secret.encrypted_data, master_key) do
      {:ok, decrypted_data, secret}
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

  defp maybe_encrypt_secret_data(attrs) do
    case attrs["secret_data"] do
      nil ->
        attrs

      secret_data ->
        with {:ok, master_key} <- SealState.get_master_key(),
             {:ok, encrypted} <- encrypt_secret_data(secret_data, master_key) do
          Map.put(attrs, "encrypted_data", encrypted)
        else
          _ -> attrs
        end
    end
  end

  defp encrypt_secret_data(data, master_key) when is_map(data) do
    # Serialize the secret data to JSON
    json_data = Jason.encode!(data)

    # Encrypt using the master key (use encrypt_to_blob for compatibility with decrypt_from_blob)
    Encryption.encrypt_to_blob(json_data, master_key)
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

  ## Version Management Functions

  # Archives the current version of a secret before updating.
  # This function is called automatically by `update_secret/3`.
  defp archive_current_version(repo, secret, created_by, change_description) do
    version =
      SecretVersion.from_secret(secret, created_by, change_description)
      |> SecretVersion.changeset(%{})

    repo.insert(version)
  end

  @doc """
  Lists all versions of a secret, ordered by version number (newest first).
  """
  def list_secret_versions(secret_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, 50)

    from(v in SecretVersion,
      where: v.secret_id == ^secret_id,
      order_by: [desc: v.version_number],
      limit: ^limit
    )
    |> Repo.all()
  end

  @doc """
  Gets a specific version of a secret.
  """
  def get_secret_version(secret_id, version_number) do
    case Repo.get_by(SecretVersion, secret_id: secret_id, version_number: version_number) do
      nil -> {:error, "Version not found"}
      version -> {:ok, version}
    end
  end

  @doc """
  Rollback a secret to a previous version.

  Creates a new version (doesn't actually restore the old version number).
  This maintains a complete audit trail of all changes.

  ## Examples

      iex> rollback_secret(secret_id, 5, created_by: "admin@example.com")
      {:ok, %Secret{version: 7}}  # New version created with v5's data
  """
  def rollback_secret(secret_id, target_version_number, opts \\ []) do
    created_by = Keyword.get(opts, :created_by, "system")

    with {:ok, _secret} <- get_secret(secret_id),
         {:ok, target_version} <- get_secret_version(secret_id, target_version_number) do
      # Update with the old version's data
      attrs = %{
        "encrypted_data" => target_version.encrypted_data,
        "metadata" => target_version.metadata,
        "description" => target_version.description
      }

      change_description = "Rolled back to version #{target_version_number}"

      update_secret(secret_id, attrs,
        created_by: created_by,
        change_description: change_description
      )
    end
  end

  @doc """
  Compares two versions of a secret.

  Returns a map with:
  - `:version_numbers` - tuple of {old, new} version numbers
  - `:changed_at` - timestamps of each version
  - `:metadata_diff` - differences in metadata
  - `:data_size_diff` - difference in encrypted data size
  """
  def compare_versions(secret_id, version_a, version_b) do
    with {:ok, v_a} <- get_secret_version(secret_id, version_a),
         {:ok, v_b} <- get_secret_version(secret_id, version_b) do
      comparison = %{
        version_numbers: {v_a.version_number, v_b.version_number},
        changed_at: {v_a.archived_at, v_b.archived_at},
        metadata_diff: compare_maps(v_a.metadata || %{}, v_b.metadata || %{}),
        data_size_diff: SecretVersion.data_size(v_b) - SecretVersion.data_size(v_a),
        created_by: {v_a.created_by, v_b.created_by},
        change_descriptions: {v_a.change_description, v_b.change_description}
      }

      {:ok, comparison}
    end
  end

  @doc """
  Deletes old versions based on retention policy.

  ## Options

  - `:keep_versions` - Number of most recent versions to keep (default: 10)
  - `:keep_days` - Keep versions newer than this many days (default: 90)
  """
  def prune_old_versions(secret_id, opts \\ []) do
    keep_versions = Keyword.get(opts, :keep_versions, 10)
    keep_days = Keyword.get(opts, :keep_days, 90)

    cutoff_date =
      DateTime.add(
        DateTime.utc_now() |> DateTime.truncate(:second),
        -keep_days * 24 * 3600,
        :second
      )

    # Get all versions for this secret
    versions = list_secret_versions(secret_id, limit: 1000)

    # Determine which versions to delete
    {keep, delete} =
      versions
      |> Enum.with_index()
      |> Enum.split_with(fn {version, index} ->
        # Keep recent versions (by index)
        # Keep versions newer than cutoff
        index < keep_versions ||
          DateTime.compare(version.archived_at, cutoff_date) == :gt
      end)

    # Delete old versions
    delete_ids = Enum.map(delete, fn {v, _idx} -> v.id end)

    {count, _} =
      from(v in SecretVersion, where: v.id in ^delete_ids)
      |> Repo.delete_all()

    Logger.info("Pruned old versions",
      secret_id: secret_id,
      deleted_count: count,
      kept_count: length(keep)
    )

    {:ok, %{deleted: count, kept: length(keep)}}
  end

  defp compare_maps(map_a, map_b) do
    all_keys = (Map.keys(map_a) ++ Map.keys(map_b)) |> Enum.uniq()

    Enum.reduce(all_keys, %{added: [], removed: [], changed: []}, fn key, acc ->
      cond do
        not Map.has_key?(map_a, key) ->
          %{acc | added: [{key, Map.get(map_b, key)} | acc.added]}

        not Map.has_key?(map_b, key) ->
          %{acc | removed: [{key, Map.get(map_a, key)} | acc.removed]}

        Map.get(map_a, key) != Map.get(map_b, key) ->
          %{acc | changed: [{key, {Map.get(map_a, key), Map.get(map_b, key)}} | acc.changed]}

        true ->
          acc
      end
    end)
  end
end
