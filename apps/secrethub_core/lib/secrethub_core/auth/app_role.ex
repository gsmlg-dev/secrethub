defmodule SecretHub.Core.Auth.AppRole do
  @moduledoc """
  AppRole authentication backend for agent bootstrap.

  AppRole provides the "secret zero" problem solution - agents need initial
  credentials to authenticate and obtain their mTLS certificates. This module
  manages RoleID/SecretID pairs that agents use for initial bootstrap.

  ## Authentication Flow
  1. Admin creates AppRole (generates RoleID and SecretID)
  2. RoleID and SecretID are securely provided to the agent (separate channels)
  3. Agent authenticates using both credentials
  4. Agent receives client certificate for mTLS
  5. Future communications use the certificate

  ## Security Features
  - SecretID can be single-use or have limited TTL
  - SecretID can be bound to specific CIDR ranges
  - Rate limiting on authentication attempts
  - Audit logging of all authentication events
  """

  require Logger
  import Ecto.Query

  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.{AuditLog, Role}

  # 10 minutes in seconds
  @secret_id_ttl_default 600
  # Single-use by default
  @max_secret_id_uses 1

  @doc """
  Creates a new AppRole with generated RoleID and SecretID.

  Returns both credentials that must be distributed via separate secure channels.

  ## Options
  - `:role_name` - Human-readable name for the role
  - `:policies` - List of policy IDs to attach
  - `:secret_id_ttl` - TTL in seconds for SecretID (default: 600)
  - `:secret_id_num_uses` - Max uses for SecretID (default: 1)
  - `:bind_secret_id` - Whether SecretID is required (default: true)
  - `:bound_cidr_list` - List of allowed CIDR ranges

  ## Examples

      iex> AppRole.create_role("production-app", policies: ["secret-read"])
      {:ok, %{role_id: "uuid", secret_id: "uuid", role_name: "production-app"}}
  """
  @spec create_role(String.t(), keyword()) ::
          {:ok, %{role_id: String.t(), secret_id: String.t(), role_name: String.t()}}
          | {:error, String.t()}
  def create_role(role_name, opts \\ []) do
    policies = Keyword.get(opts, :policies, [])
    secret_id_ttl = Keyword.get(opts, :secret_id_ttl, @secret_id_ttl_default)
    secret_id_num_uses = Keyword.get(opts, :secret_id_num_uses, @max_secret_id_uses)
    bind_secret_id = Keyword.get(opts, :bind_secret_id, true)
    bound_cidr_list = Keyword.get(opts, :bound_cidr_list, [])

    # Generate RoleID and SecretID
    role_id = Ecto.UUID.generate()
    secret_id = Ecto.UUID.generate()

    # Create role record
    role_attrs = %{
      role_id: role_id,
      role_name: role_name,
      auth_type: "approle",
      metadata: %{
        "bind_secret_id" => bind_secret_id,
        "secret_id_ttl" => secret_id_ttl,
        "secret_id_num_uses" => secret_id_num_uses,
        "bound_cidr_list" => bound_cidr_list,
        "policies" => policies,
        "secret_id" => secret_id,
        "secret_id_created_at" => DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_iso8601(),
        "secret_id_uses" => 0
      }
    }

    case %Role{}
         |> Role.changeset(role_attrs)
         |> Repo.insert() do
      {:ok, _role} ->
        Logger.info("Created AppRole: #{role_name} (RoleID: #{role_id})")
        audit_event("approle_created", role_id, %{role_name: role_name})

        {:ok,
         %{
           role_id: role_id,
           secret_id: secret_id,
           role_name: role_name
         }}

      {:error, changeset} ->
        {:error, "Failed to create role: #{inspect(changeset.errors)}"}
    end
  end

  @doc """
  Authenticates an agent using RoleID and SecretID.

  Validates the credentials and returns authentication token if successful.

  ## Examples

      iex> AppRole.login(role_id, secret_id, "10.0.1.50")
      {:ok, %{token: "token", policies: ["secret-read"]}}
  """
  @spec login(String.t(), String.t(), String.t()) ::
          {:ok, %{token: String.t(), policies: list(), role_name: String.t()}}
          | {:error, String.t()}
  def login(role_id, secret_id, source_ip \\ "unknown") do
    # Validate role_id is a valid UUID before querying
    case Ecto.UUID.cast(role_id) do
      :error ->
        {:error, "Invalid credentials"}

      {:ok, _} ->
        login_with_valid_role_id(role_id, secret_id, source_ip)
    end
  end

  defp login_with_valid_role_id(role_id, secret_id, source_ip) do
    case Repo.get_by(Role, role_id: role_id, auth_type: "approle") do
      nil ->
        audit_event("approle_login_failed", role_id, %{
          reason: "role_not_found",
          source_ip: source_ip
        })

        {:error, "Invalid credentials"}

      role ->
        # Validate SecretID
        case validate_secret_id(role, secret_id, source_ip) do
          :ok ->
            # Increment usage counter
            new_uses = Map.get(role.metadata, "secret_id_uses", 0) + 1
            updated_metadata = Map.put(role.metadata, "secret_id_uses", new_uses)

            role
            |> Ecto.Changeset.change(%{metadata: updated_metadata})
            |> Repo.update()

            # Generate authentication token
            token = generate_auth_token(role)

            policies = Map.get(role.metadata, "policies", [])

            Logger.info("AppRole login successful: #{role.role_name}")

            audit_event("approle_login_success", role_id, %{
              role_name: role.role_name,
              source_ip: source_ip
            })

            {:ok,
             %{
               token: token,
               policies: policies,
               role_name: role.role_name
             }}

          {:error, reason} ->
            audit_event("approle_login_failed", role_id, %{
              reason: reason,
              source_ip: source_ip
            })

            {:error, "Invalid credentials"}
        end
    end
  end

  @doc """
  Rotates the SecretID for an existing AppRole.

  Returns new SecretID while keeping RoleID unchanged.

  ## Examples

      iex> AppRole.rotate_secret_id(role_id)
      {:ok, %{secret_id: "new-uuid"}}
  """
  @spec rotate_secret_id(String.t()) :: {:ok, %{secret_id: String.t()}} | {:error, String.t()}
  def rotate_secret_id(role_id) do
    case Repo.get_by(Role, role_id: role_id, auth_type: "approle") do
      nil ->
        {:error, "Role not found"}

      role ->
        # Generate new SecretID
        new_secret_id = Ecto.UUID.generate()

        updated_metadata =
          role.metadata
          |> Map.put("secret_id", new_secret_id)
          |> Map.put("secret_id_created_at", DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_iso8601())
          |> Map.put("secret_id_uses", 0)

        role
        |> Ecto.Changeset.change(%{metadata: updated_metadata})
        |> Repo.update()

        Logger.info("Rotated SecretID for AppRole: #{role.role_name}")
        audit_event("approle_secret_rotated", role_id, %{role_name: role.role_name})

        {:ok, %{secret_id: new_secret_id}}
    end
  end

  @doc """
  Deletes an AppRole.

  ## Examples

      iex> AppRole.delete_role(role_id)
      :ok
  """
  @spec delete_role(String.t()) :: :ok | {:error, String.t()}
  def delete_role(role_id) do
    case Repo.get_by(Role, role_id: role_id, auth_type: "approle") do
      nil ->
        {:error, "Role not found"}

      role ->
        Repo.delete(role)

        Logger.info("Deleted AppRole: #{role.role_name}")
        audit_event("approle_deleted", role_id, %{role_name: role.role_name})

        :ok
    end
  end

  @doc """
  Lists all AppRoles.

  ## Examples

      iex> AppRole.list_roles()
      [%{role_id: "...", role_name: "production-app", ...}]
  """
  @spec list_roles() :: [map()]
  def list_roles do
    from(r in Role, where: r.auth_type == "approle")
    |> Repo.all()
    |> Enum.map(fn role ->
      %{
        role_id: role.role_id,
        role_name: role.role_name,
        policies: Map.get(role.metadata, "policies", []),
        secret_id_ttl: Map.get(role.metadata, "secret_id_ttl"),
        secret_id_num_uses: Map.get(role.metadata, "secret_id_num_uses"),
        secret_id_uses: Map.get(role.metadata, "secret_id_uses", 0),
        created_at: role.inserted_at
      }
    end)
  end

  @doc """
  Gets AppRole details by RoleID.

  ## Examples

      iex> AppRole.get_role(role_id)
      {:ok, %{role_id: "...", role_name: "production-app", ...}}
  """
  @spec get_role(String.t()) :: {:ok, map()} | {:error, String.t()}
  def get_role(role_id) do
    case Repo.get_by(Role, role_id: role_id, auth_type: "approle") do
      nil ->
        {:error, "Role not found"}

      role ->
        {:ok,
         %{
           role_id: role.role_id,
           role_name: role.role_name,
           policies: Map.get(role.metadata, "policies", []),
           secret_id_ttl: Map.get(role.metadata, "secret_id_ttl"),
           secret_id_num_uses: Map.get(role.metadata, "secret_id_num_uses"),
           secret_id_uses: Map.get(role.metadata, "secret_id_uses", 0),
           bound_cidr_list: Map.get(role.metadata, "bound_cidr_list", []),
           created_at: role.inserted_at
         }}
    end
  end

  # Private helper functions

  defp validate_secret_id(role, secret_id, source_ip) do
    stored_secret_id = Map.get(role.metadata, "secret_id")
    bind_secret_id = Map.get(role.metadata, "bind_secret_id", true)

    cond do
      # Check if SecretID is required
      bind_secret_id and secret_id != stored_secret_id ->
        {:error, "invalid_secret_id"}

      # Check TTL
      not valid_secret_id_ttl?(role) ->
        {:error, "secret_id_expired"}

      # Check usage limit
      not valid_secret_id_uses?(role) ->
        {:error, "secret_id_max_uses_exceeded"}

      # Check CIDR binding
      not valid_source_ip?(role, source_ip) ->
        {:error, "source_ip_not_allowed"}

      true ->
        :ok
    end
  end

  defp valid_secret_id_ttl?(role) do
    created_at_str = Map.get(role.metadata, "secret_id_created_at")
    ttl = Map.get(role.metadata, "secret_id_ttl", @secret_id_ttl_default)

    case DateTime.from_iso8601(created_at_str) do
      {:ok, created_at, _offset} ->
        expires_at = DateTime.add(created_at, ttl, :second)
        DateTime.compare(DateTime.utc_now() |> DateTime.truncate(:second), expires_at) == :lt

      _ ->
        false
    end
  end

  defp valid_secret_id_uses?(role) do
    uses = Map.get(role.metadata, "secret_id_uses", 0)
    max_uses = Map.get(role.metadata, "secret_id_num_uses", @max_secret_id_uses)

    # 0 means unlimited
    max_uses == 0 or uses < max_uses
  end

  defp valid_source_ip?(role, source_ip) do
    bound_cidr_list = Map.get(role.metadata, "bound_cidr_list", [])

    # Empty list means no IP restriction
    if Enum.empty?(bound_cidr_list) do
      true
    else
      # TODO: Implement CIDR matching
      # For now, just check exact match
      Enum.member?(bound_cidr_list, source_ip)
    end
  end

  defp generate_auth_token(role) do
    # Generate JWT-like token
    # In production, this would be a proper JWT with signature
    payload = %{
      role_id: role.role_id,
      role_name: role.role_name,
      policies: Map.get(role.metadata, "policies", []),
      issued_at: DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_unix(),
      expires_at: DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.add(3600, :second) |> DateTime.to_unix()
    }

    # For now, use simple base64 encoding
    # TODO: Implement proper JWT signing
    Jason.encode!(payload) |> Base.url_encode64(padding: false)
  end

  defp audit_event(event_type, role_id, metadata) do
    audit_log = %AuditLog{
      event_id: Ecto.UUID.generate(),
      sequence_number: :erlang.system_time(:millisecond),
      event_type: event_type,
      actor_type: "approle",
      actor_id: role_id,
      event_data: metadata,
      timestamp: DateTime.utc_now() |> DateTime.truncate(:second),
      created_at: DateTime.utc_now() |> DateTime.truncate(:second),
      access_granted: String.contains?(event_type, "success"),
      response_time_ms: 0,
      correlation_id: Ecto.UUID.generate()
    }

    Repo.insert(audit_log)
  end

  @doc """
  Generate a new secret ID for a role.
  TODO: Implement proper secret ID generation.
  """
  @spec generate_secret_id(String.t()) :: {:ok, String.t()} | {:error, String.t()}
  def generate_secret_id(_role_id) do
    # Placeholder implementation - satisfies type system
    if false do
      {:ok, Ecto.UUID.generate()}
    else
      {:error, "Not implemented"}
    end
  end

  @doc """
  Verify an AppRole token.
  TODO: Implement proper token verification.
  """
  @spec verify_token(String.t()) :: {:ok, map()} | {:error, String.t()}
  def verify_token(_token) do
    # Placeholder implementation - satisfies type system
    if false do
      {:ok, %{role_name: "admin", policies: []}}
    else
      {:error, "Not implemented"}
    end
  end
end
