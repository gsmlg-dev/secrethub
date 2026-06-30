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

  alias SecretHub.Core.{Audit, Repo}
  alias SecretHub.Shared.Schemas.{CliAccessRequest, Role}

  # 10 minutes in seconds
  @secret_id_ttl_default 600
  # Single-use by default
  @max_secret_id_uses 1
  # 30 days in seconds
  @token_ttl_seconds 30 * 24 * 60 * 60

  @doc """
  Returns the lifetime used for AppRole client tokens.
  """
  @spec token_ttl_seconds() :: pos_integer()
  def token_ttl_seconds, do: @token_ttl_seconds

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
      policies: policies,
      metadata: %{
        "bind_secret_id" => bind_secret_id,
        "secret_id_ttl" => secret_id_ttl,
        "secret_id_num_uses" => secret_id_num_uses,
        "bound_cidr_list" => bound_cidr_list,
        "policies" => policies,
        "secret_id" => secret_id,
        "secret_id_created_at" =>
          DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_iso8601(),
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
          {:ok, %{token: String.t(), policies: list(), role_name: String.t(), ttl: pos_integer()}}
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
            policies = role_policies(role)

            Logger.info("AppRole login successful: #{role.role_name}")

            audit_event("approle_login_success", role_id, %{
              role_name: role.role_name,
              source_ip: source_ip
            })

            {:ok,
             %{
               token: token,
               policies: policies,
               role_name: role.role_name,
               ttl: @token_ttl_seconds
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
          |> Map.put(
            "secret_id_created_at",
            DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_iso8601()
          )
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
    |> Enum.map(&format_role/1)
  end

  @doc """
  Gets AppRole details by role name.

  Uses a database query instead of loading all roles and filtering in memory.
  """
  @spec get_role_by_name(String.t()) :: {:ok, map()} | {:error, String.t()}
  def get_role_by_name(role_name) do
    case Repo.get_by(Role, role_name: role_name, auth_type: "approle") do
      nil ->
        {:error, "Role not found"}

      role ->
        {:ok, format_role(role)}
    end
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
        {:ok, format_role(role)}
    end
  end

  @doc """
  Issues an AppRole token for an existing role without requiring a SecretID.

  This is intended for admin-approved flows such as CLI Access, where the admin
  explicitly chooses which AppRole should back the issued token.
  """
  @spec issue_token_for_role(String.t(), String.t(), map()) ::
          {:ok, %{token: String.t(), policies: list(), role_name: String.t(), ttl: pos_integer()}}
          | {:error, String.t()}
  def issue_token_for_role(role_id, source_ip \\ "unknown", token_metadata \\ %{}) do
    case Repo.get_by(Role, role_id: role_id, auth_type: "approle") do
      nil ->
        {:error, "Role not found"}

      %{enabled: false} ->
        {:error, "Role disabled"}

      role ->
        policies = role_policies(role)
        token = generate_auth_token(role, token_metadata)

        audit_event("approle_token_issued", role.role_id, %{
          role_name: role.role_name,
          source_ip: source_ip
        })

        {:ok,
         %{
           token: token,
           policies: policies,
           role_name: role.role_name,
           ttl: @token_ttl_seconds
         }}
    end
  end

  @doc """
  Replaces the policies attached to an AppRole.

  Updates both the role's policy field and metadata policy list so legacy callers
  that read either location see the same policy bindings.
  """
  @spec update_role_policies(String.t(), [String.t()]) :: {:ok, map()} | {:error, String.t()}
  def update_role_policies(role_id, policies) when is_list(policies) do
    policies = normalize_policies(policies)

    case Repo.get_by(Role, role_id: role_id, auth_type: "approle") do
      nil ->
        {:error, "Role not found"}

      role ->
        metadata = (role.metadata || %{}) |> Map.put("policies", policies)

        role
        |> Role.changeset(%{policies: policies, metadata: metadata})
        |> Repo.update()
        |> case do
          {:ok, updated_role} ->
            Logger.info("Updated AppRole policies: #{role.role_name}")

            audit_event("policy.updated", role_id, %{
              role_name: role.role_name,
              policies: policies
            })

            {:ok, format_role(updated_role)}

          {:error, changeset} ->
            {:error, "Failed to update role policies: #{inspect(changeset.errors)}"}
        end
    end
  end

  # Private helper functions

  defp normalize_policies(policies) do
    policies
    |> Enum.map(&to_string/1)
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.uniq()
  end

  defp role_policies(role) do
    metadata_policies = Map.get(role.metadata || %{}, "policies")

    cond do
      is_list(metadata_policies) -> metadata_policies
      is_list(role.policies) -> role.policies
      true -> []
    end
  end

  defp format_role(role) do
    %{
      role_id: role.role_id,
      role_name: role.role_name,
      policies: role_policies(role),
      secret_id_ttl: Map.get(role.metadata, "secret_id_ttl"),
      secret_id_num_uses: Map.get(role.metadata, "secret_id_num_uses"),
      secret_id_uses: Map.get(role.metadata, "secret_id_uses", 0),
      bound_cidr_list: Map.get(role.metadata, "bound_cidr_list", []),
      created_at: role.inserted_at
    }
  end

  defp validate_secret_id(role, secret_id, source_ip) do
    stored_secret_id = Map.get(role.metadata, "secret_id")
    bind_secret_id = Map.get(role.metadata, "bind_secret_id", true)

    cond do
      # Use constant-time comparison to prevent timing attacks
      bind_secret_id and not Plug.Crypto.secure_compare(secret_id, stored_secret_id) ->
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
      ip_in_any_cidr?(source_ip, bound_cidr_list)
    end
  end

  defp ip_in_any_cidr?(ip_string, cidr_list) do
    case :inet.parse_address(String.to_charlist(ip_string)) do
      {:ok, ip} ->
        Enum.any?(cidr_list, fn cidr -> ip_matches_cidr?(ip, cidr) end)

      {:error, _} ->
        false
    end
  end

  defp ip_matches_cidr?(ip, cidr) do
    case parse_cidr(cidr) do
      {:ok, network, prefix_len} ->
        ip_to_integer(ip) |> mask(prefix_len) ==
          ip_to_integer(network) |> mask(prefix_len)

      :error ->
        # Fall back to exact match for bare IP addresses
        to_string(:inet.ntoa(ip)) == cidr
    end
  end

  defp parse_cidr(cidr) do
    case String.split(cidr, "/") do
      [ip_str, prefix_str] ->
        with {:ok, ip} <- :inet.parse_address(String.to_charlist(ip_str)),
             {prefix_len, ""} <- Integer.parse(prefix_str),
             true <- valid_prefix_length?(ip, prefix_len) do
          {:ok, ip, prefix_len}
        else
          _ -> :error
        end

      _ ->
        :error
    end
  end

  defp valid_prefix_length?(ip, len) when tuple_size(ip) == 4, do: len >= 0 and len <= 32
  defp valid_prefix_length?(ip, len) when tuple_size(ip) == 8, do: len >= 0 and len <= 128

  defp ip_to_integer({a, b, c, d}) do
    Bitwise.bsl(a, 24) + Bitwise.bsl(b, 16) + Bitwise.bsl(c, 8) + d
  end

  defp ip_to_integer({a, b, c, d, e, f, g, h}) do
    Enum.reduce([a, b, c, d, e, f, g, h], 0, fn segment, acc ->
      Bitwise.bsl(acc, 16) + segment
    end)
  end

  defp mask(ip_int, prefix_len) do
    shift = max(0, bit_size_for(ip_int) - prefix_len)
    Bitwise.bsr(ip_int, shift)
  end

  defp bit_size_for(n) when n <= 0xFFFFFFFF, do: 32
  defp bit_size_for(_), do: 128

  defp generate_auth_token(role, token_metadata \\ %{}) do
    payload =
      %{
        role_id: role.role_id,
        role_name: role.role_name,
        policies: role_policies(role),
        issued_at: DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_unix()
      }
      |> Map.merge(allowed_token_metadata(token_metadata))

    Phoenix.Token.sign(SecretHub.Web.Endpoint, "approle_auth", payload)
  end

  defp audit_event(event_type, role_id, metadata) do
    Audit.log_event(%{
      event_type: event_type,
      actor_type: "approle",
      actor_id: role_id,
      event_data: metadata,
      access_granted: successful_event?(event_type),
      response_time_ms: 0
    })
  end

  defp successful_event?(event_type) do
    String.contains?(event_type, "success") or String.ends_with?(event_type, "renewed") or
      String.ends_with?(event_type, "issued")
  end

  @doc """
  Generate a new secret ID for a role.

  Rotates the secret ID and returns the new value.
  """
  @spec generate_secret_id(String.t()) :: {:ok, String.t()} | {:error, String.t()}
  def generate_secret_id(role_id) do
    case rotate_secret_id(role_id) do
      {:ok, %{secret_id: new_id}} -> {:ok, new_id}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Verify an AppRole token and return its payload.
  """
  @spec verify_token(String.t()) :: {:ok, map()} | {:error, String.t()}
  def verify_token(token) do
    case Phoenix.Token.verify(SecretHub.Web.Endpoint, "approle_auth", token,
           max_age: @token_ttl_seconds
         ) do
      {:ok, payload} ->
        verify_cli_access_payload(payload)

      {:error, :expired} ->
        {:error, "Token has expired"}

      {:error, _reason} ->
        {:error, "Invalid token"}
    end
  end

  @doc """
  Renews a valid AppRole token by re-signing the current role state.
  """
  @spec renew_token(String.t()) ::
          {:ok, %{token: String.t(), policies: list(), role_name: String.t(), ttl: pos_integer()}}
          | {:error, String.t()}
  def renew_token(token) do
    with {:ok, payload} <- verify_token(token),
         {:ok, role} <- get_token_role(payload) do
      policies = role_policies(role)
      renewed_token = generate_auth_token(role, renewal_token_metadata(payload))

      audit_event("approle_token_renewed", role.role_id, %{
        role_name: role.role_name
      })

      {:ok,
       %{
         token: renewed_token,
         policies: policies,
         role_name: role.role_name,
         ttl: @token_ttl_seconds
       }}
    end
  end

  defp get_token_role(payload) do
    role_id = Map.get(payload, :role_id) || Map.get(payload, "role_id")

    case Repo.get_by(Role, role_id: role_id, auth_type: "approle") do
      nil -> {:error, "Role not found"}
      %{enabled: false} -> {:error, "Role disabled"}
      role -> {:ok, role}
    end
  end

  defp verify_cli_access_payload(payload) do
    case cli_access_request_id(payload) do
      nil ->
        {:ok, payload}

      request_id ->
        case Repo.get(CliAccessRequest, request_id) do
          nil -> {:error, "CLI access not found"}
          %{status: :revoked} -> {:error, "CLI access has been revoked"}
          _request -> {:ok, payload}
        end
    end
  end

  defp renewal_token_metadata(payload) do
    case cli_access_request_id(payload) do
      nil -> %{}
      request_id -> %{cli_access_request_id: request_id}
    end
  end

  defp allowed_token_metadata(metadata) when is_map(metadata) do
    metadata
    |> Enum.reduce(%{}, fn {key, value}, acc ->
      case normalize_token_metadata_key(key) do
        :cli_access_request_id -> Map.put(acc, :cli_access_request_id, value)
        nil -> acc
      end
    end)
  end

  defp allowed_token_metadata(_metadata), do: %{}

  defp normalize_token_metadata_key(:cli_access_request_id), do: :cli_access_request_id
  defp normalize_token_metadata_key("cli_access_request_id"), do: :cli_access_request_id
  defp normalize_token_metadata_key(_key), do: nil

  defp cli_access_request_id(payload) do
    Map.get(payload, :cli_access_request_id) || Map.get(payload, "cli_access_request_id")
  end
end
