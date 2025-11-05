defmodule SecretHub.Core.Engines.Dynamic do
  @moduledoc """
  Behaviour for dynamic secret engines.

  Dynamic secret engines generate temporary credentials on-demand with
  configurable time-to-live (TTL). Credentials are automatically revoked
  when the lease expires.

  ## Responsibilities

  Dynamic engines are responsible for:
  - Generating fresh credentials with specified TTL
  - Renewing leases before expiry
  - Revoking credentials when leases expire
  - Managing connection pools to external systems
  - Validating role configurations

  ## Lifecycle

  1. **Configuration**: Engine is configured with connection details and roles
  2. **Generation**: Client requests credentials for a specific role
  3. **Lease Creation**: Credentials are returned with a lease ID and TTL
  4. **Renewal**: Clients can renew leases before expiry
  5. **Revocation**: Credentials are revoked on lease expiry or manual revocation

  ## Example Implementation

      defmodule MyApp.Engines.PostgreSQL do
        @behaviour SecretHub.Core.Engines.Dynamic

        @impl true
        def generate_credentials(role_name, opts) do
          # Connect to PostgreSQL
          # Create temporary user
          # Return credentials with TTL
          {:ok, %{username: "...", password: "...", ttl: 3600}}
        end

        @impl true
        def revoke_credentials(lease_id, credentials) do
          # Drop the temporary user
          :ok
        end

        @impl true
        def renew_lease(lease_id, opts) do
          # Extend the lease TTL
          {:ok, %{ttl: 3600}}
        end
      end
  """

  @type role_name :: String.t()
  @type lease_id :: String.t()
  @type ttl :: pos_integer()
  @type credentials :: map()
  @type error_reason :: atom() | String.t()

  @doc """
  Generate new credentials for the given role.

  ## Parameters

  - `role_name`: The name of the role to generate credentials for
  - `opts`: Options including:
    - `:ttl` - Requested TTL in seconds (optional, uses role default if not provided)
    - `:config` - Engine-specific configuration
    - `:metadata` - Additional metadata for audit logging

  ## Returns

  - `{:ok, credentials}` - Successfully generated credentials with metadata
    - `credentials.username` - Generated username
    - `credentials.password` - Generated password
    - `credentials.ttl` - Actual TTL granted (may differ from requested)
    - `credentials.metadata` - Engine-specific metadata (host, port, database, etc.)

  - `{:error, reason}` - Failed to generate credentials
  """
  @callback generate_credentials(role_name, opts :: keyword()) ::
              {:ok, credentials} | {:error, error_reason}

  @doc """
  Revoke credentials associated with a lease.

  This callback is invoked when:
  - A lease expires naturally
  - A client explicitly revokes a lease
  - The system performs cleanup of orphaned leases

  ## Parameters

  - `lease_id`: The ID of the lease being revoked
  - `credentials`: The credentials to revoke (includes username, connection info, etc.)

  ## Returns

  - `:ok` - Successfully revoked credentials
  - `{:error, reason}` - Failed to revoke (will be retried)
  """
  @callback revoke_credentials(lease_id, credentials) :: :ok | {:error, error_reason}

  @doc """
  Renew an existing lease.

  ## Parameters

  - `lease_id`: The ID of the lease to renew
  - `opts`: Options including:
    - `:increment` - Requested TTL increment in seconds
    - `:current_ttl` - Current remaining TTL
    - `:credentials` - Original credentials metadata

  ## Returns

  - `{:ok, %{ttl: new_ttl}}` - Successfully renewed with new TTL
  - `{:error, :not_renewable}` - This lease cannot be renewed
  - `{:error, reason}` - Failed to renew
  """
  @callback renew_lease(lease_id, opts :: keyword()) ::
              {:ok, %{ttl: ttl}} | {:error, error_reason}

  @doc """
  Validate role configuration.

  This callback is invoked when creating or updating a role configuration
  to ensure the configuration is valid before saving.

  ## Parameters

  - `config`: Role configuration map

  ## Returns

  - `:ok` - Configuration is valid
  - `{:error, errors}` - Configuration is invalid with error details
  """
  @callback validate_config(config :: map()) :: :ok | {:error, list()}

  @optional_callbacks [validate_config: 1]
end
