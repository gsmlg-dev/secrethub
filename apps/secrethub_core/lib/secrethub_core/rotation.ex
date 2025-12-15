defmodule SecretHub.Core.Rotation do
  @moduledoc """
  Behavior for secret rotation engines.

  Rotation engines handle the automatic rotation of long-lived credentials
  with zero downtime. Each engine implements a specific rotation strategy
  for different types of secrets (database passwords, AWS keys, API keys, etc.).

  ## Rotation Process

  1. **Pre-rotation Check**: Validate current credentials work
  2. **Create New Credential**: Generate new password/key
  3. **Grace Period**: Both old and new credentials work simultaneously
  4. **Update Applications**: Applications transition to new credentials
  5. **Revoke Old Credential**: Remove old password/key
  6. **Verify**: Confirm new credentials work and old ones don't

  ## Rollback Strategy

  If rotation fails at any step:
  1. Restore old credential if it was removed
  2. Log failure reason
  3. Alert operators
  4. Do not proceed with scheduled rotation

  ## Example Implementation

      defmodule MyApp.DatabasePasswordRotation do
        @behaviour SecretHub.Core.Rotation

        @impl true
        def rotate(schedule, opts) do
          with :ok <- validate_current_password(schedule),
               {:ok, new_password} <- generate_new_password(),
               :ok <- create_new_password(new_password),
               :ok <- wait_grace_period(schedule.grace_period_seconds),
               :ok <- update_applications(new_password),
               :ok <- revoke_old_password() do
            {:ok, %{old_version: "v1", new_version: "v2"}}
          else
            {:error, reason} -> {:error, reason}
          end
        end

        @impl true
        def rollback(schedule, history) do
          # Restore old password
          restore_password(history.old_version)
        end
      end
  """

  @type schedule :: %SecretHub.Shared.Schemas.RotationSchedule{}
  @type history :: %SecretHub.Shared.Schemas.RotationHistory{}
  @type rotation_result :: %{
          old_version: String.t(),
          new_version: String.t(),
          metadata: map()
        }
  @type error_reason :: atom() | String.t()

  @doc """
  Perform a rotation for the given schedule.

  ## Parameters

  - `schedule` - The rotation schedule configuration
  - `opts` - Additional options:
    - `:dry_run` - If true, validate but don't actually rotate
    - `:force` - If true, skip pre-rotation checks

  ## Returns

  - `{:ok, result}` - Rotation succeeded with version information
  - `{:error, reason}` - Rotation failed

  ## Rotation Steps

  The rotation should follow these steps:
  1. Validate current credential works
  2. Generate new credential
  3. Create/activate new credential in target system
  4. Wait for grace period (both credentials work)
  5. Update dependent applications
  6. Revoke/deactivate old credential
  7. Verify only new credential works
  """
  @callback rotate(schedule, opts :: keyword()) ::
              {:ok, rotation_result()} | {:error, error_reason()}

  @doc """
  Rollback a failed rotation.

  This is called when a rotation fails and needs to be reverted.
  The implementation should restore the old credential and ensure
  the system is in a stable state.

  ## Parameters

  - `schedule` - The rotation schedule
  - `history` - The history record of the failed rotation

  ## Returns

  - `:ok` - Rollback succeeded
  - `{:error, reason}` - Rollback failed (manual intervention required)
  """
  @callback rollback(schedule, history) :: :ok | {:error, error_reason()}

  @doc """
  Validate rotation configuration.

  Called when creating or updating a rotation schedule to ensure
  the configuration is valid.

  ## Parameters

  - `config` - The rotation configuration map

  ## Returns

  - `:ok` - Configuration is valid
  - `{:error, errors}` - Configuration is invalid
  """
  @callback validate_config(config :: map()) :: :ok | {:error, list()}

  @optional_callbacks [validate_config: 1]
end
