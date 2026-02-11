defmodule SecretHub.Core.AutoUnseal do
  @moduledoc """
  Auto-unseal functionality for SecretHub.

  Automatically unseals the vault on startup by retrieving and decrypting
  unseal keys from cloud KMS providers (AWS KMS, Google Cloud KMS, Azure Key Vault).

  ## Auto-Unseal Flow

  1. **Initialization**: Admin initializes vault with auto-unseal enabled
     - Vault generates master key and unseal keys normally
     - Unseal keys are encrypted with KMS and stored in database
     - Only encrypted unseal keys are stored (plaintext keys never persisted)

  2. **Startup/Restart**: Node starts and vault is sealed
     - Auto-unseal process retrieves encrypted unseal keys from database
     - Decrypts keys using KMS provider
     - Automatically submits unseal keys to vault
     - Vault unseals without manual intervention

  3. **Failover**: If KMS is unavailable
     - Falls back to manual unseal if configured
     - Logs warning and waits for KMS recovery
     - Admin can still manually unseal as backup

  ## Configuration

  Auto-unseal is configured via environment variables or runtime config:

      config :secrethub_core, SecretHub.Core.AutoUnseal,
        enabled: true,
        provider: :aws_kms,  # or :gcp_kms, :azure_kv
        kms_key_id: "arn:aws:kms:us-east-1:123456789012:key/...",
        region: "us-east-1",
        max_retries: 3,
        retry_delay_ms: 5000

  ## Security Considerations

  - Unseal keys are ALWAYS encrypted before storage
  - KMS credentials should use IAM roles (AWS) or service accounts (GCP)
  - Never use long-lived credentials
  - KMS access is logged and audited
  - Supports key rotation for KMS keys

  ## HA Deployment

  In HA clusters:
  - Each node independently auto-unseals
  - No coordination needed (each node has same encrypted keys)
  - Leader node does not have special unsealing privilege
  - All nodes can auto-unseal concurrently
  """

  use GenServer
  require Logger

  alias SecretHub.Core.{Repo, Vault.SealState}
  alias SecretHub.Shared.Schemas.AutoUnsealConfig

  @type provider :: :aws_kms | :gcp_kms | :azure_kv | :disabled
  @type config :: %{
          enabled: boolean(),
          provider: provider(),
          kms_key_id: String.t(),
          region: String.t() | nil,
          max_retries: non_neg_integer(),
          retry_delay_ms: non_neg_integer()
        }

  defstruct [
    :config,
    :provider_module,
    :unseal_keys,
    :unseal_in_progress,
    :last_unseal_attempt
  ]

  @default_max_retries 3
  @default_retry_delay_ms 5000

  # Client API

  @doc """
  Starts the AutoUnseal GenServer.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Enables auto-unseal with the specified configuration.

  This should be called during vault initialization to configure auto-unseal.
  The unseal keys will be encrypted with the KMS provider and stored.

  ## Options

    * `:provider` - KMS provider (:aws_kms, :gcp_kms, :azure_kv)
    * `:kms_key_id` - KMS key identifier
    * `:region` - Cloud region (provider-specific)
    * `:unseal_keys` - List of unseal keys to encrypt and store

  Returns `{:ok, encrypted_keys}` on success or `{:error, reason}` on failure.
  """
  @spec enable(keyword()) :: {:ok, list(String.t())} | {:error, term()}
  def enable(opts) do
    GenServer.call(__MODULE__, {:enable_auto_unseal, opts}, 30_000)
  end

  @doc """
  Disables auto-unseal and removes stored encrypted keys.
  """
  @spec disable() :: :ok | {:error, term()}
  def disable do
    GenServer.call(__MODULE__, :disable_auto_unseal)
  end

  @doc """
  Manually triggers auto-unseal process.

  Useful for retry after KMS errors or manual testing.
  """
  @spec trigger_unseal() :: :ok | {:error, term()}
  def trigger_unseal do
    GenServer.call(__MODULE__, :trigger_unseal, 60_000)
  end

  @doc """
  Returns current auto-unseal configuration status.
  """
  @spec status() :: %{enabled: boolean(), provider: provider(), configured: boolean()}
  def status do
    GenServer.call(__MODULE__, :get_status)
  end

  @doc """
  Returns whether auto-unseal is enabled.
  """
  @spec enabled?() :: boolean()
  def enabled? do
    case status() do
      %{enabled: true, configured: true} -> true
      _ -> false
    end
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    # Load auto-unseal configuration from database
    config = load_config()

    state = %__MODULE__{
      config: config,
      provider_module: get_provider_module(config),
      unseal_keys: nil,
      unseal_in_progress: false,
      last_unseal_attempt: nil
    }

    # If auto-unseal is enabled and vault is sealed, trigger unseal
    if config.enabled && SealState.sealed?() do
      send(self(), :attempt_auto_unseal)
    end

    Logger.info("AutoUnseal initialized (enabled: #{config.enabled})")

    {:ok, state}
  end

  @impl true
  def handle_call({:enable_auto_unseal, opts}, _from, state) do
    provider = Keyword.fetch!(opts, :provider)
    kms_key_id = Keyword.fetch!(opts, :kms_key_id)
    region = Keyword.get(opts, :region)
    unseal_keys = Keyword.fetch!(opts, :unseal_keys)

    config = %{
      enabled: true,
      provider: provider,
      kms_key_id: kms_key_id,
      region: region,
      max_retries: @default_max_retries,
      retry_delay_ms: @default_retry_delay_ms
    }

    provider_module = get_provider_module(config)

    # Encrypt unseal keys with KMS
    case encrypt_unseal_keys(provider_module, config, unseal_keys) do
      {:ok, encrypted_keys} ->
        # Store encrypted keys in database
        case save_config(config, encrypted_keys) do
          {:ok, _} ->
            new_state = %{state | config: config, provider_module: provider_module}
            Logger.info("Auto-unseal enabled with provider: #{provider}")
            {:reply, {:ok, encrypted_keys}, new_state}

          {:error, reason} ->
            {:reply, {:error, reason}, state}
        end

      {:error, reason} ->
        Logger.error("Failed to encrypt unseal keys: #{inspect(reason)}")
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call(:disable_auto_unseal, _from, state) do
    case delete_config() do
      :ok ->
        new_config = %{enabled: false, provider: :disabled}

        new_state = %{state | config: new_config, provider_module: nil, unseal_keys: nil}

        Logger.info("Auto-unseal disabled")
        {:reply, :ok, new_state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call(:trigger_unseal, _from, state) do
    if state.config.enabled do
      result = perform_auto_unseal(state)
      {:reply, result, state}
    else
      {:reply, {:error, :auto_unseal_not_enabled}, state}
    end
  end

  @impl true
  def handle_call(:get_status, _from, state) do
    status = %{
      enabled: state.config.enabled,
      provider: state.config[:provider] || :disabled,
      configured: state.config.enabled && state.provider_module != nil
    }

    {:reply, status, state}
  end

  @impl true
  def handle_info(:attempt_auto_unseal, state) do
    if state.config.enabled && !state.unseal_in_progress do
      Logger.info("Attempting auto-unseal...")
      new_state = %{state | unseal_in_progress: true}

      case perform_auto_unseal(new_state) do
        :ok ->
          Logger.info("Auto-unseal successful")

          {:noreply,
           %{
             new_state
             | unseal_in_progress: false,
               last_unseal_attempt: DateTime.utc_now() |> DateTime.truncate(:second)
           }}

        {:error, reason} ->
          Logger.error("Auto-unseal failed: #{inspect(reason)}")
          # Schedule retry
          Process.send_after(self(), :attempt_auto_unseal, state.config.retry_delay_ms)

          {:noreply,
           %{
             new_state
             | unseal_in_progress: false,
               last_unseal_attempt: DateTime.utc_now() |> DateTime.truncate(:second)
           }}
      end
    else
      {:noreply, state}
    end
  end

  # Private Functions

  defp load_config do
    # Load from database or return default disabled config
    case Repo.get_by(AutoUnsealConfig, active: true) do
      nil ->
        %{enabled: false, provider: :disabled}

      config ->
        %{
          enabled: true,
          provider: String.to_existing_atom(config.provider),
          kms_key_id: config.kms_key_id,
          region: config.region,
          max_retries: config.max_retries || @default_max_retries,
          retry_delay_ms: config.retry_delay_ms || @default_retry_delay_ms
        }
    end
  rescue
    # If schema doesn't exist yet (during initial setup), return disabled
    _ -> %{enabled: false, provider: :disabled}
  end

  defp save_config(config, encrypted_keys) do
    # Deactivate any existing configs
    Repo.update_all(AutoUnsealConfig, set: [active: false])

    # Create new config
    attrs = %{
      provider: Atom.to_string(config.provider),
      kms_key_id: config.kms_key_id,
      region: config.region,
      encrypted_unseal_keys: encrypted_keys,
      active: true,
      max_retries: config.max_retries,
      retry_delay_ms: config.retry_delay_ms
    }

    %AutoUnsealConfig{}
    |> AutoUnsealConfig.changeset(attrs)
    |> Repo.insert()
  end

  defp delete_config do
    Repo.delete_all(AutoUnsealConfig)
    :ok
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp get_provider_module(%{provider: :aws_kms}), do: SecretHub.Core.AutoUnseal.Providers.AWSKMS
  defp get_provider_module(%{provider: :gcp_kms}), do: SecretHub.Core.AutoUnseal.Providers.GCPKMS

  defp get_provider_module(%{provider: :azure_kv}),
    do: SecretHub.Core.AutoUnseal.Providers.AzureKV

  defp get_provider_module(_), do: nil

  defp encrypt_unseal_keys(nil, _config, _keys), do: {:error, :no_provider}

  defp encrypt_unseal_keys(provider_module, config, unseal_keys) do
    # Encrypt each unseal key individually
    encrypted_keys =
      Enum.map(unseal_keys, fn key ->
        case provider_module.encrypt(config, key) do
          {:ok, encrypted} -> encrypted
          {:error, reason} -> throw({:encryption_error, reason})
        end
      end)

    {:ok, encrypted_keys}
  catch
    {:encryption_error, reason} -> {:error, reason}
  end

  defp perform_auto_unseal(state) do
    # Retrieve encrypted keys from database
    case Repo.get_by(AutoUnsealConfig, active: true) do
      nil ->
        {:error, :no_auto_unseal_config}

      config_record ->
        # Decrypt unseal keys using KMS
        case decrypt_unseal_keys(
               state.provider_module,
               state.config,
               config_record.encrypted_unseal_keys
             ) do
          {:ok, unseal_keys} ->
            # Submit unseal keys to vault
            submit_unseal_keys(unseal_keys)

          {:error, reason} ->
            {:error, reason}
        end
    end
  end

  defp decrypt_unseal_keys(nil, _config, _encrypted_keys), do: {:error, :no_provider}

  defp decrypt_unseal_keys(provider_module, config, encrypted_keys) do
    # Decrypt each key
    decrypted_keys =
      Enum.map(encrypted_keys, fn encrypted_key ->
        case provider_module.decrypt(config, encrypted_key) do
          {:ok, decrypted} -> decrypted
          {:error, reason} -> throw({:decryption_error, reason})
        end
      end)

    {:ok, decrypted_keys}
  catch
    {:decryption_error, reason} -> {:error, reason}
  end

  defp submit_unseal_keys(unseal_keys) do
    # Submit each unseal key to the seal state
    Enum.reduce_while(unseal_keys, :ok, fn key, _acc ->
      case SealState.unseal(key) do
        {:ok, %{sealed: false}} ->
          # Vault is unsealed
          {:halt, :ok}

        {:ok, %{sealed: true}} ->
          # Need more keys
          {:cont, :ok}

        {:error, reason} ->
          {:halt, {:error, reason}}
      end
    end)
  end
end
