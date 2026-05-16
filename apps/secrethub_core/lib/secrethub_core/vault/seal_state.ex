defmodule SecretHub.Core.Vault.SealState do
  @moduledoc """
  GenServer managing the vault's seal/unseal state.

  The vault starts in a sealed state and must be unsealed using Shamir shares
  before it can decrypt secrets. Once unsealed, the master encryption key remains
  in memory until the vault is explicitly sealed or the server process stops.

  ## States
  - `:not_initialized` - Vault has never been initialized
  - `:sealed` - Vault is initialized but sealed (master key not in memory)
  - `:unsealed` - Vault is unsealed (master key in memory)

  ## Security Features
  - Master key never persists to disk unencrypted
  - Audit logging of all seal state changes
  - Constant-time operations where applicable
  """

  use GenServer
  require Logger

  alias SecretHub.Core.Audit
  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Crypto.{Encryption, Shamir}
  alias SecretHub.Shared.Schemas.VaultConfig

  defmodule State do
    @moduledoc false
    defstruct status: :not_initialized,
              master_key: nil,
              encrypted_master_key: nil,
              unseal_shares: [],
              threshold: nil,
              total_shares: nil,
              unseal_progress: 0,
              initialized_at: nil,
              unsealed_at: nil

    @type status :: :not_initialized | :sealed | :unsealed
    @type t :: %__MODULE__{
            status: status(),
            master_key: binary() | nil,
            encrypted_master_key: binary() | nil,
            unseal_shares: [Shamir.share()],
            threshold: non_neg_integer() | nil,
            total_shares: non_neg_integer() | nil,
            unseal_progress: non_neg_integer(),
            initialized_at: DateTime.t() | nil,
            unsealed_at: DateTime.t() | nil
          }
  end

  # Client API

  @doc """
  Starts the SealState GenServer.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Initializes the vault with Shamir secret sharing.

  Generates a master key, splits it into shares, and stores the encrypted
  master key in the database.

  Returns the unseal shares that must be distributed to administrators.
  """
  @spec initialize(pos_integer(), pos_integer()) ::
          {:ok, [Shamir.share()]} | {:error, String.t()}
  def initialize(total_shares, threshold) do
    GenServer.call(__MODULE__, {:initialize, total_shares, threshold})
  end

  @doc """
  Provides an unseal share to progress unsealing.

  Returns the current unseal progress and whether unsealing is complete.
  """
  @spec unseal(Shamir.share()) ::
          {:ok, %{sealed: boolean(), progress: non_neg_integer(), threshold: non_neg_integer()}}
          | {:error, String.t()}
  def unseal(share) do
    GenServer.call(__MODULE__, {:unseal, share})
  end

  @doc """
  Manual sealing is disabled. The vault remains unsealed until the server process stops.
  """
  @spec seal() :: :ok
  def seal do
    GenServer.call(__MODULE__, :seal)
  end

  @doc """
  Returns the current seal status.
  """
  @spec status() :: %{
          initialized: boolean(),
          sealed: boolean(),
          progress: non_neg_integer(),
          threshold: non_neg_integer() | nil,
          total_shares: non_neg_integer() | nil
        }
  def status do
    GenServer.call(__MODULE__, :status)
  end

  @doc """
  Returns whether the vault is initialized.
  """
  @spec initialized?() :: boolean()
  def initialized? do
    status = status()
    status.initialized
  end

  @doc """
  Returns whether the vault is sealed.
  """
  @spec sealed?() :: boolean()
  def sealed? do
    status = status()
    status.sealed
  end

  @doc """
  Gets the master encryption key if vault is unsealed.

  Returns `{:ok, key}` if unsealed, `{:error, :sealed}` if sealed.
  """
  @spec get_master_key() :: {:ok, binary()} | {:error, :sealed | :not_initialized}
  def get_master_key do
    GenServer.call(__MODULE__, :get_master_key)
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    # Check if vault is already initialized by looking for stored encrypted master key
    state = load_vault_state()

    Logger.info("Vault SealState initialized - Status: #{state.status}")

    # Try to audit the event, but don't fail if DB isn't ready (test mode)
    try do
      audit_event("vault_started", state.status)
    rescue
      # Sandbox not ready yet in test mode
      RuntimeError -> :ok
      # DB connection not ready
      ArgumentError -> :ok
    end

    {:ok, state}
  end

  @impl true
  def handle_call({:initialize, total_shares, threshold}, _from, state) do
    case state.status do
      :not_initialized ->
        # Generate master encryption key
        master_key = Encryption.generate_key()

        # Split into Shamir shares
        case Shamir.split(master_key, total_shares, threshold) do
          {:ok, shares} ->
            # Encrypt master key with a random key derivation key (KDK)
            # In production, this KDK would be wrapped by an HSM or cloud KMS
            kdk = Encryption.generate_key()
            {:ok, encrypted_master_key} = Encryption.encrypt_to_blob(master_key, kdk)

            persist_vault_config(encrypted_master_key, threshold, total_shares)

            new_state = %{
              state
              | status: :sealed,
                encrypted_master_key: encrypted_master_key,
                threshold: threshold,
                total_shares: total_shares,
                initialized_at: DateTime.utc_now() |> DateTime.truncate(:second)
            }

            Logger.info("Vault initialized with #{total_shares} shares (threshold: #{threshold})")

            audit_event("vault_initialized", :sealed, %{
              threshold: threshold,
              total_shares: total_shares
            })

            {:reply, {:ok, shares}, new_state}

          {:error, reason} ->
            {:reply, {:error, reason}, state}
        end

      _ ->
        {:reply, {:error, "Vault already initialized"}, state}
    end
  end

  @impl true
  def handle_call({:unseal, share}, _from, state) do
    case state.status do
      :unsealed ->
        {:reply,
         {:ok,
          %{
            initialized: true,
            sealed: false,
            progress: state.threshold,
            threshold: state.threshold
          }}, state}

      :sealed ->
        process_unseal_share(share, state)

      :not_initialized ->
        {:reply, {:error, "Vault not initialized"}, state}
    end
  end

  @impl true
  def handle_call(:seal, _from, state) do
    case state.status do
      :unsealed ->
        Logger.info("Ignoring manual seal request; vault remains unsealed until server stop")
        {:reply, :ok, state}

      _ ->
        {:reply, :ok, state}
    end
  end

  @impl true
  def handle_call(:status, _from, state) do
    status = %{
      initialized: state.status != :not_initialized,
      sealed: state.status != :unsealed,
      progress: state.unseal_progress,
      threshold: state.threshold,
      total_shares: state.total_shares
    }

    {:reply, status, state}
  end

  @impl true
  def handle_call(:get_master_key, _from, state) do
    case state.status do
      :unsealed ->
        {:reply, {:ok, state.master_key}, state}

      :sealed ->
        {:reply, {:error, :sealed}, state}

      :not_initialized ->
        {:reply, {:error, :not_initialized}, state}
    end
  end

  @impl true
  def handle_info(:auto_seal, state) do
    Logger.debug("Ignoring stale vault auto-seal message")
    {:noreply, state}
  end

  # Private helper functions

  defp process_unseal_share(share, state) do
    if Shamir.valid_share?(share) do
      new_shares = [share | state.unseal_shares] |> Enum.uniq_by(& &1.id)
      new_progress = length(new_shares)

      if new_progress >= state.threshold do
        attempt_reconstruct_master_key(new_shares, state)
      else
        new_state = %{state | unseal_shares: new_shares, unseal_progress: new_progress}

        {:reply,
         {:ok,
          %{initialized: true, sealed: true, progress: new_progress, threshold: state.threshold}},
         new_state}
      end
    else
      {:reply, {:error, "Invalid share format"}, state}
    end
  end

  defp attempt_reconstruct_master_key(new_shares, state) do
    case Shamir.combine(Enum.take(new_shares, state.threshold)) do
      {:ok, reconstructed_key} ->
        new_state = %{
          state
          | status: :unsealed,
            master_key: reconstructed_key,
            unseal_shares: [],
            unseal_progress: 0,
            unsealed_at: DateTime.utc_now() |> DateTime.truncate(:second)
        }

        Logger.info("Vault unsealed successfully")
        audit_event("vault_unsealed", :unsealed)

        {:reply,
         {:ok,
          %{
            initialized: true,
            sealed: false,
            progress: state.threshold,
            threshold: state.threshold
          }}, new_state}

      {:error, reason} ->
        Logger.error("Failed to reconstruct master key: #{reason}")
        {:reply, {:error, "Failed to reconstruct key"}, state}
    end
  end

  defp load_vault_state do
    case load_vault_config_from_db() do
      {:ok, %VaultConfig{} = config} ->
        %State{
          status: :sealed,
          master_key: nil,
          encrypted_master_key: config.encrypted_master_key,
          unseal_shares: [],
          threshold: config.threshold,
          total_shares: config.total_shares,
          unseal_progress: 0,
          initialized_at: config.initialized_at
        }

      {:error, _reason} ->
        %State{
          status: :not_initialized,
          master_key: nil,
          encrypted_master_key: nil,
          unseal_shares: [],
          threshold: nil,
          total_shares: nil,
          unseal_progress: 0
        }
    end
  end

  defp load_vault_config_from_db do
    import Ecto.Query

    try do
      case Repo.one(from(vc in VaultConfig, limit: 1)) do
        nil -> {:error, :not_found}
        config -> {:ok, config}
      end
    rescue
      # DB not ready during startup or in test mode
      _ -> {:error, :db_not_ready}
    end
  end

  defp persist_vault_config(encrypted_master_key, threshold, total_shares) do
    import Ecto.Query

    now = DateTime.utc_now() |> DateTime.truncate(:second)

    attrs = %{
      encrypted_master_key: encrypted_master_key,
      threshold: threshold,
      total_shares: total_shares,
      initialized_at: now
    }

    try do
      # Delete any existing config (singleton pattern)
      Repo.delete_all(from(vc in VaultConfig))

      %VaultConfig{}
      |> VaultConfig.changeset(attrs)
      |> Repo.insert!()

      Logger.info("Vault configuration persisted to database")
    rescue
      e ->
        Logger.error("Failed to persist vault config: #{inspect(e)}")
        {:error, :persistence_failed}
    end
  end

  defp audit_event(event_type, status, metadata \\ %{}) do
    # Use the Audit module's log_event to ensure proper hash chain
    event_data =
      Map.merge(metadata, %{
        "vault_status" => to_string(status),
        "event_type" => event_type
      })

    try do
      # Try to use the Audit module if available
      # This ensures proper hash chain management
      if Code.ensure_loaded?(Audit) do
        Audit.log_event(%{
          event_type: event_type,
          actor_type: "system",
          actor_id: "vault",
          event_data: event_data,
          access_granted: true,
          response_time_ms: 0
        })
      end
    rescue
      # Ignore audit errors in test mode or when DB isn't ready
      _ -> :ok
    end
  end
end
