defmodule SecretHub.Agent.PKI.TrustBundleManager do
  @moduledoc """
  Coordinates Agent-side Client Auth PKI trust bundle receipt, validation,
  atomic disk application, periodic synchronization, and convergence receipts.
  """

  use GenServer
  require Logger

  alias SecretHub.Agent.PKI.{AtomicStore, BundleValidator}

  # 15 minutes
  @periodic_sync_interval_ms 900_000
  # 5 minutes
  @max_retry_interval_ms 300_000

  defstruct [
    :state_dir,
    :base_dir,
    :agent_id,
    :connection_mod,
    # High-water mark state (from persistent watermark)
    lkg_generation: 0,
    lkg_crl_number: 0,
    lkg_ca_fingerprint: nil,
    lkg_bundle_sha256: nil,
    # Installed disk state (from current symlink)
    installed_generation: 0,
    installed_crl_number: 0,
    installed_ca_fingerprint: nil,
    installed_bundle_sha256: nil,
    needs_repair: false,
    last_applied_at: nil,
    # Synchronization status
    status: "initializing",
    recovery_mode: :none,
    observation_sequence: 0,
    last_error_code: nil,
    last_error_detail: nil,
    # Timers
    sync_timer: nil,
    retry_timer: nil,
    retry_attempt: 0,
    outbox_drain_timer: nil
  ]

  @type t :: %__MODULE__{}

  def start_link(opts) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @impl true
  def init(opts) do
    state_dir = Keyword.get(opts, :state_dir, Path.expand("~/.local/state/secrethub/agent"))

    base_dir =
      Keyword.get(opts, :bundle_dir) ||
        System.get_env("SECRET_HUB_CLIENT_AUTH_BUNDLE_DIR") ||
        Application.get_env(:secrethub_agent, :client_auth_bundle_dir) ||
        Path.join(state_dir, "pki/client-auth")

    agent_id = Keyword.get(opts, :agent_id)
    conn_mod = Keyword.get(opts, :connection_mod, SecretHub.Agent.Connection)

    # 1. Read persistent watermark
    persistent_wm_res = AtomicStore.read_persistent_watermark(base_dir)

    # 2. Validate disk bundle with pinned CA fingerprint if known from watermark
    pinned_ca_fp =
      case persistent_wm_res do
        {:ok, wm} -> wm["pinned_ca_fingerprint"]
        _ -> nil
      end

    disk_opts = if pinned_ca_fp, do: [pinned_ca_fingerprint: pinned_ca_fp], else: []

    disk_validation =
      BundleValidator.validate_disk_bundle(Path.join(base_dir, "current"), disk_opts)

    state =
      case {persistent_wm_res, disk_validation} do
        {{:ok, wm}, {:ok, validated}} ->
          wm_gen = wm["highest_seen_generation"] || 0
          wm_crl = wm["highest_seen_crl_number"] || 0
          wm_fp = wm["pinned_ca_fingerprint"]
          wm_hash = wm["last_bundle_sha256"]

          cond do
            validated.generation < wm_gen ->
              # Rollback detected: current is older than persistent watermark
              %__MODULE__{
                state_dir: state_dir,
                base_dir: base_dir,
                agent_id: agent_id,
                connection_mod: conn_mod,
                lkg_generation: wm_gen,
                lkg_crl_number: wm_crl,
                lkg_ca_fingerprint: wm_fp,
                lkg_bundle_sha256: wm_hash,
                installed_generation: validated.generation,
                installed_crl_number: validated.crl_number,
                installed_ca_fingerprint: validated.ca_fingerprint,
                installed_bundle_sha256: validated.bundle_sha256,
                needs_repair: true,
                status: "error",
                last_error_code: :generation_rollback,
                last_error_detail:
                  "disk generation #{validated.generation} is lower than persistent watermark #{wm_gen}"
              }

            validated.generation == wm_gen and wm_hash != nil and
                validated.bundle_sha256 != wm_hash ->
              # Equivocation detected on disk!
              %__MODULE__{
                state_dir: state_dir,
                base_dir: base_dir,
                agent_id: agent_id,
                connection_mod: conn_mod,
                lkg_generation: wm_gen,
                lkg_crl_number: wm_crl,
                lkg_ca_fingerprint: wm_fp,
                lkg_bundle_sha256: wm_hash,
                installed_generation: validated.generation,
                installed_crl_number: validated.crl_number,
                installed_ca_fingerprint: validated.ca_fingerprint,
                installed_bundle_sha256: validated.bundle_sha256,
                needs_repair: true,
                status: "error",
                last_error_code: :equivocation_detected,
                last_error_detail: "disk bundle hash does not match persistent watermark"
              }

            validated.generation >= wm_gen and validated.crl_number < wm_crl ->
              # CRL downgrade on disk!
              %__MODULE__{
                state_dir: state_dir,
                base_dir: base_dir,
                agent_id: agent_id,
                connection_mod: conn_mod,
                lkg_generation: wm_gen,
                lkg_crl_number: wm_crl,
                lkg_ca_fingerprint: wm_fp,
                lkg_bundle_sha256: wm_hash,
                installed_generation: validated.generation,
                installed_crl_number: validated.crl_number,
                installed_ca_fingerprint: validated.ca_fingerprint,
                installed_bundle_sha256: validated.bundle_sha256,
                needs_repair: true,
                status: "error",
                last_error_code: :crl_number_downgrade,
                last_error_detail: "disk CRL number is lower than persistent watermark"
              }

            wm_fp != nil and validated.ca_fingerprint != wm_fp ->
              # CA fingerprint mismatch!
              %__MODULE__{
                state_dir: state_dir,
                base_dir: base_dir,
                agent_id: agent_id,
                connection_mod: conn_mod,
                lkg_generation: wm_gen,
                lkg_crl_number: wm_crl,
                lkg_ca_fingerprint: wm_fp,
                lkg_bundle_sha256: wm_hash,
                installed_generation: validated.generation,
                installed_crl_number: validated.crl_number,
                installed_ca_fingerprint: validated.ca_fingerprint,
                installed_bundle_sha256: validated.bundle_sha256,
                needs_repair: true,
                status: "error",
                last_error_code: :ca_fingerprint_mismatch,
                last_error_detail: "disk CA fingerprint differs from persistent watermark"
              }

            true ->
              # Both watermark and disk match cleanly
              %__MODULE__{
                state_dir: state_dir,
                base_dir: base_dir,
                agent_id: agent_id,
                connection_mod: conn_mod,
                lkg_generation: max(validated.generation, wm_gen),
                lkg_crl_number: max(validated.crl_number, wm_crl),
                lkg_ca_fingerprint: validated.ca_fingerprint || wm_fp,
                lkg_bundle_sha256: validated.bundle_sha256 || wm_hash,
                installed_generation: validated.generation,
                installed_crl_number: validated.crl_number,
                installed_ca_fingerprint: validated.ca_fingerprint,
                installed_bundle_sha256: validated.bundle_sha256,
                last_applied_at: parse_datetime(validated.this_update),
                needs_repair: false,
                status: "applied"
              }
          end

        {{:ok, wm}, _disk_err} ->
          # Watermark exists but disk is missing or corrupted -> needs repair!
          %__MODULE__{
            state_dir: state_dir,
            base_dir: base_dir,
            agent_id: agent_id,
            connection_mod: conn_mod,
            lkg_generation: wm["highest_seen_generation"] || 0,
            lkg_crl_number: wm["highest_seen_crl_number"] || 0,
            lkg_ca_fingerprint: wm["pinned_ca_fingerprint"],
            lkg_bundle_sha256: wm["last_bundle_sha256"],
            installed_generation: 0,
            installed_crl_number: 0,
            installed_ca_fingerprint: nil,
            installed_bundle_sha256: nil,
            needs_repair: true,
            status: "initializing"
          }

        {{:error, wm_err}, _} ->
          case BundleValidator.find_surviving_disk_bundle(base_dir, disk_opts) do
            {:ok, surviving} ->
              # Surviving valid bundle exists on disk. Check active temporal validation of current/
              case BundleValidator.validate_disk_bundle(Path.join(base_dir, "current"), disk_opts) do
                {:ok, current_val} when current_val.generation == surviving.generation ->
                  if wm_err == :not_found do
                    # No watermark file existed -> write replacement watermark & mark applied
                    store_opts =
                      Keyword.take(opts, [
                        :inject_watermark_fsync_error,
                        :record_operations_to
                      ])

                    case AtomicStore.write_watermark(base_dir, surviving, store_opts) do
                      :ok ->
                        %__MODULE__{
                          state_dir: state_dir,
                          base_dir: base_dir,
                          agent_id: agent_id,
                          connection_mod: conn_mod,
                          lkg_generation: surviving.generation,
                          lkg_crl_number: surviving.crl_number,
                          lkg_ca_fingerprint: surviving.ca_fingerprint,
                          lkg_bundle_sha256: surviving.bundle_sha256,
                          installed_generation: surviving.generation,
                          installed_crl_number: surviving.crl_number,
                          installed_ca_fingerprint: surviving.ca_fingerprint,
                          installed_bundle_sha256: surviving.bundle_sha256,
                          last_applied_at: parse_datetime(surviving.this_update),
                          needs_repair: false,
                          status: "applied"
                        }

                      {:error, reason} ->
                        Logger.error("Failed to write initial watermark: #{inspect(reason)}")

                        # Preserve surviving lower bound in memory rather than resetting to 0
                        %__MODULE__{
                          state_dir: state_dir,
                          base_dir: base_dir,
                          agent_id: agent_id,
                          connection_mod: conn_mod,
                          lkg_generation: surviving.generation,
                          lkg_crl_number: surviving.crl_number,
                          lkg_ca_fingerprint: surviving.ca_fingerprint,
                          lkg_bundle_sha256: surviving.bundle_sha256,
                          installed_generation: surviving.generation,
                          installed_crl_number: surviving.crl_number,
                          installed_ca_fingerprint: surviving.ca_fingerprint,
                          installed_bundle_sha256: surviving.bundle_sha256,
                          last_applied_at: parse_datetime(surviving.this_update),
                          needs_repair: true,
                          status: "repair_required",
                          last_error_code: :watermark_persistence_failed,
                          last_error_detail: inspect(reason)
                        }
                    end
                  else
                    # Watermark on disk was present but corrupted. Preserve disk baseline to reject downgrades.
                    %__MODULE__{
                      state_dir: state_dir,
                      base_dir: base_dir,
                      agent_id: agent_id,
                      connection_mod: conn_mod,
                      lkg_generation: surviving.generation,
                      lkg_crl_number: surviving.crl_number,
                      lkg_ca_fingerprint: surviving.ca_fingerprint,
                      lkg_bundle_sha256: surviving.bundle_sha256,
                      installed_generation: surviving.generation,
                      installed_crl_number: surviving.crl_number,
                      installed_ca_fingerprint: surviving.ca_fingerprint,
                      installed_bundle_sha256: surviving.bundle_sha256,
                      last_applied_at: parse_datetime(surviving.this_update),
                      needs_repair: true,
                      status: "error",
                      last_error_code: :corrupted_watermark,
                      last_error_detail: inspect(wm_err)
                    }
                  end

                _ ->
                  # current/ is missing, pointing to older generation, or CRL expired.
                  # Establish cryptographic rollback barrier (lkg_*) from surviving, but report repair_required!
                  %__MODULE__{
                    state_dir: state_dir,
                    base_dir: base_dir,
                    agent_id: agent_id,
                    connection_mod: conn_mod,
                    lkg_generation: surviving.generation,
                    lkg_crl_number: surviving.crl_number,
                    lkg_ca_fingerprint: surviving.ca_fingerprint,
                    lkg_bundle_sha256: surviving.bundle_sha256,
                    installed_generation: 0,
                    installed_crl_number: 0,
                    installed_ca_fingerprint: nil,
                    installed_bundle_sha256: nil,
                    needs_repair: true,
                    status: "repair_required",
                    last_error_code:
                      if(wm_err == :not_found,
                        do: :historical_baseline_survived,
                        else: :corrupted_watermark
                      ),
                    last_error_detail:
                      "Surviving generation #{surviving.generation} established cryptographic baseline, active repair required"
                  }
              end

            {:error, :empty_installation} ->
              if wm_err == :not_found do
                # Clean first-time enrollment
                %__MODULE__{
                  state_dir: state_dir,
                  base_dir: base_dir,
                  agent_id: agent_id,
                  connection_mod: conn_mod,
                  needs_repair: true,
                  status: "initializing"
                }
              else
                # Watermark corrupted on disk with no surviving disk bundles -> quarantine
                %__MODULE__{
                  state_dir: state_dir,
                  base_dir: base_dir,
                  agent_id: agent_id,
                  connection_mod: conn_mod,
                  lkg_generation: 0,
                  lkg_crl_number: 0,
                  lkg_ca_fingerprint: nil,
                  lkg_bundle_sha256: nil,
                  installed_generation: 0,
                  installed_crl_number: 0,
                  installed_ca_fingerprint: nil,
                  installed_bundle_sha256: nil,
                  needs_repair: true,
                  recovery_mode: :quarantined,
                  status: "recovery_required",
                  last_error_code: :damaged_state_recovery_required,
                  last_error_detail:
                    "Corrupt watermark with no surviving disk bundle baseline. Operator intervention required."
                }
              end

            {:error, error_reason} ->
              # Conflicting, damaged, or corrupted candidate evidence -> quarantine
              %__MODULE__{
                state_dir: state_dir,
                base_dir: base_dir,
                agent_id: agent_id,
                connection_mod: conn_mod,
                lkg_generation: 0,
                lkg_crl_number: 0,
                lkg_ca_fingerprint: nil,
                lkg_bundle_sha256: nil,
                installed_generation: 0,
                installed_crl_number: 0,
                installed_ca_fingerprint: nil,
                installed_bundle_sha256: nil,
                needs_repair: true,
                recovery_mode: :quarantined,
                status: "recovery_required",
                last_error_code: :damaged_state_recovery_required,
                last_error_detail:
                  "Conflicting or damaged disk evidence detected during recovery: #{inspect(error_reason)}. Operator intervention required."
              }
          end
      end

    state =
      case AtomicStore.read_outbox(base_dir) do
        {:ok, %{highest_sequence: seq, outbox: ob}} ->
          if ob != [] do
            send(self(), :drain_outbox)
          end

          %{state | observation_sequence: seq}

        {:error, {:corrupted_outbox, reason}} ->
          Logger.error("Durable outbox corrupted: #{inspect(reason)}; entering quarantine")

          %{
            state
            | needs_repair: true,
              recovery_mode: :quarantined,
              status: "recovery_required",
              last_error_code: :corrupted_outbox,
              last_error_detail: inspect(reason),
              observation_sequence: 0
          }

        {:error, reason} ->
          Logger.error("Failed to read outbox during init: #{inspect(reason)}")
          %{state | observation_sequence: 0}
      end

    send(self(), :initial_reconcile)
    timer = schedule_periodic_sync()
    {:ok, %{state | sync_timer: timer}}
  end

  @doc """
  Processes a trust bundle map from Core (validates and writes atomically).
  Returns `{:ok, receipt}` or `{:error, error_code, receipt}`.
  """
  @spec process_bundle(pid() | module(), map(), keyword()) ::
          {:ok, map()}
          | {:error, atom(), map() | nil}
  def process_bundle(server \\ __MODULE__, bundle, opts \\ []) do
    GenServer.call(server, {:process_bundle, bundle, opts})
  end

  @doc """
  Triggers an immediate synchronization of the trust bundle from Core.
  """
  @spec sync_bundle(pid() | module(), keyword()) :: :ok
  def sync_bundle(server \\ __MODULE__, opts \\ []) do
    GenServer.cast(server, {:sync_bundle, opts})
  end

  @doc """
  Returns the current status of the TrustBundleManager.
  """
  @spec status(pid() | module()) :: map()
  def status(server \\ __MODULE__) do
    GenServer.call(server, :get_status)
  end

  @impl true
  def handle_call({:process_bundle, bundle, opts}, _from, state) do
    case apply_bundle(state, bundle, opts) do
      {:ok, receipt, new_state} ->
        {:reply, {:ok, receipt}, new_state}

      {:error, error_code, receipt, new_state} ->
        {:reply, {:error, error_code, receipt}, new_state}
    end
  end

  @impl true
  def handle_call(:get_status, _from, state) do
    info = %{
      current_generation: state.installed_generation,
      lkg_generation: state.lkg_generation,
      current_crl_number: state.installed_crl_number,
      lkg_crl_number: state.lkg_crl_number,
      bundle_sha256: state.installed_bundle_sha256 || state.lkg_bundle_sha256,
      last_applied_at: state.last_applied_at,
      status: state.status,
      recovery_mode: state.recovery_mode,
      observation_sequence: state.observation_sequence,
      needs_repair: state.needs_repair,
      last_error_code: state.last_error_code,
      last_error_detail: state.last_error_detail,
      base_dir: state.base_dir
    }

    {:reply, info, state}
  end

  @impl true
  def handle_cast({:sync_bundle, opts}, state) do
    new_state = do_sync(state, opts)
    {:noreply, new_state}
  end

  @impl true
  def handle_info(:initial_reconcile, state) do
    new_state = do_sync(state, [])
    {:noreply, new_state}
  end

  @impl true
  def handle_info(:periodic_sync, state) do
    new_state = do_sync(state, [])
    timer = schedule_periodic_sync()
    {:noreply, %{new_state | sync_timer: timer}}
  end

  @impl true
  def handle_info(:retry_sync, state) do
    state = %{state | retry_timer: nil}
    new_state = do_sync(state, [])
    {:noreply, new_state}
  end

  @impl true
  def handle_info(:drain_outbox, state) do
    state = %{state | outbox_drain_timer: nil}
    new_state = drain_outbox_loop(state)
    {:noreply, new_state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # Core Bundle Application & Verification

  defp apply_bundle(state, bundle, opts) do
    now = Keyword.get(opts, :now, DateTime.utc_now() |> DateTime.truncate(:second))
    force = Keyword.get(opts, :force, false)
    val_opts = Keyword.put_new(opts, :pinned_ca_fingerprint, state.lkg_ca_fingerprint)

    core_seq = bundle["last_accepted_sequence"] || bundle[:last_accepted_sequence]
    enqueue_opts = if is_integer(core_seq), do: [core_seq: core_seq] ++ opts, else: opts

    cond do
      state.recovery_mode == :quarantined and not force ->
        # Durable quarantine prevents non-forced application or sync from mutating state
        error_code = :damaged_state_recovery_required

        error_detail =
          "Trust bundle state is in durable quarantine. Operator intervention or force recovery required."

        new_state = %{
          state
          | status: "recovery_required",
            recovery_mode: :quarantined,
            last_error_code: to_string(error_code),
            last_error_detail: error_detail
        }

        raw_receipt = build_error_receipt(new_state, bundle, error_code, error_detail, now)

        case enqueue_and_submit_receipt(new_state, raw_receipt, enqueue_opts) do
          {:ok, receipt, final_state} ->
            Logger.error("Client Auth trust bundle rejected: quarantined state requires force")
            {:error, error_code, receipt, final_state}

          {:error, :receipt_persistence_failed, reason} ->
            Logger.error("Failed to persist receipt during quarantine: #{inspect(reason)}")
            {:error, :receipt_persistence_failed, nil, new_state}
        end

      true ->
        with {:ok, validated} <- BundleValidator.validate(bundle, val_opts),
             :ok <- check_monotonicity_and_invariants(state, validated, force) do
          # Determine if disk already has this exact bundle installed and verified
          is_disk_already_matching =
            !state.needs_repair and
              state.installed_generation == validated.generation and
              state.installed_bundle_sha256 == validated.bundle_sha256 and
              case BundleValidator.validate_disk_bundle(
                     Path.join(state.base_dir, "current"),
                     val_opts
                   ) do
                {:ok, disk_val} ->
                  disk_val.generation == validated.generation and
                    disk_val.bundle_sha256 == validated.bundle_sha256 and
                    disk_val.crl_number == validated.crl_number and
                    disk_val.ca_fingerprint == validated.ca_fingerprint

                _ ->
                  false
              end

          if !force and is_disk_already_matching do
            case maybe_repair_watermark(state.base_dir, validated) do
              :ok ->
                new_state = %{
                  state
                  | lkg_generation: validated.generation,
                    lkg_crl_number: validated.crl_number,
                    lkg_ca_fingerprint: validated.ca_fingerprint,
                    lkg_bundle_sha256: validated.bundle_sha256,
                    installed_generation: validated.generation,
                    installed_crl_number: validated.crl_number,
                    installed_ca_fingerprint: validated.ca_fingerprint,
                    installed_bundle_sha256: validated.bundle_sha256,
                    needs_repair: false,
                    status: "applied",
                    recovery_mode: :none,
                    last_error_code: nil,
                    last_error_detail: nil,
                    retry_attempt: 0
                }

                raw_receipt = build_receipt(new_state, "applied", now)

                case enqueue_and_submit_receipt(new_state, raw_receipt, enqueue_opts) do
                  {:ok, receipt, final_state} ->
                    {:ok, receipt, final_state}

                  {:error, :receipt_persistence_failed, reason} ->
                    Logger.error(
                      "Failed to persist receipt for applied bundle: #{inspect(reason)}"
                    )

                    {:error, :receipt_persistence_failed, nil, new_state}
                end

              {:error, reason} ->
                Logger.error(
                  "Failed to repair watermark during bundle validation: #{inspect(reason)}"
                )

                normalized = normalize_publication_error(reason)

                new_state = %{
                  state
                  | needs_repair: true,
                    status: "error",
                    last_error_code: to_string(normalized.code),
                    last_error_detail: normalized.detail
                }

                raw_receipt =
                  build_error_receipt(
                    new_state,
                    %{
                      "generation" => validated.generation,
                      "crl_number" => validated.crl_number,
                      "bundle_sha256" => validated.bundle_sha256
                    },
                    normalized.code,
                    normalized.detail,
                    now
                  )

                case enqueue_and_submit_receipt(new_state, raw_receipt, enqueue_opts) do
                  {:ok, receipt, final_state} ->
                    {:error, normalized.code, receipt, final_state}

                  {:error, :receipt_persistence_failed, reason} ->
                    Logger.error(
                      "Failed to persist watermark repair failure receipt: #{inspect(reason)}"
                    )

                    {:error, :receipt_persistence_failed, nil, new_state}
                end
            end
          else
            case AtomicStore.write_bundle(state.base_dir, bundle, opts) do
              {:ok, _result} ->
                new_state = %{
                  state
                  | lkg_generation: validated.generation,
                    lkg_crl_number: validated.crl_number,
                    lkg_ca_fingerprint: validated.ca_fingerprint,
                    lkg_bundle_sha256: validated.bundle_sha256,
                    installed_generation: validated.generation,
                    installed_crl_number: validated.crl_number,
                    installed_ca_fingerprint: validated.ca_fingerprint,
                    installed_bundle_sha256: validated.bundle_sha256,
                    last_applied_at: now,
                    needs_repair: false,
                    last_error_code: nil,
                    last_error_detail: nil,
                    status: "applied",
                    recovery_mode: :none,
                    retry_attempt: 0
                }

                raw_receipt = build_receipt(new_state, "applied", now)

                Logger.info(
                  "Client Auth trust bundle updated to generation #{validated.generation}"
                )

                case enqueue_and_submit_receipt(new_state, raw_receipt, enqueue_opts) do
                  {:ok, receipt, final_state} ->
                    {:ok, receipt, final_state}

                  {:error, :receipt_persistence_failed, reason} ->
                    Logger.error(
                      "Failed to persist receipt for updated bundle: #{inspect(reason)}"
                    )

                    {:error, :receipt_persistence_failed, nil, new_state}
                end

              {:error, reason} ->
                reconciled_state = reconcile_disk_state(state)
                normalized = normalize_publication_error(reason)

                new_state = %{
                  reconciled_state
                  | last_error_code: to_string(normalized.code),
                    last_error_detail: normalized.detail,
                    status: "failed",
                    needs_repair: true
                }

                raw_receipt =
                  build_error_receipt(
                    new_state,
                    bundle,
                    normalized.code,
                    normalized.detail,
                    now
                  )

                case enqueue_and_submit_receipt(new_state, raw_receipt, enqueue_opts) do
                  {:ok, receipt, final_state} ->
                    {:error, normalized.code, receipt, final_state}

                  {:error, :receipt_persistence_failed, reason} ->
                    Logger.error("Failed to persist write failure receipt: #{inspect(reason)}")
                    {:error, :receipt_persistence_failed, nil, new_state}
                end
            end
          end
        else
          {:error, error_code, detail} ->
            new_state = %{
              state
              | last_error_code: to_string(error_code),
                last_error_detail: detail,
                status: "failed"
            }

            raw_receipt = build_error_receipt(new_state, bundle, error_code, detail, now)

            Logger.error("Client Auth trust bundle rejected: #{error_code} - #{detail}")

            case enqueue_and_submit_receipt(new_state, raw_receipt, enqueue_opts) do
              {:ok, receipt, final_state} ->
                {:error, error_code, receipt, final_state}

              {:error, :receipt_persistence_failed, reason} ->
                Logger.error("Failed to persist invariant rejection receipt: #{inspect(reason)}")
                {:error, :receipt_persistence_failed, nil, new_state}
            end
        end
    end
  end

  defp normalize_publication_error(reason) do
    case reason do
      {:after_current_switched, cause} ->
        %{
          code: :dir_sync_failed_after_switch,
          phase: :post_switch_sync,
          cause: cause,
          detail: inspect(cause)
        }

      {:after_watermark_committed, cause} ->
        %{
          code: :pointer_switch_failed,
          phase: :pointer_switch,
          cause: cause,
          detail: inspect(cause)
        }

      {:watermark_commit_failed, cause} ->
        %{
          code: :watermark_commit_failed,
          phase: :watermark_commit,
          cause: cause,
          detail: inspect(cause)
        }

      {:before_watermark, cause} when is_atom(cause) ->
        %{code: cause, phase: :before_watermark, cause: cause, detail: to_string(cause)}

      {:before_watermark, cause} ->
        %{
          code: :atomic_write_failed,
          phase: :before_watermark,
          cause: cause,
          detail: inspect(cause)
        }

      other when is_atom(other) ->
        %{code: other, phase: :before_watermark, cause: other, detail: to_string(other)}

      other ->
        %{
          code: :atomic_write_failed,
          phase: :before_watermark,
          cause: other,
          detail: inspect(other)
        }
    end
  end

  defp check_monotonicity_and_invariants(state, validated, force) do
    cond do
      (state.recovery_mode == :quarantined or state.status == "recovery_required") and not force ->
        {:error, :damaged_state_recovery_required,
         "Trust bundle state is damaged with no surviving baseline. Operator intervention or force recovery required."}

      state.lkg_generation > 0 ->
        cond do
          validated.generation < state.lkg_generation ->
            {:error, :generation_downgrade_rejected,
             "Received generation #{validated.generation} < last-known-good generation #{state.lkg_generation}"}

          validated.generation == state.lkg_generation and
              validated.bundle_sha256 != state.lkg_bundle_sha256 ->
            {:error, :equivocation_detected,
             "Equivocation detected: received differing bundle hash for generation #{validated.generation}"}

          validated.generation > state.lkg_generation and
            state.lkg_ca_fingerprint != nil and
              validated.ca_fingerprint != state.lkg_ca_fingerprint ->
            {:error, :ca_fingerprint_mismatch,
             "Received CA fingerprint #{validated.ca_fingerprint} differs from established CA #{state.lkg_ca_fingerprint}"}

          validated.generation >= state.lkg_generation and
              validated.crl_number < state.lkg_crl_number ->
            {:error, :crl_number_downgrade,
             "Received CRL number #{validated.crl_number} < last-known-good CRL number #{state.lkg_crl_number}"}

          true ->
            :ok
        end

      true ->
        :ok
    end
  end

  defp reconcile_disk_state(state) do
    # Read persistent watermark to ensure memory reflects any durable watermark advance
    state =
      case AtomicStore.read_persistent_watermark(state.base_dir) do
        {:ok, wm} ->
          wm_gen = wm["highest_seen_generation"] || 0
          wm_crl = wm["highest_seen_crl_number"] || 0
          wm_fp = wm["pinned_ca_fingerprint"]
          wm_hash = wm["last_bundle_sha256"]

          %{
            state
            | lkg_generation: max(state.lkg_generation, wm_gen),
              lkg_crl_number: max(state.lkg_crl_number, wm_crl),
              lkg_ca_fingerprint: wm_fp || state.lkg_ca_fingerprint,
              lkg_bundle_sha256: wm_hash || state.lkg_bundle_sha256
          }

        _ ->
          state
      end

    # Check installed disk bundle
    case BundleValidator.validate_disk_historical_evidence(
           Path.join(state.base_dir, "current"),
           pinned_ca_fingerprint: state.lkg_ca_fingerprint
         ) do
      {:ok, disk_val} ->
        %{
          state
          | installed_generation: disk_val.generation,
            installed_crl_number: disk_val.crl_number,
            installed_ca_fingerprint: disk_val.ca_fingerprint,
            installed_bundle_sha256: disk_val.bundle_sha256,
            lkg_generation: max(state.lkg_generation, disk_val.generation),
            lkg_crl_number: max(state.lkg_crl_number, disk_val.crl_number)
        }

      _ ->
        state
    end
  end

  # Pull from Core and Apply

  defp do_sync(state, opts) do
    case pull_bundle_from_core(state) do
      {:ok, bundle} ->
        core_seq = bundle["last_accepted_sequence"] || bundle[:last_accepted_sequence]
        sync_opts = if is_integer(core_seq), do: [core_seq: core_seq] ++ opts, else: opts

        case apply_bundle(state, bundle, sync_opts) do
          {:ok, _receipt, new_state} ->
            new_state

          {:error, _code, _receipt, new_state} ->
            schedule_retry(new_state)
        end

      {:error, reason} ->
        Logger.debug("TrustBundleManager pull skipped or failed: #{inspect(reason)}")
        schedule_retry(state)
    end
  end

  defp pull_bundle_from_core(state) do
    conn_mod = state.connection_mod || SecretHub.Agent.Connection

    if Process.whereis(conn_mod) do
      case conn_mod.pull_trust_bundle() do
        {:ok, %{"bundle" => bundle}} when is_map(bundle) -> {:ok, bundle}
        {:ok, bundle} when is_map(bundle) -> {:ok, bundle}
        {:error, reason} -> {:error, reason}
      end
    else
      {:error, :connection_not_running}
    end
  catch
    _, reason -> {:error, reason}
  end

  defp enqueue_and_submit_receipt(state, raw_receipt, opts) do
    case AtomicStore.enqueue_observation(state.base_dir, raw_receipt, opts) do
      {:ok, seq, receipt} ->
        send(self(), :drain_outbox)
        {:ok, receipt, %{state | observation_sequence: seq}}

      {:error, reason} ->
        {:error, :receipt_persistence_failed, reason}
    end
  end

  defp drain_outbox_loop(state) do
    case AtomicStore.read_outbox(state.base_dir) do
      {:ok, %{outbox: []}} ->
        state

      {:ok, %{outbox: outbox}} ->
        sorted_outbox = Enum.sort_by(outbox, fn entry -> entry["sequence"] end)
        conn = state.connection_mod || SecretHub.Agent.Connection

        conn_alive? =
          cond do
            is_pid(conn) ->
              Process.alive?(conn)

            is_atom(conn) and Process.whereis(conn) != nil ->
              true

            is_atom(conn) and Code.ensure_loaded?(conn) ->
              Process.whereis(conn) != nil

            true ->
              false
          end

        if conn_alive? do
          entry = hd(sorted_outbox)
          seq = entry["sequence"]
          receipt = entry["receipt"]

          raw_response = safe_submit_receipt(conn, receipt)

          case normalize_submit_response(raw_response) do
            :ok ->
              case AtomicStore.acknowledge_observation(state.base_dir, seq) do
                :ok ->
                  if length(sorted_outbox) > 1 do
                    send(self(), :drain_outbox)
                  end

                  state

                {:error, reason} ->
                  Logger.error(
                    "Failed to persist ACK for observation sequence #{seq}: #{inspect(reason)}; scheduling backoff"
                  )

                  schedule_outbox_drain(state, 5_000)
              end

            {:rejected, error_code, error_reason} ->
              Logger.warning(
                "Observation sequence #{seq} permanently rejected by Core (#{error_code}: #{error_reason}); moving to dead-letter"
              )

              case AtomicStore.record_rejected_observation(
                     state.base_dir,
                     entry,
                     error_code,
                     error_reason
                   ) do
                :ok ->
                  if length(sorted_outbox) > 1 do
                    send(self(), :drain_outbox)
                  end

                  state

                {:error, reason} ->
                  Logger.error(
                    "Failed to persist dead-letter observation for sequence #{seq}: #{inspect(reason)}; scheduling backoff"
                  )

                  schedule_outbox_drain(state, 5_000)
              end

            {:transient_error, reason} ->
              Logger.debug("Outbox drain submission failed: #{inspect(reason)}; will retry")
              schedule_outbox_drain(state, 5_000)
          end
        else
          # Connection not running yet, retry later
          schedule_outbox_drain(state, 2_000)
        end

      {:error, {:corrupted_outbox, reason}} ->
        Logger.error("Durable outbox corrupted during draining: #{inspect(reason)}; quarantining")

        %{
          state
          | needs_repair: true,
            recovery_mode: :quarantined,
            status: "recovery_required",
            last_error_code: :corrupted_outbox,
            last_error_detail: inspect(reason)
        }

      {:error, reason} ->
        Logger.error("Failed to read outbox for draining: #{inspect(reason)}")
        schedule_outbox_drain(state, 5_000)
    end
  end

  defp normalize_submit_response(raw_response) do
    case raw_response do
      {:ok, _} ->
        :ok

      :ok ->
        :ok

      {:error, %{"reason" => "conflicting_observation_sequence"} = detail} ->
        {:rejected, :conflicting_observation_sequence,
         detail["detail"] || "conflicting observation sequence"}

      {:error, %{reason: "conflicting_observation_sequence"} = detail} ->
        {:rejected, :conflicting_observation_sequence,
         detail[:detail] || detail["detail"] || "conflicting observation sequence"}

      {:error, :conflicting_observation_sequence} ->
        {:rejected, :conflicting_observation_sequence, "conflicting observation sequence"}

      {:conflict, reason} ->
        {:rejected, :conflicting_observation_sequence, to_string(reason)}

      {:error, other} ->
        {:transient_error, other}

      other ->
        {:transient_error, other}
    end
  end

  defp schedule_outbox_drain(state, delay_ms) do
    if state.outbox_drain_timer, do: Process.cancel_timer(state.outbox_drain_timer)
    timer = Process.send_after(self(), :drain_outbox, delay_ms)
    %{state | outbox_drain_timer: timer}
  end

  defp safe_submit_receipt(conn, receipt) do
    try do
      cond do
        is_atom(conn) and function_exported?(conn, :submit_bundle_receipt, 1) ->
          conn.submit_bundle_receipt(receipt)

        true ->
          SecretHub.Agent.Connection.submit_bundle_receipt(conn, receipt)
      end
    catch
      :exit, reason -> {:error, {:exit, reason}}
      kind, error -> {:error, {kind, error}}
    end
  end

  # Helpers

  defp schedule_periodic_sync do
    # 15 minutes +/- 60s jitter
    jitter = :rand.uniform(120_000) - 60_000
    interval = max(60_000, @periodic_sync_interval_ms + jitter)
    Process.send_after(self(), :periodic_sync, interval)
  end

  defp schedule_retry(state) do
    attempt = state.retry_attempt + 1
    # Exponential backoff: 5s, 10s, 20s, 40s, ..., up to max 300s
    raw_interval = 5_000 * trunc(:math.pow(2, min(attempt, 6)))
    interval = min(@max_retry_interval_ms, raw_interval)

    if state.retry_timer, do: Process.cancel_timer(state.retry_timer)
    timer = Process.send_after(self(), :retry_sync, interval)

    %{state | retry_timer: timer, retry_attempt: attempt}
  end

  defp build_receipt(state, status, now) do
    %{
      "agent_id" => state.agent_id,
      "generation" => state.lkg_generation,
      "crl_number" => state.lkg_crl_number,
      "bundle_sha256" => state.lkg_bundle_sha256,
      "status" => status,
      "applied_at" => DateTime.to_iso8601(now)
    }
  end

  defp build_error_receipt(state, bundle, error_code, error_detail, now) do
    %{
      "agent_id" => state.agent_id,
      "generation" => bundle["generation"] || state.lkg_generation,
      "crl_number" => bundle["crl_number"] || state.lkg_crl_number,
      "bundle_sha256" => bundle["bundle_sha256"] || state.lkg_bundle_sha256 || "",
      "status" => "failed",
      "last_error_code" => to_string(error_code),
      "last_error_detail" => error_detail,
      "applied_at" => DateTime.to_iso8601(now)
    }
  end

  defp parse_datetime(nil), do: nil

  defp parse_datetime(iso_str) when is_binary(iso_str) do
    case DateTime.from_iso8601(iso_str) do
      {:ok, dt, _} -> dt
      _ -> nil
    end
  end

  defp maybe_repair_watermark(base_dir, validated) do
    case AtomicStore.read_persistent_watermark(base_dir) do
      {:ok, wm} ->
        wm_gen = wm["highest_seen_generation"] || 0
        wm_crl = wm["highest_seen_crl_number"] || 0
        wm_fp = wm["pinned_ca_fingerprint"]
        wm_hash = wm["last_bundle_sha256"]

        is_matching =
          wm_gen == validated.generation and
            wm_crl == validated.crl_number and
            String.downcase(to_string(wm_fp)) ==
              String.downcase(to_string(validated.ca_fingerprint)) and
            String.downcase(to_string(wm_hash)) ==
              String.downcase(to_string(validated.bundle_sha256))

        cond do
          is_matching ->
            :ok

          wm_gen > validated.generation ->
            {:error, :watermark_generation_downgrade}

          wm_gen == validated.generation and wm_hash != nil and
              String.downcase(to_string(wm_hash)) !=
                String.downcase(to_string(validated.bundle_sha256)) ->
            {:error, :watermark_equivocation}

          true ->
            AtomicStore.write_watermark(base_dir, validated)
        end

      {:error, :not_found} ->
        AtomicStore.write_watermark(base_dir, validated)

      {:error, _reason} ->
        AtomicStore.write_watermark(base_dir, validated)
    end
  end
end
