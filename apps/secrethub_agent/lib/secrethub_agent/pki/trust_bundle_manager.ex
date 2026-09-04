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
    last_error_code: nil,
    last_error_detail: nil,
    # Timers
    sync_timer: nil,
    retry_timer: nil,
    retry_attempt: 0
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

        {{:error, :not_found}, {:ok, validated}} ->
          # No watermark yet, but valid disk exists — persist watermark
          case AtomicStore.write_watermark(base_dir, validated) do
            :ok ->
              %__MODULE__{
                state_dir: state_dir,
                base_dir: base_dir,
                agent_id: agent_id,
                connection_mod: conn_mod,
                lkg_generation: validated.generation,
                lkg_crl_number: validated.crl_number,
                lkg_ca_fingerprint: validated.ca_fingerprint,
                lkg_bundle_sha256: validated.bundle_sha256,
                installed_generation: validated.generation,
                installed_crl_number: validated.crl_number,
                installed_ca_fingerprint: validated.ca_fingerprint,
                installed_bundle_sha256: validated.bundle_sha256,
                last_applied_at: parse_datetime(validated.this_update),
                needs_repair: false,
                status: "applied"
              }

            {:error, reason} ->
              Logger.error("Failed to write initial watermark: #{inspect(reason)}")

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
                status: "error",
                last_error_code: :watermark_persistence_failed,
                last_error_detail: inspect(reason)
              }
          end

        {{:error, :not_found}, _} ->
          %__MODULE__{
            state_dir: state_dir,
            base_dir: base_dir,
            agent_id: agent_id,
            connection_mod: conn_mod,
            needs_repair: true,
            status: "initializing"
          }

        {{:error, wm_err}, _} ->
          # Watermark is invalid JSON or unreadable -> fail closed / mark error
          %__MODULE__{
            state_dir: state_dir,
            base_dir: base_dir,
            agent_id: agent_id,
            connection_mod: conn_mod,
            needs_repair: true,
            status: "error",
            last_error_code: :corrupted_watermark,
            last_error_detail: inspect(wm_err)
          }
      end

    timer = schedule_periodic_sync()
    {:ok, %{state | sync_timer: timer}}
  end

  @doc """
  Processes a trust bundle map from Core (validates and writes atomically).
  Returns `{:ok, receipt}` or `{:error, error_code, receipt}`.
  """
  @spec process_bundle(pid() | module(), map(), keyword()) ::
          {:ok, map()}
          | {:error, atom(), map()}
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

  def handle_info(_msg, state), do: {:noreply, state}

  # Core Bundle Application & Verification

  defp apply_bundle(state, bundle, opts) do
    now = Keyword.get(opts, :now, DateTime.utc_now() |> DateTime.truncate(:second))
    force = Keyword.get(opts, :force, false)
    val_opts = Keyword.put_new(opts, :pinned_ca_fingerprint, state.lkg_ca_fingerprint)

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
                last_error_code: nil,
                last_error_detail: nil,
                retry_attempt: 0
            }

            receipt = build_receipt(new_state, "applied", now)
            submit_receipt_async(new_state, receipt)
            {:ok, receipt, new_state}

          {:error, reason} ->
            Logger.error(
              "Failed to repair watermark during bundle validation: #{inspect(reason)}"
            )

            new_state = %{
              state
              | needs_repair: true,
                status: "error",
                last_error_code: :watermark_repair_failed,
                last_error_detail: inspect(reason)
            }

            receipt =
              build_error_receipt(
                new_state,
                %{
                  "generation" => validated.generation,
                  "crl_number" => validated.crl_number,
                  "bundle_sha256" => validated.bundle_sha256
                },
                :watermark_repair_failed,
                inspect(reason),
                now
              )

            submit_receipt_async(new_state, receipt)
            {:error, :watermark_repair_failed, new_state}
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
                retry_attempt: 0
            }

            receipt = build_receipt(new_state, "applied", now)
            submit_receipt_async(new_state, receipt)

            Logger.info("Client Auth trust bundle updated to generation #{validated.generation}")

            {:ok, receipt, new_state}

          {:error, reason} ->
            error_code = :atomic_write_failed
            error_detail = inspect(reason)

            new_state = %{
              state
              | last_error_code: to_string(error_code),
                last_error_detail: error_detail,
                status: "failed"
            }

            receipt = build_error_receipt(new_state, bundle, error_code, error_detail, now)
            submit_receipt_async(new_state, receipt)
            {:error, error_code, receipt, new_state}
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

        receipt = build_error_receipt(new_state, bundle, error_code, detail, now)
        submit_receipt_async(new_state, receipt)
        Logger.error("Client Auth trust bundle rejected: #{error_code} - #{detail}")
        {:error, error_code, receipt, new_state}
    end
  end

  defp check_monotonicity_and_invariants(state, validated, _force) do
    if state.lkg_generation > 0 do
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
    else
      :ok
    end
  end

  # Pull from Core and Apply

  defp do_sync(state, opts) do
    case pull_bundle_from_core(state) do
      {:ok, bundle} ->
        case apply_bundle(state, bundle, opts) do
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

  defp submit_receipt_async(state, receipt) do
    conn_mod = state.connection_mod || SecretHub.Agent.Connection

    if Process.whereis(conn_mod) do
      Task.start(fn ->
        try do
          conn_mod.submit_bundle_receipt(receipt)
        catch
          _, _ -> :ok
        end
      end)
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

        if wm_gen < validated.generation do
          AtomicStore.write_watermark(base_dir, validated)
        else
          :ok
        end

      {:error, :not_found} ->
        AtomicStore.write_watermark(base_dir, validated)

      _ ->
        :ok
    end
  end
end
