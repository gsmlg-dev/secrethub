defmodule SecretHub.Core.Workers.ClientAuthCRLRefresher do
  @moduledoc """
  Periodic background worker to refresh Client Auth PKI CRL before it expires.

  Periodically checks the current CRL and, if it is nearing nextUpdate (within 12h)
  or needs refresh, transactionally generates a new signed CRL and publishes
  the updated trust bundle.

  In the refresh window, transient failures use bounded exponential retry backoff.
  Unseal events trigger immediate reconciliation.
  """

  use GenServer
  import Ecto.Query
  require Logger

  alias SecretHub.Core.PKI.ClientAuth
  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.{ClientAuthAuthority, ClientAuthCrl}

  # 6 hours in milliseconds
  @default_interval_ms 6 * 3600 * 1000
  # Refresh-ahead window in seconds (12 hours)
  @refresh_ahead_seconds 12 * 3600
  # Add up to 10 minutes jitter for normal interval
  @max_jitter_ms 600 * 1000

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(opts) do
    interval = Keyword.get(opts, :interval_ms, @default_interval_ms)
    enabled = Keyword.get(opts, :enabled, true)

    if enabled do
      attach_telemetry_handler()
      send(self(), :reconcile_startup)
    end

    {:ok, %{interval: interval, enabled: enabled, retry_attempt: 0, timer: nil}}
  end

  @impl true
  def terminate(_reason, _state) do
    detach_telemetry_handler()
    :ok
  end

  @doc """
  Triggers immediate reconciliation of the CRL.
  """
  def reconcile_now do
    send(__MODULE__, :reconcile_now)
    :ok
  end

  @impl true
  def handle_info(:vault_unsealed, state) do
    Logger.info(
      "ClientAuthCRLRefresher: Vault unsealed event received; triggering immediate reconciliation"
    )

    handle_info(:reconcile_now, state)
  end

  @impl true
  def handle_info(:reconcile_now, state) do
    if state.enabled do
      cancel_timer(state.timer)
      new_state = do_reconcile(%{state | retry_attempt: 0})
      {:noreply, new_state}
    else
      {:noreply, state}
    end
  end

  @impl true
  def handle_info(:reconcile_startup, state) do
    if state.enabled do
      cancel_timer(state.timer)
      new_state = do_reconcile(state)
      {:noreply, new_state}
    else
      {:noreply, state}
    end
  end

  @impl true
  def handle_info(:check_crl, state) do
    if state.enabled do
      cancel_timer(state.timer)
      new_state = do_reconcile(state)
      {:noreply, new_state}
    else
      {:noreply, state}
    end
  end

  def handle_info(_msg, state), do: {:noreply, state}

  @doc """
  Performs an immediate CRL check and refresh if needed.
  """
  def perform_refresh do
    case ClientAuth.refresh_if_needed() do
      {:ok, :not_modified} ->
        Logger.debug("Client Auth CRL is up to date")
        :ok

      {:ok, %{generation: gen, crl_number: crl_num}} ->
        Logger.info("Client Auth CRL refreshed to generation #{gen}, crl_number #{crl_num}")
        :ok

      {:error, :authority_not_initialized} ->
        Logger.debug("Client Auth CA not initialized; skipping CRL refresh")
        {:error, :authority_not_initialized}

      {:error, :vault_sealed} ->
        Logger.warning("Vault is sealed; cannot refresh Client Auth CRL")
        {:error, :vault_sealed}

      {:error, reason} ->
        Logger.error("Client Auth CRL refresh failed: #{inspect(reason)}")
        {:error, reason}
    end
  rescue
    e ->
      Logger.error("Exception during Client Auth CRL refresh: #{Exception.message(e)}")
      {:error, e}
  end

  defp do_reconcile(state) do
    case get_current_crl_next_update() do
      {:ok, next_update} ->
        now = DateTime.utc_now()
        remaining_secs = DateTime.diff(next_update, now, :second)
        in_refresh_window = remaining_secs <= @refresh_ahead_seconds

        if in_refresh_window do
          case perform_refresh() do
            :ok ->
              # Refresh succeeded. Re-check next_update to schedule following check
              schedule_after_refresh_success(state)

            {:error, reason} ->
              # In refresh window and refresh failed: bounded exponential retry
              schedule_refresh_retry(state, reason)
          end
        else
          # Outside refresh window: schedule next check at (remaining - window) or interval
          delay_secs =
            max(60, min(div(state.interval, 1000), remaining_secs - @refresh_ahead_seconds))

          timer = schedule_next_check(delay_secs * 1000)
          %{state | retry_attempt: 0, timer: timer}
        end

      {:error, :authority_not_initialized} ->
        timer = schedule_next_check(state.interval)
        %{state | retry_attempt: 0, timer: timer}

      {:error, _reason} ->
        attempt = state.retry_attempt + 1
        backoff_ms = min(60_000, 5_000 * trunc(:math.pow(2, min(attempt, 4))))
        timer = Process.send_after(self(), :check_crl, backoff_ms)
        %{state | retry_attempt: attempt, timer: timer}
    end
  end

  defp schedule_after_refresh_success(state) do
    case get_current_crl_next_update() do
      {:ok, next_update} ->
        now = DateTime.utc_now()
        remaining_secs = DateTime.diff(next_update, now, :second)

        delay_secs =
          max(60, min(div(state.interval, 1000), remaining_secs - @refresh_ahead_seconds))

        timer = schedule_next_check(delay_secs * 1000)
        %{state | retry_attempt: 0, timer: timer}

      _ ->
        timer = schedule_next_check(state.interval)
        %{state | retry_attempt: 0, timer: timer}
    end
  end

  defp schedule_refresh_retry(state, reason) do
    attempt = state.retry_attempt + 1
    backoff_ms = min(60_000, 5_000 * trunc(:math.pow(2, min(attempt, 4))))

    Logger.warning(
      "Client Auth CRL refresh failed in refresh window (#{inspect(reason)}); retrying in #{div(backoff_ms, 1000)}s (attempt #{attempt})"
    )

    timer = Process.send_after(self(), :check_crl, backoff_ms)
    %{state | retry_attempt: attempt, timer: timer}
  end

  defp get_current_crl_next_update do
    case Repo.one(
           from(a in ClientAuthAuthority,
             where: a.slug == "client-auth" and a.status == "active",
             preload: [:current_crl]
           )
         ) do
      %ClientAuthAuthority{current_crl: %ClientAuthCrl{next_update: next_update}}
      when not is_nil(next_update) ->
        {:ok, next_update}

      %ClientAuthAuthority{current_crl: nil} ->
        {:error, :no_crl}

      nil ->
        {:error, :authority_not_initialized}
    end
  rescue
    e -> {:error, e}
  end

  defp cancel_timer(nil), do: :ok

  defp cancel_timer(timer) do
    Process.cancel_timer(timer)
    :ok
  end

  defp schedule_next_check(interval) do
    jitter = :rand.uniform(min(@max_jitter_ms, max(1_000, div(interval, 10))))
    Process.send_after(self(), :check_crl, interval + jitter)
  end

  defp attach_telemetry_handler do
    pid = self()
    handler_id = "client-auth-crl-refresher-#{inspect(pid)}"

    :telemetry.attach(
      handler_id,
      [:secrethub, :vault, :unsealed],
      fn _event, _measurements, _metadata, _config ->
        send(pid, :vault_unsealed)
      end,
      nil
    )
  end

  defp detach_telemetry_handler do
    handler_id = "client-auth-crl-refresher-#{inspect(self())}"
    :telemetry.detach(handler_id)
  rescue
    _ -> :ok
  end
end
