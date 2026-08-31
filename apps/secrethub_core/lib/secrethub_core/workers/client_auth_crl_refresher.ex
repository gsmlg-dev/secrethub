defmodule SecretHub.Core.Workers.ClientAuthCRLRefresher do
  @moduledoc """
  Periodic background worker to refresh Client Auth PKI CRL before it expires.

  Periodically checks the current CRL and, if it is nearing nextUpdate (within 12h)
  or needs refresh, transactionally generates a new signed CRL and publishes
  the updated trust bundle.
  """

  use GenServer
  require Logger

  alias SecretHub.Core.PKI.ClientAuth

  # 6 hours in milliseconds
  @default_interval_ms 6 * 3600 * 1000
  # Add up to 10 minutes jitter
  @max_jitter_ms 600 * 1000

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(opts) do
    interval = Keyword.get(opts, :interval_ms, @default_interval_ms)
    enabled = Keyword.get(opts, :enabled, true)

    if enabled do
      schedule_next_check(interval)
    end

    {:ok, %{interval: interval, enabled: enabled}}
  end

  @impl true
  def handle_info(:check_crl, state) do
    if state.enabled do
      perform_refresh()
      schedule_next_check(state.interval)
    end

    {:noreply, state}
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
        :ok

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

  defp schedule_next_check(interval) do
    jitter = :rand.uniform(@max_jitter_ms)
    Process.send_after(self(), :check_crl, interval + jitter)
  end
end
