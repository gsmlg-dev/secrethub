defmodule SecretHub.Agent.LeaseRenewer do
  @moduledoc """
  Automatically renews dynamic secret leases before expiry.

  The LeaseRenewer monitors active leases and proactively renews them
  before they expire, ensuring continuous access to dynamic credentials.

  ## Renewal Strategy

  - Leases are renewed when TTL drops below 33% (e.g., at 20 min for 1-hour lease)
  - Uses exponential backoff on renewal failures (1s, 2s, 4s, 8s, max 60s)
  - Retries up to 5 times before giving up
  - Failed leases trigger callbacks for application handling

  ## Callbacks

  The renewer supports callbacks for renewal events:
  - `:on_renewed` - Called when a lease is successfully renewed
  - `:on_failed` - Called when all renewal attempts fail
  - `:on_expiring_soon` - Called when a lease is about to expire (< 5 min)

  ## State Management

  Tracks leases in memory with renewal status:
  - `:active` - Lease is valid, not yet time to renew
  - `:renewing` - Renewal in progress
  - `:failed` - Renewal failed, will retry
  - `:expired` - Lease expired, no longer tracked

  ## Example

      # Start the renewer
      {:ok, pid} = LeaseRenewer.start_link(
        core_url: "https://secrethub-core:4000",
        callbacks: %{
          on_renewed: &MyApp.handle_renewed/1,
          on_failed: &MyApp.handle_failed/1
        }
      )

      # Add a lease to track
      LeaseRenewer.track_lease(lease_id, %{
        lease_duration: 3600,
        secret_path: "database/readonly",
        credentials: %{...}
      })

      # Check renewal status
      {:ok, status} = LeaseRenewer.get_lease_status(lease_id)
  """

  use GenServer

  require Logger

  @check_interval :timer.seconds(10)
  @renewal_threshold 0.33
  @max_retries 5
  @base_backoff :timer.seconds(1)
  @max_backoff :timer.seconds(60)

  defmodule Lease do
    @moduledoc false
    defstruct [
      :id,
      :secret_path,
      :credentials,
      :lease_duration,
      :expires_at,
      :status,
      :retry_count,
      :next_retry_at,
      :metadata
    ]
  end

  defmodule State do
    @moduledoc false
    defstruct [
      # Map of lease_id => %Lease{}
      :leases,
      # Core server URL
      :core_url,
      # Callback functions
      :callbacks,
      # Timer ref
      :check_timer
    ]
  end

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Track a new lease for automatic renewal.

  ## Parameters

  - `lease_id`: Unique identifier for the lease
  - `lease_data`: Map containing:
    - `:lease_duration` - TTL in seconds
    - `:secret_path` - Path to the secret
    - `:credentials` - Credential data (optional)
    - `:metadata` - Additional metadata (optional)
  """
  def track_lease(lease_id, lease_data) do
    GenServer.cast(__MODULE__, {:track_lease, lease_id, lease_data})
  end

  @doc """
  Stop tracking a lease (e.g., when manually revoked or no longer needed).
  """
  def untrack_lease(lease_id) do
    GenServer.cast(__MODULE__, {:untrack_lease, lease_id})
  end

  @doc """
  Get the current status of a tracked lease.

  Returns `{:ok, status}` or `{:error, :not_found}`.

  Status map contains:
  - `:status` - Current state (:active, :renewing, :failed, :expired)
  - `:expires_at` - Expiration timestamp
  - `:retry_count` - Number of failed renewal attempts
  """
  def get_lease_status(lease_id) do
    GenServer.call(__MODULE__, {:get_status, lease_id})
  end

  @doc """
  List all currently tracked leases.
  """
  def list_leases do
    GenServer.call(__MODULE__, :list_leases)
  end

  @doc """
  Get statistics about lease renewals.

  Returns map with:
  - `:total_leases` - Number of tracked leases
  - `:active` - Leases in good standing
  - `:renewing` - Leases currently being renewed
  - `:failed` - Leases with failed renewals
  - `:expiring_soon` - Leases expiring in next 5 minutes
  """
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  # Server Callbacks

  @impl true
  def init(opts) do
    core_url = Keyword.fetch!(opts, :core_url)
    callbacks = Keyword.get(opts, :callbacks, %{})

    check_timer = schedule_check()

    state = %State{
      leases: %{},
      core_url: core_url,
      callbacks: callbacks,
      check_timer: check_timer
    }

    Logger.info("LeaseRenewer started", core_url: core_url)

    {:ok, state}
  end

  @impl true
  def handle_cast({:track_lease, lease_id, lease_data}, state) do
    lease_duration = lease_data[:lease_duration] || lease_data["lease_duration"]
    expires_at = DateTime.add(DateTime.utc_now(), lease_duration, :second)

    lease = %Lease{
      id: lease_id,
      secret_path: lease_data[:secret_path] || lease_data["secret_path"],
      credentials: lease_data[:credentials] || lease_data["credentials"],
      lease_duration: lease_duration,
      expires_at: expires_at,
      status: :active,
      retry_count: 0,
      next_retry_at: nil,
      metadata: lease_data[:metadata] || lease_data["metadata"] || %{}
    }

    new_leases = Map.put(state.leases, lease_id, lease)

    Logger.info("Tracking lease",
      lease_id: lease_id,
      secret_path: lease.secret_path,
      expires_at: expires_at
    )

    {:noreply, %{state | leases: new_leases}}
  end

  @impl true
  def handle_cast({:untrack_lease, lease_id}, state) do
    new_leases = Map.delete(state.leases, lease_id)

    Logger.info("Stopped tracking lease", lease_id: lease_id)

    {:noreply, %{state | leases: new_leases}}
  end

  @impl true
  def handle_call({:get_status, lease_id}, _from, state) do
    case Map.get(state.leases, lease_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      lease ->
        status = %{
          status: lease.status,
          expires_at: lease.expires_at,
          retry_count: lease.retry_count,
          secret_path: lease.secret_path
        }

        {:reply, {:ok, status}, state}
    end
  end

  @impl true
  def handle_call(:list_leases, _from, state) do
    leases =
      state.leases
      |> Map.values()
      |> Enum.map(fn lease ->
        %{
          id: lease.id,
          secret_path: lease.secret_path,
          status: lease.status,
          expires_at: lease.expires_at,
          retry_count: lease.retry_count
        }
      end)

    {:reply, leases, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    now = DateTime.utc_now()
    five_min_from_now = DateTime.add(now, 300, :second)

    stats = %{
      total_leases: map_size(state.leases),
      active: count_by_status(state.leases, :active),
      renewing: count_by_status(state.leases, :renewing),
      failed: count_by_status(state.leases, :failed),
      expiring_soon:
        state.leases
        |> Map.values()
        |> Enum.count(fn lease ->
          DateTime.compare(lease.expires_at, five_min_from_now) == :lt
        end)
    }

    {:reply, stats, state}
  end

  @impl true
  def handle_info(:check_renewals, state) do
    now = DateTime.utc_now()

    # Process each lease
    new_leases =
      Enum.reduce(state.leases, state.leases, fn {lease_id, lease}, acc ->
        cond do
          # Lease has expired - remove it
          DateTime.compare(lease.expires_at, now) == :lt ->
            Logger.warning("Lease expired", lease_id: lease_id)
            invoke_callback(state.callbacks, :on_expired, lease)
            Map.delete(acc, lease_id)

          # Lease is expiring soon (< 5 min) - trigger warning callback
          DateTime.diff(lease.expires_at, now) < 300 and lease.status != :renewing ->
            Logger.warning("Lease expiring soon",
              lease_id: lease_id,
              remaining: DateTime.diff(lease.expires_at, now)
            )

            invoke_callback(state.callbacks, :on_expiring_soon, lease)
            acc

          # Lease needs renewal (< 33% TTL remaining)
          should_renew?(lease, now) ->
            Logger.info("Initiating lease renewal", lease_id: lease_id)
            send(self(), {:renew_lease, lease_id})
            Map.put(acc, lease_id, %{lease | status: :renewing})

          # Lease failed previously, check if it's time to retry
          lease.status == :failed and should_retry?(lease, now) ->
            Logger.info("Retrying lease renewal",
              lease_id: lease_id,
              retry: lease.retry_count + 1
            )

            send(self(), {:renew_lease, lease_id})
            Map.put(acc, lease_id, %{lease | status: :renewing})

          # Lease is fine, no action needed
          true ->
            acc
        end
      end)

    check_timer = schedule_check()

    {:noreply, %{state | leases: new_leases, check_timer: check_timer}}
  end

  @impl true
  def handle_info({:renew_lease, lease_id}, state) do
    case Map.get(state.leases, lease_id) do
      nil ->
        {:noreply, state}

      lease ->
        case perform_renewal(state.core_url, lease) do
          {:ok, new_lease_duration} ->
            # Renewal successful
            new_expires_at = DateTime.add(DateTime.utc_now(), new_lease_duration, :second)

            updated_lease = %{
              lease
              | expires_at: new_expires_at,
                lease_duration: new_lease_duration,
                status: :active,
                retry_count: 0,
                next_retry_at: nil
            }

            Logger.info("Lease renewed successfully",
              lease_id: lease_id,
              new_ttl: new_lease_duration
            )

            invoke_callback(state.callbacks, :on_renewed, updated_lease)

            new_leases = Map.put(state.leases, lease_id, updated_lease)
            {:noreply, %{state | leases: new_leases}}

          {:error, reason} ->
            # Renewal failed
            retry_count = lease.retry_count + 1

            if retry_count >= @max_retries do
              Logger.error("Lease renewal failed permanently",
                lease_id: lease_id,
                retries: retry_count,
                error: inspect(reason)
              )

              invoke_callback(state.callbacks, :on_failed, lease)

              # Remove from tracking
              new_leases = Map.delete(state.leases, lease_id)
              {:noreply, %{state | leases: new_leases}}
            else
              # Schedule retry with exponential backoff
              backoff = calculate_backoff(retry_count)
              next_retry_at = DateTime.add(DateTime.utc_now(), backoff, :millisecond)

              updated_lease = %{
                lease
                | status: :failed,
                  retry_count: retry_count,
                  next_retry_at: next_retry_at
              }

              Logger.warning("Lease renewal failed, will retry",
                lease_id: lease_id,
                retry: retry_count,
                backoff_ms: backoff,
                error: inspect(reason)
              )

              new_leases = Map.put(state.leases, lease_id, updated_lease)
              {:noreply, %{state | leases: new_leases}}
            end
        end
    end
  end

  # Private Functions

  defp schedule_check do
    Process.send_after(self(), :check_renewals, @check_interval)
  end

  defp should_renew?(lease, now) do
    lease.status == :active and
      DateTime.diff(lease.expires_at, now) < lease.lease_duration * @renewal_threshold
  end

  defp should_retry?(lease, now) do
    lease.next_retry_at != nil and DateTime.compare(now, lease.next_retry_at) != :lt
  end

  defp perform_renewal(core_url, lease) do
    # Call Core API to renew the lease
    url = "#{core_url}/v1/sys/leases/renew"

    body =
      Jason.encode!(%{
        lease_id: lease.id,
        increment: lease.lease_duration
      })

    headers = [
      {"Content-Type", "application/json"},
      {"Accept", "application/json"}
    ]

    case HTTPoison.post(url, body, headers, recv_timeout: 5000) do
      {:ok, %{status_code: 200, body: response_body}} ->
        case Jason.decode(response_body) do
          {:ok, %{"lease_duration" => duration}} ->
            {:ok, duration}

          {:error, reason} ->
            {:error, {:decode_error, reason}}
        end

      {:ok, %{status_code: status_code, body: body}} ->
        {:error, {:http_error, status_code, body}}

      {:error, %HTTPoison.Error{reason: reason}} ->
        {:error, {:request_failed, reason}}
    end
  end

  defp calculate_backoff(retry_count) do
    # Exponential backoff: 1s, 2s, 4s, 8s, 16s, 32s, 60s (max)
    backoff = @base_backoff * :math.pow(2, retry_count - 1)
    min(round(backoff), @max_backoff)
  end

  defp count_by_status(leases, status) do
    leases
    |> Map.values()
    |> Enum.count(fn lease -> lease.status == status end)
  end

  defp invoke_callback(callbacks, event, lease) do
    case Map.get(callbacks, event) do
      nil ->
        :ok

      callback when is_function(callback, 1) ->
        try do
          callback.(lease)
        rescue
          error ->
            Logger.error("Callback error",
              event: event,
              error: inspect(error)
            )
        end
    end
  end
end
