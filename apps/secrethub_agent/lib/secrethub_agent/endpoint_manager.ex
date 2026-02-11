defmodule SecretHub.Agent.EndpointManager do
  @moduledoc """
  Manages multiple SecretHub Core endpoints for high availability.

  Provides:
  - Health monitoring for all configured endpoints
  - Automatic failover to healthy endpoints
  - Round-robin load balancing for healthy endpoints
  - Exponential backoff for failed endpoints
  - Connection health tracking

  ## Configuration

      config :secrethub_agent,
        core_endpoints: [
          "wss://secrethub-core-0.secrethub.svc.cluster.local:4000",
          "wss://secrethub-core-1.secrethub.svc.cluster.local:4000",
          "wss://secrethub-core-2.secrethub.svc.cluster.local:4000"
        ],
        endpoint_health_check_interval: 30_000,
        endpoint_failover_threshold: 3

  ## Usage

      # Get next healthy endpoint
      {:ok, endpoint} = EndpointManager.get_next_endpoint()

      # Report connection failure (triggers failover)
      :ok = EndpointManager.report_failure(endpoint)

      # Report successful connection
      :ok = EndpointManager.report_success(endpoint)

      # Get endpoint health status
      health = EndpointManager.get_health_status()
  """

  use GenServer
  require Logger

  @type endpoint :: String.t()
  @type endpoint_status :: %{
          url: endpoint(),
          status: :healthy | :degraded | :unhealthy,
          last_success: DateTime.t() | nil,
          last_failure: DateTime.t() | nil,
          consecutive_failures: non_neg_integer(),
          consecutive_successes: non_neg_integer(),
          backoff_until: DateTime.t() | nil
        }

  defstruct [
    :endpoints,
    :endpoint_status,
    :current_index,
    :health_check_interval,
    :failover_threshold,
    :health_check_timer
  ]

  # 30 seconds
  @default_health_check_interval 30_000
  @default_failover_threshold 3
  # 5 minutes
  @max_backoff_seconds 300
  @initial_backoff_seconds 5

  ## Client API

  @doc """
  Starts the EndpointManager GenServer.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Returns the next healthy endpoint to connect to.

  Uses round-robin selection among healthy endpoints.
  Skips endpoints that are in backoff period.

  Returns `{:ok, endpoint_url}` or `{:error, :no_healthy_endpoints}`.
  """
  @spec get_next_endpoint() :: {:ok, endpoint()} | {:error, :no_healthy_endpoints}
  def get_next_endpoint do
    GenServer.call(__MODULE__, :get_next_endpoint)
  end

  @doc """
  Reports a connection failure for an endpoint.

  Increments failure counter and may trigger backoff.
  """
  @spec report_failure(endpoint()) :: :ok
  def report_failure(endpoint) do
    GenServer.cast(__MODULE__, {:report_failure, endpoint})
  end

  @doc """
  Reports a successful connection to an endpoint.

  Resets failure counter and removes from backoff.
  """
  @spec report_success(endpoint()) :: :ok
  def report_success(endpoint) do
    GenServer.cast(__MODULE__, {:report_success, endpoint})
  end

  @doc """
  Returns health status for all endpoints.
  """
  @spec get_health_status() :: [endpoint_status()]
  def get_health_status do
    GenServer.call(__MODULE__, :get_health_status)
  end

  @doc """
  Manually marks an endpoint as unhealthy.

  Useful for testing or manual intervention.
  """
  @spec mark_unhealthy(endpoint()) :: :ok
  def mark_unhealthy(endpoint) do
    GenServer.cast(__MODULE__, {:mark_unhealthy, endpoint})
  end

  @doc """
  Manually marks an endpoint as healthy.

  Useful for testing or manual intervention.
  """
  @spec mark_healthy(endpoint()) :: :ok
  def mark_healthy(endpoint) do
    GenServer.cast(__MODULE__, {:mark_healthy, endpoint})
  end

  ## GenServer Callbacks

  @impl true
  def init(opts) do
    # Get endpoints from config or options
    endpoints =
      Keyword.get(opts, :core_endpoints) ||
        Application.get_env(:secrethub_agent, :core_endpoints, [])

    if Enum.empty?(endpoints) do
      Logger.error("No Core endpoints configured!")
      {:stop, :no_endpoints_configured}
    else
      health_check_interval =
        Keyword.get(opts, :health_check_interval, @default_health_check_interval)

      failover_threshold = Keyword.get(opts, :failover_threshold, @default_failover_threshold)

      # Initialize status for all endpoints
      endpoint_status =
        Enum.reduce(endpoints, %{}, fn endpoint, acc ->
          Map.put(acc, endpoint, %{
            url: endpoint,
            status: :healthy,
            last_success: nil,
            last_failure: nil,
            consecutive_failures: 0,
            consecutive_successes: 0,
            backoff_until: nil
          })
        end)

      state = %__MODULE__{
        endpoints: endpoints,
        endpoint_status: endpoint_status,
        current_index: 0,
        health_check_interval: health_check_interval,
        failover_threshold: failover_threshold,
        health_check_timer: nil
      }

      # Schedule periodic health check
      timer = schedule_health_check(health_check_interval)

      Logger.info("EndpointManager initialized with #{length(endpoints)} endpoints")

      {:ok, %{state | health_check_timer: timer}}
    end
  end

  @impl true
  def handle_call(:get_next_endpoint, _from, state) do
    case find_next_healthy_endpoint(state) do
      {:ok, endpoint, new_index} ->
        {:reply, {:ok, endpoint}, %{state | current_index: new_index}}

      :error ->
        Logger.error("No healthy endpoints available!")
        {:reply, {:error, :no_healthy_endpoints}, state}
    end
  end

  @impl true
  def handle_call(:get_health_status, _from, state) do
    status_list = Map.values(state.endpoint_status)
    {:reply, status_list, state}
  end

  @impl true
  def handle_cast({:report_failure, endpoint}, state) do
    new_state = update_endpoint_failure(state, endpoint)
    {:noreply, new_state}
  end

  @impl true
  def handle_cast({:report_success, endpoint}, state) do
    new_state = update_endpoint_success(state, endpoint)
    {:noreply, new_state}
  end

  @impl true
  def handle_cast({:mark_unhealthy, endpoint}, state) do
    new_status =
      Map.update!(state.endpoint_status, endpoint, fn status ->
        %{status | status: :unhealthy, consecutive_failures: state.failover_threshold}
      end)

    {:noreply, %{state | endpoint_status: new_status}}
  end

  @impl true
  def handle_cast({:mark_healthy, endpoint}, state) do
    new_status =
      Map.update!(state.endpoint_status, endpoint, fn status ->
        %{
          status
          | status: :healthy,
            consecutive_failures: 0,
            consecutive_successes: 5,
            backoff_until: nil
        }
      end)

    {:noreply, %{state | endpoint_status: new_status}}
  end

  @impl true
  def handle_info(:health_check, state) do
    # Perform health check on all endpoints
    new_state = perform_health_checks(state)

    # Schedule next health check
    timer = schedule_health_check(state.health_check_interval)

    {:noreply, %{new_state | health_check_timer: timer}}
  end

  ## Private Functions

  defp find_next_healthy_endpoint(state) do
    # Try to find a healthy endpoint starting from current_index
    total_endpoints = length(state.endpoints)

    Enum.reduce_while(0..(total_endpoints - 1), :error, fn offset, _acc ->
      index = rem(state.current_index + offset, total_endpoints)
      endpoint = Enum.at(state.endpoints, index)
      status = Map.get(state.endpoint_status, endpoint)

      if endpoint_available?(status) do
        {:halt, {:ok, endpoint, rem(index + 1, total_endpoints)}}
      else
        {:cont, :error}
      end
    end)
  end

  defp endpoint_available?(status) do
    # Check if endpoint is healthy or in backoff period
    cond do
      status.status == :healthy ->
        true

      status.backoff_until && DateTime.compare(DateTime.utc_now(), status.backoff_until) == :gt ->
        true

      true ->
        false
    end
  end

  defp update_endpoint_failure(state, endpoint) do
    new_status =
      Map.update!(state.endpoint_status, endpoint, fn status ->
        consecutive_failures = status.consecutive_failures + 1
        now = DateTime.utc_now()

        # Calculate backoff if threshold exceeded
        {new_status_state, backoff_until} =
          if consecutive_failures >= state.failover_threshold do
            backoff_seconds = calculate_backoff(consecutive_failures)
            backoff_time = DateTime.add(now, backoff_seconds, :second)

            Logger.warning(
              "Endpoint #{endpoint} marked unhealthy (#{consecutive_failures} failures), backoff until #{backoff_time}"
            )

            {:unhealthy, backoff_time}
          else
            {:degraded, nil}
          end

        %{
          status
          | consecutive_failures: consecutive_failures,
            consecutive_successes: 0,
            last_failure: now,
            status: new_status_state,
            backoff_until: backoff_until
        }
      end)

    %{state | endpoint_status: new_status}
  end

  defp update_endpoint_success(state, endpoint) do
    new_status =
      Map.update!(state.endpoint_status, endpoint, fn status ->
        consecutive_successes = status.consecutive_successes + 1

        # Mark healthy after 3 consecutive successes
        new_status_state =
          if consecutive_successes >= 3 do
            Logger.info("Endpoint #{endpoint} marked healthy")
            :healthy
          else
            :degraded
          end

        %{
          status
          | consecutive_successes: consecutive_successes,
            consecutive_failures: 0,
            last_success: DateTime.utc_now(),
            status: new_status_state,
            backoff_until: nil
        }
      end)

    %{state | endpoint_status: new_status}
  end

  defp calculate_backoff(consecutive_failures) do
    # Exponential backoff: 5s, 10s, 20s, 40s, ..., max 300s
    backoff = @initial_backoff_seconds * :math.pow(2, consecutive_failures - 1)
    min(round(backoff), @max_backoff_seconds)
  end

  defp perform_health_checks(state) do
    new_status =
      Enum.reduce(state.endpoint_status, state.endpoint_status, fn {endpoint, status}, acc ->
        maybe_clear_backoff(acc, endpoint, status)
      end)

    %{state | endpoint_status: new_status}
  end

  defp maybe_clear_backoff(acc, endpoint, %{backoff_until: backoff_until} = status)
       when not is_nil(backoff_until) do
    if DateTime.compare(DateTime.utc_now(), backoff_until) == :gt do
      Logger.info("Endpoint #{endpoint} backoff expired, ready for retry")
      Map.put(acc, endpoint, %{status | backoff_until: nil, status: :degraded})
    else
      acc
    end
  end

  defp maybe_clear_backoff(acc, _endpoint, _status), do: acc

  defp schedule_health_check(interval) do
    Process.send_after(self(), :health_check, interval)
  end
end
