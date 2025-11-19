defmodule SecretHub.WebWeb.EngineHealthDashboardLive do
  @moduledoc """
  LiveView for detailed engine health monitoring and analytics.

  Displays:
  - Real-time health status
  - Historical health check data
  - Performance metrics (response times)
  - Uptime statistics
  - Health trends and charts
  """

  use SecretHub.WebWeb, :live_view
  require Logger
  alias SecretHub.Core.EngineConfigurations

  @refresh_interval 10_000
  @default_history_days 7

  @impl true
  def mount(%{"id" => id}, _session, socket) do
    case EngineConfigurations.get_configuration(id) do
      {:ok, config} ->
        if connected?(socket) do
          schedule_refresh()
        end

        socket =
          socket
          |> assign(:config, config)
          |> assign(:time_range, @default_history_days)
          |> assign(:auto_refresh, true)
          |> load_health_data()

        {:ok, socket}

      {:error, :not_found} ->
        socket =
          socket
          |> put_flash(:error, "Engine configuration not found")
          |> push_navigate(to: ~p"/admin/engines")

        {:ok, socket}
    end
  end

  @impl true
  def handle_info(:refresh, socket) do
    if socket.assigns.auto_refresh do
      schedule_refresh()
    end

    {:noreply, load_health_data(socket)}
  end

  @impl true
  def handle_info(:perform_health_check, socket) do
    config = socket.assigns.config

    start_time = System.monotonic_time(:millisecond)

    result =
      case EngineConfigurations.perform_health_check(config) do
        {:ok, status} ->
          response_time = System.monotonic_time(:millisecond) - start_time
          EngineConfigurations.update_health_status(config.id, status)

          EngineConfigurations.record_health_check(config.id, status,
            response_time_ms: response_time
          )

          {:success, "Health check passed: #{status}"}

        {:error, reason} ->
          response_time = System.monotonic_time(:millisecond) - start_time
          EngineConfigurations.update_health_status(config.id, :unhealthy, inspect(reason))

          EngineConfigurations.record_health_check(config.id, :unhealthy,
            response_time_ms: response_time,
            error_message: inspect(reason)
          )

          {:error, "Health check failed: #{inspect(reason)}"}
      end

    socket =
      case result do
        {:success, msg} ->
          socket
          |> put_flash(:info, msg)
          |> assign(:checking, false)
          |> load_health_data()

        {:error, msg} ->
          socket
          |> put_flash(:error, msg)
          |> assign(:checking, false)
          |> load_health_data()
      end

    {:noreply, socket}
  end

  @impl true
  def handle_event("toggle_refresh", _params, socket) do
    new_auto_refresh = !socket.assigns.auto_refresh

    if new_auto_refresh do
      schedule_refresh()
    end

    {:noreply, assign(socket, :auto_refresh, new_auto_refresh)}
  end

  @impl true
  def handle_event("change_time_range", %{"days" => days}, socket) do
    time_range = String.to_integer(days)

    socket =
      socket
      |> assign(:time_range, time_range)
      |> load_health_data()

    {:noreply, socket}
  end

  @impl true
  def handle_event("refresh_now", _params, socket) do
    {:noreply, load_health_data(socket)}
  end

  @impl true
  def handle_event("run_health_check", _params, socket) do
    send(self(), :perform_health_check)
    {:noreply, assign(socket, :checking, true)}
  end

  # Private helpers

  defp schedule_refresh do
    Process.send_after(self(), :refresh, @refresh_interval)
  end

  defp load_health_data(socket) do
    config = socket.assigns.config
    time_range = socket.assigns[:time_range] || @default_history_days

    since = DateTime.add(DateTime.utc_now(), -time_range * 24 * 3600, :second)

    # Reload config for latest health status
    {:ok, fresh_config} = EngineConfigurations.get_configuration(config.id)

    history = EngineConfigurations.get_health_history(config.id, since: since, limit: 200)
    stats = EngineConfigurations.get_health_stats(config.id, since: since)

    socket
    |> assign(:config, fresh_config)
    |> assign(:history, history)
    |> assign(:stats, stats)
    |> assign(:checking, false)
  end

  defp health_status_badge(status, assigns \\ %{}) do
    case status do
      :healthy ->
        ~H"""
        <span class="badge badge-success badge-lg">Healthy</span>
        """

      :degraded ->
        ~H"""
        <span class="badge badge-warning badge-lg">Degraded</span>
        """

      :unhealthy ->
        ~H"""
        <span class="badge badge-error badge-lg">Unhealthy</span>
        """

      :unknown ->
        ~H"""
        <span class="badge badge-ghost badge-lg">Unknown</span>
        """

      _ ->
        assigns = assign(assigns, :status, status)

        ~H"""
        <span class="badge badge-ghost badge-lg">{to_string(@status)}</span>
        """
    end
  end

  defp format_timestamp(nil), do: "Never"

  defp format_timestamp(timestamp) do
    Calendar.strftime(timestamp, "%Y-%m-%d %H:%M:%S UTC")
  end

  defp format_relative_time(timestamp) do
    diff = DateTime.diff(DateTime.utc_now(), timestamp, :second)

    cond do
      diff < 60 -> "#{diff}s ago"
      diff < 3600 -> "#{div(diff, 60)}m ago"
      diff < 86400 -> "#{div(diff, 3600)}h ago"
      true -> "#{div(diff, 86400)}d ago"
    end
  end

  defp status_dot_color(status) do
    case status do
      :healthy -> "bg-green-500"
      :degraded -> "bg-yellow-500"
      :unhealthy -> "bg-red-500"
      _ -> "bg-gray-400"
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="container mx-auto p-6">
      <div class="flex justify-between items-center mb-6">
        <div>
          <div class="flex items-center gap-3">
            <h1 class="text-3xl font-bold">{@config.name}</h1>
            {health_status_badge(@config.health_status)}
          </div>
          <p class="text-gray-600 mt-1">{@config.description || "No description"}</p>
        </div>

        <div class="flex gap-2">
          <.link navigate={~p"/admin/engines"} class="btn btn-outline">
            Back to Engines
          </.link>

          <button
            phx-click="toggle_refresh"
            class={"btn btn-outline #{if @auto_refresh, do: "btn-active", else: ""}"}
          >
            {if @auto_refresh, do: "Auto-refresh ON", else: "Auto-refresh OFF"}
          </button>

          <button phx-click="refresh_now" class="btn btn-secondary">
            Refresh
          </button>

          <button
            phx-click="run_health_check"
            class="btn btn-primary"
            disabled={@checking}
          >
            {if @checking, do: "Checking...", else: "Run Check Now"}
          </button>
        </div>
      </div>
      
    <!-- Current Status Card -->
      <div class="card bg-base-100 shadow-xl mb-6">
        <div class="card-body">
          <h2 class="card-title">Current Status</h2>

          <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mt-4">
            <div>
              <div class="text-sm text-gray-600">Status</div>
              <div class="text-lg font-semibold">{health_status_badge(@config.health_status)}</div>
            </div>

            <div>
              <div class="text-sm text-gray-600">Last Check</div>
              <div class="text-lg font-semibold">
                <%= if @config.last_health_check_at do %>
                  {format_relative_time(@config.last_health_check_at)}
                <% else %>
                  Never
                <% end %>
              </div>
            </div>

            <div>
              <div class="text-sm text-gray-600">Engine Type</div>
              <div class="text-lg font-semibold capitalize">{to_string(@config.engine_type)}</div>
            </div>

            <div>
              <div class="text-sm text-gray-600">State</div>
              <div class="text-lg font-semibold">
                <%= if @config.enabled do %>
                  <span class="badge badge-success">Enabled</span>
                <% else %>
                  <span class="badge badge-ghost">Disabled</span>
                <% end %>
              </div>
            </div>
          </div>

          <%= if @config.health_message do %>
            <div class="alert alert-warning mt-4">
              <span>{@config.health_message}</span>
            </div>
          <% end %>
        </div>
      </div>
      
    <!-- Statistics Cards -->
      <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <div class="stat bg-base-100 shadow rounded-lg">
          <div class="stat-title">Total Checks</div>
          <div class="stat-value text-3xl">{@stats.total_checks}</div>
          <div class="stat-desc">Last {@time_range} days</div>
        </div>

        <div class="stat bg-base-100 shadow rounded-lg">
          <div class="stat-title">Uptime</div>
          <div class="stat-value text-3xl text-green-600">{@stats.uptime_percentage}%</div>
          <div class="stat-desc">{@stats.healthy_count} healthy checks</div>
        </div>

        <div class="stat bg-base-100 shadow rounded-lg">
          <div class="stat-title">Failures</div>
          <div class="stat-value text-3xl text-red-600">{@stats.unhealthy_count}</div>
          <div class="stat-desc">Failed health checks</div>
        </div>

        <div class="stat bg-base-100 shadow rounded-lg">
          <div class="stat-title">Avg Response</div>
          <div class="stat-value text-3xl">
            <%= if @stats.avg_response_time do %>
              {@stats.avg_response_time}ms
            <% else %>
              -
            <% end %>
          </div>
          <div class="stat-desc">Response time</div>
        </div>
      </div>
      
    <!-- Time Range Selector -->
      <div class="mb-6 flex items-center gap-4">
        <label class="text-sm font-medium">Time Range:</label>
        <div class="join">
          <button
            phx-click="change_time_range"
            phx-value-days="1"
            class={"btn btn-sm join-item #{if @time_range == 1, do: "btn-active", else: ""}"}
          >
            24h
          </button>
          <button
            phx-click="change_time_range"
            phx-value-days="7"
            class={"btn btn-sm join-item #{if @time_range == 7, do: "btn-active", else: ""}"}
          >
            7d
          </button>
          <button
            phx-click="change_time_range"
            phx-value-days="30"
            class={"btn btn-sm join-item #{if @time_range == 30, do: "btn-active", else: ""}"}
          >
            30d
          </button>
        </div>
      </div>
      
    <!-- Health History -->
      <div class="card bg-base-100 shadow-xl">
        <div class="card-body">
          <h2 class="card-title">Health Check History</h2>

          <%= if Enum.any?(@history) do %>
            <div class="overflow-x-auto mt-4">
              <table class="table table-zebra table-sm">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Status</th>
                    <th>Response Time</th>
                    <th>Error Message</th>
                  </tr>
                </thead>
                <tbody>
                  <%= for check <- @history do %>
                    <tr>
                      <td>
                        <div class="flex items-center gap-2">
                          <div class={"w-2 h-2 rounded-full #{status_dot_color(check.status)}"}></div>
                          <span class="text-sm">{format_timestamp(check.checked_at)}</span>
                          <span class="text-xs text-gray-500">
                            ({format_relative_time(check.checked_at)})
                          </span>
                        </div>
                      </td>
                      <td>
                        {health_status_badge(check.status)}
                      </td>
                      <td>
                        <%= if check.response_time_ms do %>
                          <span class={
                            if check.response_time_ms < 100,
                              do: "text-green-600",
                              else:
                                if(check.response_time_ms < 500,
                                  do: "text-yellow-600",
                                  else: "text-red-600"
                                )
                          }>
                            {check.response_time_ms}ms
                          </span>
                        <% else %>
                          -
                        <% end %>
                      </td>
                      <td>
                        <%= if check.error_message do %>
                          <span class="text-sm text-error">{check.error_message}</span>
                        <% else %>
                          -
                        <% end %>
                      </td>
                    </tr>
                  <% end %>
                </tbody>
              </table>
            </div>
          <% else %>
            <div class="alert alert-info mt-4">
              <span>No health check history available for the selected time range.</span>
            </div>
          <% end %>
        </div>
      </div>
    </div>
    """
  end
end
