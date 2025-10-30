defmodule SecretHub.WebWeb.NodeHealthLive do
  @moduledoc """
  LiveView for detailed node health monitoring.

  Displays:
  - Real-time health metrics for a specific node
  - CPU, memory, database latency
  - Historical health data with time-series visualization
  - Recent alerts for this node
  """

  use SecretHub.WebWeb, :live_view
  require Logger
  alias SecretHub.Core.{ClusterState, HealthAlerts}

  @refresh_interval 5_000

  @impl true
  def mount(%{"node_id" => node_id}, _session, socket) do
    if connected?(socket) do
      schedule_refresh()
    end

    socket =
      socket
      |> assign(:node_id, node_id)
      |> assign(:loading, true)
      |> assign(:auto_refresh, true)
      |> assign(:time_range, "1h")
      |> load_node_data()

    {:ok, socket}
  end

  @impl true
  def handle_info(:refresh, socket) do
    if socket.assigns.auto_refresh do
      schedule_refresh()
    end

    {:noreply, load_node_data(socket)}
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
  def handle_event("refresh_now", _params, socket) do
    {:noreply, load_node_data(socket)}
  end

  @impl true
  def handle_event("change_time_range", %{"range" => range}, socket) do
    socket =
      socket
      |> assign(:time_range, range)
      |> load_node_data()

    {:noreply, socket}
  end

  # Private helpers

  defp schedule_refresh do
    Process.send_after(self(), :refresh, @refresh_interval)
  end

  defp load_node_data(socket) do
    node_id = socket.assigns.node_id
    time_range = socket.assigns[:time_range] || "1h"

    # Get current health
    current_health =
      case ClusterState.get_node_current_health(node_id) do
        {:ok, metric} -> metric
        {:error, _} -> nil
      end

    # Get health history
    hours = parse_time_range(time_range)

    health_history =
      case ClusterState.get_node_health_history(node_id, hours) do
        {:ok, metrics} -> metrics
        {:error, _} -> []
      end

    # Get recent triggered alerts
    recent_alerts = get_recent_alerts_for_node(node_id)

    socket
    |> assign(:loading, false)
    |> assign(:current_health, current_health)
    |> assign(:health_history, health_history)
    |> assign(:recent_alerts, recent_alerts)
    |> assign(:error, nil)
  rescue
    e ->
      Logger.error("Failed to load node health data: #{Exception.message(e)}")

      socket
      |> assign(:loading, false)
      |> assign(:error, "Failed to load node health data")
  end

  defp parse_time_range("1h"), do: 1
  defp parse_time_range("6h"), do: 6
  defp parse_time_range("24h"), do: 24
  defp parse_time_range(_), do: 1

  defp get_recent_alerts_for_node(_node_id) do
    # TODO: Filter alerts by node_id when alert history is implemented
    []
  end

  defp format_percentage(nil), do: "N/A"
  defp format_percentage(value), do: "#{Float.round(value, 1)}%"

  defp format_latency(nil), do: "N/A"
  defp format_latency(value), do: "#{Float.round(value, 2)}ms"

  defp format_timestamp(nil), do: "N/A"

  defp format_timestamp(datetime) do
    Calendar.strftime(datetime, "%Y-%m-%d %H:%M:%S UTC")
  end

  defp health_status_badge(nil), do: health_status_badge("unknown")

  defp health_status_badge(status) when is_binary(status) do
    case status do
      "healthy" ->
        ~H"""
        <span class="badge badge-success">Healthy</span>
        """

      "degraded" ->
        ~H"""
        <span class="badge badge-warning">Degraded</span>
        """

      "unhealthy" ->
        ~H"""
        <span class="badge badge-error">Unhealthy</span>
        """

      _ ->
        ~H"""
        <span class="badge badge-ghost">Unknown</span>
        """
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="container mx-auto p-6">
      <div class="flex justify-between items-center mb-6">
        <div>
          <h1 class="text-3xl font-bold">Node Health: {@node_id}</h1>
          <p class="text-gray-600 mt-1">Detailed health monitoring and metrics</p>
        </div>

        <div class="flex gap-2">
          <.link navigate={~p"/admin/cluster"} class="btn btn-outline">
            <svg
              xmlns="http://www.w3.org/2000/svg"
              class="h-5 w-5"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path
                stroke-linecap="round"
                stroke-linejoin="round"
                stroke-width="2"
                d="M10 19l-7-7m0 0l7-7m-7 7h18"
              />
            </svg>
            Back to Cluster
          </.link>

          <button
            phx-click="toggle_refresh"
            class={"btn btn-outline #{if @auto_refresh, do: "btn-active", else: ""}"}
          >
            {if @auto_refresh, do: "Auto-refresh ON", else: "Auto-refresh OFF"}
          </button>

          <button phx-click="refresh_now" class="btn btn-primary">
            Refresh Now
          </button>
        </div>
      </div>

      <%= if @error do %>
        <div class="alert alert-error mb-6">
          <svg
            xmlns="http://www.w3.org/2000/svg"
            class="stroke-current shrink-0 h-6 w-6"
            fill="none"
            viewBox="0 0 24 24"
          >
            <path
              stroke-linecap="round"
              stroke-linejoin="round"
              stroke-width="2"
              d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z"
            />
          </svg>
          <span>{@error}</span>
        </div>
      <% end %>
      
    <!-- Current Health Metrics -->
      <div class="card bg-base-100 shadow-xl mb-6">
        <div class="card-body">
          <h2 class="card-title">Current Health Status</h2>

          <%= if @current_health do %>
            <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mt-4">
              <div class="stat bg-base-200 rounded-lg">
                <div class="stat-title">Health Status</div>
                <div class="stat-value text-2xl">
                  {health_status_badge(@current_health.health_status)}
                </div>
                <div class="stat-desc">{format_timestamp(@current_health.timestamp)}</div>
              </div>

              <div class="stat bg-base-200 rounded-lg">
                <div class="stat-title">CPU Usage</div>
                <div class="stat-value text-2xl">
                  {format_percentage(@current_health.cpu_percent)}
                </div>
                <div class="stat-desc">Processor utilization</div>
              </div>

              <div class="stat bg-base-200 rounded-lg">
                <div class="stat-title">Memory Usage</div>
                <div class="stat-value text-2xl">
                  {format_percentage(@current_health.memory_percent)}
                </div>
                <div class="stat-desc">Memory utilization</div>
              </div>

              <div class="stat bg-base-200 rounded-lg">
                <div class="stat-title">Database Latency</div>
                <div class="stat-value text-2xl">
                  {format_latency(@current_health.database_latency_ms)}
                </div>
                <div class="stat-desc">Query response time</div>
              </div>

              <div class="stat bg-base-200 rounded-lg">
                <div class="stat-title">Active Connections</div>
                <div class="stat-value text-2xl">{@current_health.active_connections || 0}</div>
                <div class="stat-desc">Current connections</div>
              </div>

              <div class="stat bg-base-200 rounded-lg">
                <div class="stat-title">Vault Status</div>
                <div class="stat-value text-sm">
                  {if @current_health.vault_sealed, do: "🔒 Sealed", else: "🔓 Unsealed"}
                  {if @current_health.vault_initialized, do: " (Init)", else: " (Not Init)"}
                </div>
                <div class="stat-desc">Vault state</div>
              </div>
            </div>
          <% else %>
            <div class="alert alert-info">
              <svg
                xmlns="http://www.w3.org/2000/svg"
                fill="none"
                viewBox="0 0 24 24"
                class="stroke-current shrink-0 w-6 h-6"
              >
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width="2"
                  d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
                />
              </svg>
              <span>No health data available for this node.</span>
            </div>
          <% end %>
        </div>
      </div>
      <!-- Health History -->
      <div class="card bg-base-100 shadow-xl mb-6">
        <div class="card-body">
          <div class="flex justify-between items-center">
            <h2 class="card-title">Health History</h2>

            <div class="tabs tabs-boxed">
              <button
                phx-click="change_time_range"
                phx-value-range="1h"
                class={"tab #{if @time_range == "1h", do: "tab-active", else: ""}"}
              >
                1 Hour
              </button>
              <button
                phx-click="change_time_range"
                phx-value-range="6h"
                class={"tab #{if @time_range == "6h", do: "tab-active", else: ""}"}
              >
                6 Hours
              </button>
              <button
                phx-click="change_time_range"
                phx-value-range="24h"
                class={"tab #{if @time_range == "24h", do: "tab-active", else: ""}"}
              >
                24 Hours
              </button>
            </div>
          </div>

          <%= if Enum.any?(@health_history) do %>
            <div class="overflow-x-auto mt-4">
              <table class="table table-zebra">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Status</th>
                    <th>CPU</th>
                    <th>Memory</th>
                    <th>DB Latency</th>
                    <th>Connections</th>
                  </tr>
                </thead>
                <tbody>
                  <%= for metric <- Enum.take(@health_history, 50) do %>
                    <tr>
                      <td class="text-sm">{format_timestamp(metric.timestamp)}</td>
                      <td>{health_status_badge(metric.health_status)}</td>
                      <td>{format_percentage(metric.cpu_percent)}</td>
                      <td>{format_percentage(metric.memory_percent)}</td>
                      <td>{format_latency(metric.database_latency_ms)}</td>
                      <td>{metric.active_connections || 0}</td>
                    </tr>
                  <% end %>
                </tbody>
              </table>
            </div>

            <div class="mt-4 text-sm text-gray-600">
              Showing {min(length(@health_history), 50)} of {length(@health_history)} metrics
            </div>
          <% else %>
            <div class="alert alert-info mt-4">
              <span>No historical health data available for the selected time range.</span>
            </div>
          <% end %>
        </div>
      </div>
      
    <!-- Recent Alerts -->
      <div class="card bg-base-100 shadow-xl">
        <div class="card-body">
          <h2 class="card-title">Recent Alerts</h2>

          <%= if Enum.any?(@recent_alerts) do %>
            <div class="space-y-2 mt-4">
              <%= for alert <- @recent_alerts do %>
                <div class="alert alert-warning">
                  <svg
                    xmlns="http://www.w3.org/2000/svg"
                    class="stroke-current shrink-0 h-6 w-6"
                    fill="none"
                    viewBox="0 0 24 24"
                  >
                    <path
                      stroke-linecap="round"
                      stroke-linejoin="round"
                      stroke-width="2"
                      d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
                    />
                  </svg>
                  <span>{alert.name}</span>
                </div>
              <% end %>
            </div>
          <% else %>
            <div class="alert alert-success mt-4">
              <svg
                xmlns="http://www.w3.org/2000/svg"
                class="stroke-current shrink-0 h-6 w-6"
                fill="none"
                viewBox="0 0 24 24"
              >
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width="2"
                  d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
                />
              </svg>
              <span>No recent alerts for this node.</span>
            </div>
          <% end %>
        </div>
      </div>
    </div>
    """
  end
end
