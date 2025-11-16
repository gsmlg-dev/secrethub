defmodule SecretHub.WebWeb.LeaseDashboardLive do
  @moduledoc """
  LiveView for lease renewal monitoring and analytics.

  Displays:
  - Renewal success/failure metrics
  - Upcoming renewals timeline
  - Lease history and trends
  - Engine-specific statistics
  """
  use SecretHub.WebWeb, :live_view
  alias SecretHub.Core.LeaseManager
  require Logger

  @refresh_interval 5_000

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      # Schedule periodic refresh
      Process.send_after(self(), :refresh_dashboard, @refresh_interval)
    end

    socket =
      socket
      |> assign(:page_title, "Lease Dashboard")
      |> assign(:stats, %{})
      |> assign(:renewal_metrics, %{})
      |> assign(:upcoming_renewals, [])
      |> assign(:recent_activity, [])
      |> assign(:engine_breakdown, [])
      |> assign(:time_range, "1h")
      |> load_dashboard_data()

    {:ok, socket}
  end

  @impl true
  def handle_info(:refresh_dashboard, socket) do
    # Schedule next refresh
    Process.send_after(self(), :refresh_dashboard, @refresh_interval)

    socket = load_dashboard_data(socket)
    {:noreply, socket}
  end

  @impl true
  def handle_event("change_time_range", %{"range" => range}, socket) do
    socket =
      socket
      |> assign(:time_range, range)
      |> load_dashboard_data()

    {:noreply, socket}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="container mx-auto px-4 py-8">
      <div class="mb-6 flex justify-between items-center">
        <div>
          <h1 class="text-3xl font-bold text-gray-900">Lease Renewal Dashboard</h1>
          <p class="mt-2 text-gray-600">
            Monitor lease renewal metrics and system health
          </p>
        </div>

        <div>
          <label class="mr-2 text-sm font-medium text-gray-700">Time Range:</label>
          <select
            phx-change="change_time_range"
            phx-value-range={@time_range}
            class="select select-bordered select-sm"
          >
            <option value="1h" selected={@time_range == "1h"}>Last Hour</option>
            <option value="6h" selected={@time_range == "6h"}>Last 6 Hours</option>
            <option value="24h" selected={@time_range == "24h"}>Last 24 Hours</option>
            <option value="7d" selected={@time_range == "7d"}>Last 7 Days</option>
            <option value="30d" selected={@time_range == "30d"}>Last 30 Days</option>
          </select>
        </div>
      </div>
      
    <!-- Overview Statistics -->
      <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <div class="bg-white shadow rounded-lg p-6">
          <div class="text-sm font-medium text-gray-500">Total Leases</div>
          <div class="mt-2 text-3xl font-bold text-gray-900">{@stats[:total_leases] || 0}</div>
          <div class="mt-2 text-sm text-gray-500">
            {@stats[:active_leases] || 0} active
          </div>
        </div>

        <div class="bg-white shadow rounded-lg p-6">
          <div class="text-sm font-medium text-gray-500">Renewal Success Rate</div>
          <div class="mt-2 text-3xl font-bold text-green-600">
            {format_percentage(@renewal_metrics[:success_rate] || 100.0)}
          </div>
          <div class="mt-2 text-sm text-gray-500">
            {@renewal_metrics[:successful] || 0} / {@renewal_metrics[:total_attempts] || 0} renewals
          </div>
        </div>

        <div class="bg-white shadow rounded-lg p-6">
          <div class="text-sm font-medium text-gray-500">Failed Renewals</div>
          <div class="mt-2 text-3xl font-bold text-red-600">
            {@renewal_metrics[:failed] || 0}
          </div>
          <div class="mt-2 text-sm text-gray-500">
            Last {format_time_range(@time_range)}
          </div>
        </div>

        <div class="bg-white shadow rounded-lg p-6">
          <div class="text-sm font-medium text-gray-500">Avg Renewal Time</div>
          <div class="mt-2 text-3xl font-bold text-blue-600">
            {@renewal_metrics[:avg_duration_ms] || 0}ms
          </div>
          <div class="mt-2 text-sm text-gray-500">
            P95: {@renewal_metrics[:p95_duration_ms] || 0}ms
          </div>
        </div>
      </div>
      
    <!-- Renewal Metrics Chart -->
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <div class="bg-white shadow rounded-lg p-6">
          <h2 class="text-lg font-semibold mb-4">Renewal Trends</h2>

          <div class="space-y-4">
            <div>
              <div class="flex justify-between text-sm mb-1">
                <span class="text-gray-600">Successful Renewals</span>
                <span class="font-semibold text-green-600">
                  {@renewal_metrics[:successful] || 0}
                </span>
              </div>
              <div class="w-full bg-gray-200 rounded-full h-2">
                <div
                  class="bg-green-600 h-2 rounded-full"
                  style={"width: #{renewal_bar_width(@renewal_metrics, :successful)}%"}
                >
                </div>
              </div>
            </div>

            <div>
              <div class="flex justify-between text-sm mb-1">
                <span class="text-gray-600">Failed Renewals</span>
                <span class="font-semibold text-red-600">
                  {@renewal_metrics[:failed] || 0}
                </span>
              </div>
              <div class="w-full bg-gray-200 rounded-full h-2">
                <div
                  class="bg-red-600 h-2 rounded-full"
                  style={"width: #{renewal_bar_width(@renewal_metrics, :failed)}%"}
                >
                </div>
              </div>
            </div>

            <div>
              <div class="flex justify-between text-sm mb-1">
                <span class="text-gray-600">Auto-Expired</span>
                <span class="font-semibold text-yellow-600">
                  {@renewal_metrics[:expired] || 0}
                </span>
              </div>
              <div class="w-full bg-gray-200 rounded-full h-2">
                <div
                  class="bg-yellow-600 h-2 rounded-full"
                  style={"width: #{renewal_bar_width(@renewal_metrics, :expired)}%"}
                >
                </div>
              </div>
            </div>
          </div>
        </div>

        <div class="bg-white shadow rounded-lg p-6">
          <h2 class="text-lg font-semibold mb-4">Engine Breakdown</h2>

          <%= if @engine_breakdown == [] do %>
            <div class="text-center text-gray-500 py-8">
              No lease data available
            </div>
          <% else %>
            <div class="space-y-4">
              <%= for engine <- @engine_breakdown do %>
                <div>
                  <div class="flex justify-between text-sm mb-1">
                    <span class="text-gray-600 capitalize">{engine.type}</span>
                    <span class="font-semibold text-gray-900">
                      {engine.count} ({format_percentage(engine.percentage)})
                    </span>
                  </div>
                  <div class="w-full bg-gray-200 rounded-full h-2">
                    <div
                      class="bg-indigo-600 h-2 rounded-full"
                      style={"width: #{engine.percentage}%"}
                    >
                    </div>
                  </div>
                </div>
              <% end %>
            </div>
          <% end %>
        </div>
      </div>
      
    <!-- Upcoming Renewals Timeline -->
      <div class="bg-white shadow rounded-lg p-6 mb-6">
        <h2 class="text-lg font-semibold mb-4">Upcoming Renewals</h2>

        <%= if @upcoming_renewals == [] do %>
          <div class="text-center text-gray-500 py-8">
            No upcoming renewals scheduled
          </div>
        <% else %>
          <div class="overflow-x-auto">
            <table class="min-w-full divide-y divide-gray-200">
              <thead class="bg-gray-50">
                <tr>
                  <th class="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">
                    Lease ID
                  </th>
                  <th class="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">
                    Role
                  </th>
                  <th class="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">
                    Engine
                  </th>
                  <th class="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">
                    Renewal Due
                  </th>
                  <th class="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">
                    Time Until
                  </th>
                  <th class="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">
                    Status
                  </th>
                </tr>
              </thead>
              <tbody class="bg-white divide-y divide-gray-200">
                <%= for renewal <- Enum.take(@upcoming_renewals, 10) do %>
                  <tr>
                    <td class="px-4 py-2 text-sm font-mono text-gray-900">
                      {String.slice(renewal.lease_id, 0, 8)}...
                    </td>
                    <td class="px-4 py-2 text-sm text-gray-900">
                      {renewal.role_name}
                    </td>
                    <td class="px-4 py-2 text-sm text-gray-500">
                      {renewal.engine_type}
                    </td>
                    <td class="px-4 py-2 text-sm text-gray-500">
                      {format_datetime(renewal.renewal_time)}
                    </td>
                    <td class="px-4 py-2 text-sm font-semibold">
                      <span class={time_until_class(renewal.time_until)}>
                        {format_duration(renewal.time_until)}
                      </span>
                    </td>
                    <td class="px-4 py-2 text-sm">
                      <span class={"px-2 inline-flex text-xs leading-5 font-semibold rounded-full #{urgency_badge_class(renewal.time_until)}"}>
                        {urgency_text(renewal.time_until)}
                      </span>
                    </td>
                  </tr>
                <% end %>
              </tbody>
            </table>
          </div>
        <% end %>
      </div>
      
    <!-- Recent Activity -->
      <div class="bg-white shadow rounded-lg p-6">
        <h2 class="text-lg font-semibold mb-4">Recent Activity</h2>

        <%= if @recent_activity == [] do %>
          <div class="text-center text-gray-500 py-8">
            No recent activity
          </div>
        <% else %>
          <div class="space-y-3">
            <%= for activity <- Enum.take(@recent_activity, 20) do %>
              <div class={"flex items-start space-x-3 border-l-4 pl-3 py-2 #{activity_border_class(activity.type)}"}>
                <div class="flex-shrink-0">
                  <div class={"w-2 h-2 mt-1.5 rounded-full #{activity_dot_class(activity.type)}"}>
                  </div>
                </div>
                <div class="flex-1 min-w-0">
                  <div class="flex justify-between items-start">
                    <div>
                      <p class="text-sm font-medium text-gray-900">
                        {activity.description}
                      </p>
                      <p class="text-xs text-gray-500 mt-1">
                        Lease: {String.slice(activity.lease_id, 0, 16)}... | Role: {activity.role_name}
                      </p>
                    </div>
                    <span class="text-xs text-gray-500 whitespace-nowrap ml-2">
                      {format_time_ago(activity.timestamp)}
                    </span>
                  </div>
                </div>
              </div>
            <% end %>
          </div>
        <% end %>
      </div>
    </div>
    """
  end

  # Private helper functions

  defp load_dashboard_data(socket) do
    stats = load_stats()
    renewal_metrics = load_renewal_metrics(socket.assigns.time_range)
    upcoming_renewals = load_upcoming_renewals()
    recent_activity = load_recent_activity(socket.assigns.time_range)
    engine_breakdown = load_engine_breakdown()

    socket
    |> assign(:stats, stats)
    |> assign(:renewal_metrics, renewal_metrics)
    |> assign(:upcoming_renewals, upcoming_renewals)
    |> assign(:recent_activity, recent_activity)
    |> assign(:engine_breakdown, engine_breakdown)
  end

  defp load_stats do
    case LeaseManager.get_stats() do
      {:ok, stats} -> stats
      _ -> %{total_leases: 0, active_leases: 0}
    end
  end

  defp load_renewal_metrics(_time_range) do
    # TODO: Implement metrics collection from audit logs or dedicated metrics store
    # For now, return mock data structure
    %{
      total_attempts: 0,
      successful: 0,
      failed: 0,
      expired: 0,
      success_rate: 100.0,
      avg_duration_ms: 0,
      p95_duration_ms: 0
    }
  end

  defp load_upcoming_renewals do
    case LeaseManager.list_active_leases() do
      {:ok, leases} ->
        now = DateTime.utc_now()

        leases
        |> Enum.filter(fn lease ->
          remaining = DateTime.diff(lease.expires_at, now)
          threshold = lease.lease_duration * 0.33
          remaining > 0 && remaining < threshold
        end)
        |> Enum.map(fn lease ->
          _remaining = DateTime.diff(lease.expires_at, now)
          renewal_threshold = lease.lease_duration * 0.33
          renewal_time = DateTime.add(lease.expires_at, -trunc(renewal_threshold), :second)

          %{
            lease_id: lease.id,
            role_name: lease.role_name,
            engine_type: lease.engine_type,
            renewal_time: renewal_time,
            time_until: DateTime.diff(renewal_time, now)
          }
        end)
        |> Enum.sort_by(& &1.time_until)

      _ ->
        []
    end
  end

  defp load_recent_activity(_time_range) do
    # TODO: Implement activity tracking from audit logs
    # For now, return empty list
    []
  end

  defp load_engine_breakdown do
    case LeaseManager.list_active_leases() do
      {:ok, leases} ->
        total = length(leases)

        if total == 0 do
          []
        else
          leases
          |> Enum.group_by(& &1.engine_type)
          |> Enum.map(fn {type, group_leases} ->
            count = length(group_leases)
            percentage = count / total * 100

            %{
              type: type,
              count: count,
              percentage: percentage
            }
          end)
          |> Enum.sort_by(& &1.count, :desc)
        end

      _ ->
        []
    end
  end

  defp format_percentage(value) when is_float(value) do
    "#{Float.round(value, 1)}%"
  end

  defp format_percentage(_), do: "0.0%"

  defp format_time_range("1h"), do: "hour"
  defp format_time_range("6h"), do: "6 hours"
  defp format_time_range("24h"), do: "24 hours"
  defp format_time_range("7d"), do: "7 days"
  defp format_time_range("30d"), do: "30 days"

  defp renewal_bar_width(metrics, key) do
    total = metrics[:total_attempts] || 0

    if total == 0 do
      0
    else
      value = metrics[key] || 0
      value / total * 100
    end
  end

  defp format_datetime(datetime) do
    Calendar.strftime(datetime, "%Y-%m-%d %H:%M:%S")
  end

  defp format_duration(seconds) when seconds < 60, do: "#{seconds}s"
  defp format_duration(seconds) when seconds < 3600, do: "#{div(seconds, 60)}m"

  defp format_duration(seconds) when seconds < 86400,
    do: "#{div(seconds, 3600)}h #{div(rem(seconds, 3600), 60)}m"

  defp format_duration(seconds), do: "#{div(seconds, 86400)}d"

  defp time_until_class(seconds) when seconds < 300, do: "text-red-600"
  defp time_until_class(seconds) when seconds < 1800, do: "text-yellow-600"
  defp time_until_class(_), do: "text-green-600"

  defp urgency_badge_class(seconds) when seconds < 300, do: "bg-red-100 text-red-800"
  defp urgency_badge_class(seconds) when seconds < 1800, do: "bg-yellow-100 text-yellow-800"
  defp urgency_badge_class(_), do: "bg-green-100 text-green-800"

  defp urgency_text(seconds) when seconds < 300, do: "Urgent"
  defp urgency_text(seconds) when seconds < 1800, do: "Soon"
  defp urgency_text(_), do: "Normal"

  defp format_time_ago(timestamp) do
    seconds = DateTime.diff(DateTime.utc_now(), timestamp)

    cond do
      seconds < 60 -> "#{seconds}s ago"
      seconds < 3600 -> "#{div(seconds, 60)}m ago"
      seconds < 86400 -> "#{div(seconds, 3600)}h ago"
      true -> "#{div(seconds, 86400)}d ago"
    end
  end

  defp activity_border_class("renewal_success"), do: "border-green-500"
  defp activity_border_class("renewal_failed"), do: "border-red-500"
  defp activity_border_class("lease_created"), do: "border-blue-500"
  defp activity_border_class("lease_revoked"), do: "border-yellow-500"
  defp activity_border_class(_), do: "border-gray-300"

  defp activity_dot_class("renewal_success"), do: "bg-green-500"
  defp activity_dot_class("renewal_failed"), do: "bg-red-500"
  defp activity_dot_class("lease_created"), do: "bg-blue-500"
  defp activity_dot_class("lease_revoked"), do: "bg-yellow-500"
  defp activity_dot_class(_), do: "bg-gray-300"
end
