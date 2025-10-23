defmodule SecretHub.WebWeb.AdminDashboardLive do
  @moduledoc """
  LiveView for admin dashboard with real-time system statistics.
  """

  use SecretHub.WebWeb, :live_view
  require Logger

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      :timer.send_interval(30000, :refresh_dashboard)
    end

    socket =
      socket
      |> assign(:system_stats, load_system_stats())
      |> assign(:agents, load_agents())
      |> assign(:secret_stats, load_secret_stats())
      |> assign(:audit_stats, load_audit_stats())
      |> assign(:loading, false)

    {:ok, socket}
  end

  @impl true
  def handle_info(:refresh_dashboard, socket) do
    socket =
      socket
      |> assign(:system_stats, load_system_stats())
      |> assign(:agents, load_agents())
      |> assign(:secret_stats, load_secret_stats())
      |> assign(:audit_stats, load_audit_stats())

    {:noreply, socket}
  end

  @impl true
  def handle_event("rotate_all_leases", _params, socket) do
    Logger.info("Rotating all leases")
    # TODO: Call SecretHub.Core.Secrets.rotate_all_leases()

    socket = put_flash(socket, :info, "Lease rotation started")
    {:noreply, socket}
  end

  @impl true
  def handle_event("cleanup_expired_secrets", _params, socket) do
    Logger.info("Cleaning up expired secrets")
    # TODO: Call SecretHub.Core.Secrets.cleanup_expired_secrets()

    socket = put_flash(socket, :info, "Cleanup started")
    {:noreply, socket}
  end

  @impl true
  def handle_event("export_audit_logs", _params, socket) do
    Logger.info("Exporting audit logs")
    # TODO: Generate and trigger download of audit logs

    socket = put_flash(socket, :info, "Export started")
    {:noreply, socket}
  end

  @impl true
  def handle_event("disconnect_agent", %{"agent_id" => agent_id}, socket) do
    Logger.info("Disconnecting agent: #{agent_id}")
    # TODO: Call SecretHub.Core.Connections.disconnect_agent(agent_id)

    updated_agents =
      Enum.map(socket.assigns.agents, fn agent ->
        if agent.id == agent_id do
          %{agent | status: :disconnecting}
        else
          agent
        end
      end)

    socket =
      socket
      |> assign(:agents, updated_agents)
      |> put_flash(:info, "Agent disconnected successfully")

    {:noreply, socket}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="space-y-6">
      <!-- System Stats Section -->
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div class="bg-white p-6 rounded-lg shadow-lg border border-gray-200">
          <div class="flex items-center">
            <div class="flex-shrink-0 p-3 bg-blue-100 rounded-lg">
              <svg class="w-6 h-6 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width="2"
                  d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"
                />
              </svg>
            </div>
            <div class="ml-5 w-0 flex-1">
              <dl>
                <dt class="text-sm font-medium text-gray-500 truncate">Total Secrets</dt>
                <dd class="text-lg font-medium text-gray-900">{@system_stats.total_secrets}</dd>
              </dl>
            </div>
          </div>
        </div>

        <div class="bg-white p-6 rounded-lg shadow-lg border border-gray-200">
          <div class="flex items-center">
            <div class="flex-shrink-0 p-3 bg-green-100 rounded-lg">
              <svg
                class="w-6 h-6 text-green-600"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width="2"
                  d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"
                />
              </svg>
            </div>
            <div class="ml-5 w-0 flex-1">
              <dl>
                <dt class="text-sm font-medium text-gray-500 truncate">Active Agents</dt>
                <dd class="text-lg font-medium text-gray-900">{@system_stats.active_agents}</dd>
              </dl>
            </div>
          </div>
        </div>

        <div class="bg-white p-6 rounded-lg shadow-lg border border-gray-200">
          <div class="flex items-center">
            <div class="flex-shrink-0 p-3 bg-purple-100 rounded-lg">
              <svg
                class="w-6 h-6 text-purple-600"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width="2"
                  d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"
                />
              </svg>
            </div>
            <div class="ml-5 w-0 flex-1">
              <dl>
                <dt class="text-sm font-medium text-gray-500 truncate">System Uptime</dt>
                <dd class="text-lg font-medium text-gray-900">
                  {format_uptime(@system_stats.uptime_hours)}
                </dd>
              </dl>
            </div>
          </div>
        </div>

        <div class="bg-white p-6 rounded-lg shadow-lg border border-gray-200">
          <div class="flex items-center">
            <div class="flex-shrink-0 p-3 bg-yellow-100 rounded-lg">
              <svg
                class="w-6 h-6 text-yellow-600"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width="2"
                  d="M7 7h.01M7 3h5c.512 0 1.024.195 1.414.586l7 7a2 2 0 010 2.828l-7 7a2 2 0 01-2.828 0l-7-7A1.994 1.994 0 013 12V7a4 4 0 014-4z"
                />
              </svg>
            </div>
            <div class="ml-5 w-0 flex-1">
              <dl>
                <dt class="text-sm font-medium text-gray-500 truncate">Storage Used</dt>
                <dd class="text-lg font-medium text-gray-900">
                  {Float.round(@system_stats.storage_used_gb, 2)} GB
                </dd>
              </dl>
            </div>
          </div>
        </div>
      </div>
      
    <!-- Connected Agents Section -->
      <div class="bg-white p-6 rounded-lg shadow-lg border border-gray-200">
        <div class="flex justify-between items-center mb-4">
          <h3 class="text-lg font-semibold text-gray-900">Connected Agents</h3>
          <.link
            navigate="/admin/agents"
            class="text-blue-600 hover:text-blue-800 text-sm font-medium"
          >
            View All →
          </.link>
        </div>
        <div class="overflow-x-auto">
          <table class="min-w-full divide-y divide-gray-200">
            <thead class="bg-gray-50">
              <tr>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Agent
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Status
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Last Seen
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  IP Address
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody class="bg-white divide-y divide-gray-200">
              <%= for agent <- Enum.take(@agents, 5) do %>
                <tr class="hover:bg-gray-50">
                  <td class="px-6 py-4 whitespace-nowrap">
                    <div class="flex items-center">
                      <div class={"w-2 h-2 rounded-full mr-2 #{status_color(agent.status)}"}></div>
                      <div class="text-sm font-medium text-gray-900">{agent.name}</div>
                    </div>
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap">
                    <span class={"inline-flex px-2 py-1 text-xs font-semibold rounded-full #{status_badge_color(agent.status)}"}>
                      {String.upcase(Atom.to_string(agent.status))}
                    </span>
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {format_timestamp(agent.last_seen)}
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {agent.ip_address}
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                    <button
                      class="text-red-600 hover:text-red-900"
                      phx-click="disconnect_agent"
                      phx-value-agent-id={agent.id}
                      phx-confirm="Are you sure you want to disconnect this agent?"
                    >
                      Disconnect
                    </button>
                  </td>
                </tr>
              <% end %>
            </tbody>
          </table>
        </div>
      </div>
      
    <!-- Quick Actions -->
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        <div class="bg-white p-6 rounded-lg shadow-lg border border-gray-200">
          <div class="flex items-center justify-between mb-4">
            <h3 class="text-lg font-semibold text-gray-900">Maintenance</h3>
            <svg class="w-6 h-6 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path
                stroke-linecap="round"
                stroke-linejoin="round"
                stroke-width="2"
                d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"
              />
              <path
                stroke-linecap="round"
                stroke-linejoin="round"
                stroke-width="2"
                d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"
              />
            </svg>
          </div>
          <div class="space-y-3">
            <button
              phx-click="rotate_all_leases"
              class="w-full btn-primary"
              phx-disable-with="Rotating..."
            >
              Rotate All Leases
            </button>
            <button
              phx-click="cleanup_expired_secrets"
              class="w-full btn-secondary"
              phx-disable-with="Cleaning..."
            >
              Cleanup Expired Secrets
            </button>
          </div>
        </div>

        <div class="bg-white p-6 rounded-lg shadow-lg border border-gray-200">
          <div class="flex items-center justify-between mb-4">
            <h3 class="text-lg font-semibold text-gray-900">Data Management</h3>
            <svg class="w-6 h-6 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path
                stroke-linecap="round"
                stroke-linejoin="round"
                stroke-width="2"
                d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z"
              />
            </svg>
          </div>
          <div class="space-y-3">
            <.link navigate="/admin/secrets" class="block w-full text-center btn-secondary">
              Manage Secrets
            </.link>
            <.link navigate="/admin/audit" class="block w-full text-center btn-secondary">
              View Audit Logs
            </.link>
          </div>
        </div>

        <div class="bg-white p-6 rounded-lg shadow-lg border border-gray-200">
          <div class="flex items-center justify-between mb-4">
            <h3 class="text-lg font-semibold text-gray-900">Quick Links</h3>
            <svg class="w-6 h-6 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path
                stroke-linecap="round"
                stroke-linejoin="round"
                stroke-width="2"
                d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"
              />
            </svg>
          </div>
          <div class="space-y-2 text-sm">
            <div class="flex justify-between">
              <span class="text-gray-500">Static Secrets:</span>
              <span class="font-medium">{@system_stats.static_secrets}</span>
            </div>
            <div class="flex justify-between">
              <span class="text-gray-500">Dynamic Secrets:</span>
              <span class="font-medium">{@system_stats.dynamic_secrets}</span>
            </div>
            <div class="flex justify-between">
              <span class="text-gray-500">Last Rotation:</span>
              <span class="font-medium">{@system_stats.last_rotation}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
  end

  # Private functions
  defp load_system_stats do
    # TODO: Call SecretHub.Core.Stats.system_stats()
    %{
      total_secrets: 156,
      static_secrets: 89,
      dynamic_secrets: 67,
      active_agents: 12,
      uptime_hours: 72.5,
      storage_used_gb: 2.3,
      last_rotation: "2025-01-20T14:30:00Z"
    }
  end

  defp load_agents do
    # TODO: Call SecretHub.Core.Agents.list_connected_agents()
    [
      %{
        id: "agent-prod-01",
        name: "Production Web Server",
        status: :connected,
        last_seen: DateTime.utc_now() |> DateTime.add(-300, :second),
        ip_address: "10.0.1.42"
      },
      %{
        id: "agent-prod-02",
        name: "Backend Worker",
        status: :connected,
        last_seen: DateTime.utc_now() |> DateTime.add(-600, :second),
        ip_address: "10.0.1.45"
      },
      %{
        id: "agent-dev-01",
        name: "Development Environment",
        status: :disconnected,
        last_seen: DateTime.utc_now() |> DateTime.add(-1800, :second),
        ip_address: "192.168.1.100"
      }
    ]
  end

  defp load_secret_stats do
    # TODO: Call SecretHub.Core.Stats.secret_stats()
    %{
      total_secrets: 156,
      static_secrets: 89,
      dynamic_secrets: 67,
      secrets_rotated_24h: 12,
      secrets_expiring_7d: 8,
      most_accessed_secret: "prod.db.postgres.password"
    }
  end

  defp load_audit_stats do
    # TODO: Call SecretHub.Core.Stats.audit_stats()
    %{
      total_events_24h: 1247,
      access_denied_24h: 23,
      active_policies: 12
    }
  end

  defp status_color(:connected), do: "bg-green-500"
  defp status_color(:disconnected), do: "bg-gray-400"
  defp status_color(:error), do: "bg-red-500"
  defp status_color(_), do: "bg-gray-500"

  defp status_badge_color(:connected), do: "bg-green-100 text-green-800"
  defp status_badge_color(:disconnected), do: "bg-gray-100 text-gray-800"
  defp status_badge_color(:error), do: "bg-red-100 text-red-800"

  defp format_timestamp(nil), do: "Never"

  defp format_timestamp(datetime) do
    DateTime.diff(DateTime.utc_now(), datetime, :second)
    |> format_relative_time()
  end

  defp format_relative_time(seconds) when seconds < 60, do: "#{seconds}s ago"
  defp format_relative_time(seconds) when seconds < 3600, do: "#{div(seconds, 60)}m ago"
  defp format_relative_time(seconds) when seconds < 86400, do: "#{div(seconds, 3600)}h ago"
  defp format_relative_time(seconds), do: "#{div(seconds, 86400)}d ago"

  defp format_uptime(nil), do: "Unknown"
  defp format_uptime(hours) when hours < 1, do: "< 1h"
  defp format_uptime(hours) when hours < 24, do: "#{Float.round(hours, 1)}h"
  defp format_uptime(hours) when hours < 168, do: "#{Float.round(hours / 24, 1)}d"
  defp format_uptime(hours), do: "#{Float.round(hours / 168, 1)}w"
end
