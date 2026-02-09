defmodule SecretHub.Web.AgentMonitoringLive do
  @moduledoc """
  LiveView for real-time agent monitoring and management.
  """

  use SecretHub.Web, :live_view
  require Logger

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      :timer.send_interval(5000, :refresh_agents)
    end

    agents = fetch_agents()

    socket =
      socket
      |> assign(:agents, agents)
      |> assign(:selected_agent, nil)
      |> assign(:loading, false)
      |> assign(:filter_status, "all")
      |> assign(:search_query, "")

    {:ok, socket}
  end

  @impl true
  def handle_params(%{"id" => agent_id}, _url, socket) do
    agent = Enum.find(socket.assigns.agents, &(&1.id == agent_id))
    {:noreply, assign(socket, :selected_agent, agent)}
  end

  def handle_params(_params, _url, socket) do
    {:noreply, assign(socket, :selected_agent, nil)}
  end

  @impl true
  def handle_info(:refresh_agents, socket) do
    agents = fetch_agents()
    socket = assign(socket, :agents, agents)
    {:noreply, socket}
  end

  @impl true
  def handle_event("disconnect_agent", %{"agent_id" => agent_id}, socket) do
    Logger.info("Disconnecting agent: #{agent_id}")

    # FIXME: Call SecretHub.Core.Connections.disconnect_agent(agent_id)

    agents = fetch_agents()

    socket =
      socket
      |> assign(:agents, agents)
      |> put_flash(:info, "Agent disconnected successfully")

    {:noreply, socket}
  end

  @impl true
  def handle_event("filter_agents", %{"status" => status}, socket) do
    socket = assign(socket, :filter_status, status)
    {:noreply, socket}
  end

  @impl true
  def handle_event("search_agents", %{"query" => query}, socket) do
    socket = assign(socket, :search_query, query)
    {:noreply, socket}
  end

  @impl true
  def handle_event("reconnect_agent", %{"agent_id" => agent_id}, socket) do
    Logger.info("Reconnecting agent: #{agent_id}")

    # FIXME: Call SecretHub.Core.Connections.reconnect_agent(agent_id)

    socket = put_flash(socket, :info, "Reconnect signal sent to agent")
    {:noreply, socket}
  end

  @impl true
  def handle_event("restart_agent", %{"agent_id" => agent_id}, socket) do
    Logger.info("Restarting agent: #{agent_id}")

    # FIXME: Call SecretHub.Core.Connections.restart_agent(agent_id)

    socket = put_flash(socket, :info, "Restart signal sent to agent")
    {:noreply, socket}
  end

  @impl true
  def handle_event("select_agent", %{"id" => agent_id}, socket) do
    socket = push_patch(socket, to: "/admin/agents/#{agent_id}")
    {:noreply, socket}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="space-y-6">
      <!-- Filters and Search -->
      <div class="bg-white p-4 rounded-lg shadow">
        <div class="flex flex-wrap gap-4 items-center">
          <div class="flex items-center space-x-2">
            <label class="text-sm font-medium text-gray-700">Status:</label>
            <select
              class="form-select"
              phx-change="filter_agents"
              name="status"
              value={@filter_status}
            >
              <option value="all">All</option>
              <option value="connected">Connected</option>
              <option value="disconnected">Disconnected</option>
              <option value="error">Error</option>
            </select>
          </div>

          <div class="flex items-center space-x-2 flex-1">
            <label class="text-sm font-medium text-gray-700">Search:</label>
            <input
              type="text"
              class="form-input flex-1"
              placeholder="Search agents by name or IP..."
              phx-change="search_agents"
              name="query"
              value={@search_query}
            />
          </div>
        </div>
      </div>
      
    <!-- Agent List -->
      <div class="bg-white rounded-lg shadow">
        <div class="px-4 py-3 border-b border-gray-200">
          <h3 class="text-lg font-semibold text-gray-900">
            Connected Agents ({length(@agents)})
          </h3>
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
                  Secrets Accessed
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Uptime
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody class="bg-white divide-y divide-gray-200">
              <%= for agent <- filtered_agents(@agents, @filter_status, @search_query) do %>
                <tr
                  class="hover:bg-gray-50 cursor-pointer transition-colors"
                  phx-click="select_agent"
                  phx-value-id={agent.id}
                >
                  <td class="px-6 py-4 whitespace-nowrap">
                    <div class="flex items-center">
                      <div class={"w-3 h-3 rounded-full mr-3 #{status_color(agent.status)}"}></div>
                      <div>
                        <div class="text-sm font-medium text-gray-900">{agent.name}</div>
                        <div class="text-sm text-gray-500">{agent.os}</div>
                      </div>
                    </div>
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap">
                    <span class={"inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium #{status_badge_color(agent.status)}"}>
                      {Atom.to_string(agent.status)}
                    </span>
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {format_timestamp(agent.last_seen)}
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {agent.ip_address}
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {agent.secrets_accessed}
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {format_uptime(agent.uptime_hours)}
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
                    <div class="flex space-x-2">
                      <%= if agent.status == :disconnected do %>
                        <button
                          class="text-indigo-600 hover:text-indigo-900"
                          phx-click="reconnect_agent"
                          phx-value-id={agent.id}
                        >
                          Reconnect
                        </button>
                      <% end %>

                      <button
                        class="text-red-600 hover:text-red-900"
                        phx-click="disconnect_agent"
                        phx-value-id={agent.id}
                        phx-confirm="Are you sure you want to disconnect this agent?"
                      >
                        Disconnect
                      </button>
                    </div>
                  </td>
                </tr>
              <% end %>
            </tbody>
          </table>
        </div>
      </div>
      
    <!-- Agent Details Panel -->
      <%= if @selected_agent do %>
        <.live_component
          module={SecretHub.Web.AgentDetailsComponent}
          id={"agent-#{@selected_agent.id}"}
          agent={@selected_agent}
        />
      <% end %>
    </div>
    """
  end

  # Helper functions
  defp fetch_agents do
    # FIXME: Replace with actual SecretHub.Core.Connections.list_agents()
    [
      %{
        id: "agent-prod-01",
        name: "Production Web Server",
        status: :connected,
        last_seen: DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.add(-300, :second),
        secrets_accessed: 45,
        uptime_hours: 48.5,
        os: "linux",
        ip_address: "10.0.1.42",
        version: "1.0.0",
        certificate_fingerprint: "SHA256:ABC123...",
        connection_time: DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.add(-48, :hour),
        last_policy_check: DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.add(-600, :second)
      },
      %{
        id: "agent-prod-02",
        name: "Backend Worker",
        status: :disconnected,
        last_seen: DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.add(-1800, :second),
        secrets_accessed: 12,
        uptime_hours: nil,
        os: "alpine-linux",
        ip_address: "10.0.1.45",
        version: "1.0.1",
        certificate_fingerprint: "SHA256:DEF456...",
        connection_time: nil,
        last_policy_check: DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.add(-2400, :second)
      },
      %{
        id: "agent-dev-01",
        name: "Development Environment",
        status: :error,
        last_seen: DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.add(-7200, :second),
        secrets_accessed: 8,
        uptime_hours: 2.1,
        os: "macos",
        ip_address: "192.168.1.100",
        version: "0.9.0",
        certificate_fingerprint: "SHA256:GHI789...",
        connection_time: DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.add(-2, :hour),
        last_policy_check: DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.add(-7200, :second)
      }
    ]
  end

  defp filtered_agents(agents, "all", ""), do: agents

  defp filtered_agents(agents, status, ""),
    do: Enum.filter(agents, &(&1.status == String.to_atom(status)))

  defp filtered_agents(agents, "all", query) do
    query = String.downcase(query)

    Enum.filter(agents, fn agent ->
      String.contains?(String.downcase(agent.name), query) or
        String.contains?(agent.ip_address, query)
    end)
  end

  defp filtered_agents(agents, status, query) do
    agents
    |> Enum.filter(&(&1.status == String.to_atom(status)))
    |> filtered_agents("all", query)
  end

  defp status_color(:connected), do: "bg-green-500"
  defp status_color(:disconnected), do: "bg-gray-400"
  defp status_color(:error), do: "bg-red-500"

  defp status_badge_color(:connected), do: "bg-green-100 text-green-800"
  defp status_badge_color(:disconnected), do: "bg-gray-100 text-gray-800"
  defp status_badge_color(:error), do: "bg-red-100 text-red-800"

  defp format_timestamp(nil), do: "Never"

  defp format_timestamp(datetime) do
    DateTime.diff(DateTime.utc_now() |> DateTime.truncate(:second), datetime, :second)
    |> format_relative_time()
  end

  defp format_relative_time(seconds) when seconds < 60, do: "#{seconds}s ago"
  defp format_relative_time(seconds) when seconds < 3600, do: "#{div(seconds, 60)}m ago"
  defp format_relative_time(seconds) when seconds < 86_400, do: "#{div(seconds, 3600)}h ago"
  defp format_relative_time(seconds), do: "#{div(seconds, 86_400)}d ago"

  defp format_uptime(nil), do: "Offline"
  defp format_uptime(hours) when hours < 1, do: "< 1h"
  defp format_uptime(hours) when hours < 24, do: "#{Float.round(hours, 1)}h"
  defp format_uptime(hours) when hours < 168, do: "#{Float.round(hours / 24, 1)}d"
  defp format_uptime(hours), do: "#{Float.round(hours / 168, 1)}w"
end
