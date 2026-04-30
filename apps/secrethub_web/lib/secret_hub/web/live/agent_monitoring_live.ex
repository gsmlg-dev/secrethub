defmodule SecretHub.Web.AgentMonitoringLive do
  @moduledoc """
  LiveView for real-time agent monitoring and management.
  """

  use SecretHub.Web, :live_view
  require Logger

  alias SecretHub.Core.Agents
  alias SecretHub.Web.Endpoint

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
  def handle_event("disconnect_agent", %{"id" => agent_id}, socket) do
    Logger.info("Disconnecting agent: #{agent_id}")

    case Agents.mark_disconnected(agent_id) do
      {:ok, _agent} ->
        # Broadcast disconnect to the agent's WebSocket channel
        Endpoint.broadcast("agent:#{agent_id}", "disconnect", %{
          reason: "admin_disconnect"
        })

      {:error, reason} ->
        Logger.warning("Failed to disconnect agent #{agent_id}: #{inspect(reason)}")
    end

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
  def handle_event("reconnect_agent", %{"id" => agent_id}, socket) do
    Logger.info("Reconnecting agent: #{agent_id}")

    # FIXME: Call SecretHub.Core.Connections.reconnect_agent(agent_id)

    socket = put_flash(socket, :info, "Reconnect signal sent to agent")
    {:noreply, socket}
  end

  @impl true
  def handle_event("restart_agent", %{"id" => agent_id}, socket) do
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
      <div class="bg-surface-container p-4 rounded-lg shadow">
        <div class="flex flex-wrap gap-4 items-center">
          <div class="flex items-center space-x-2">
            <label class="text-sm font-medium text-on-surface">Status:</label>
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
            <label class="text-sm font-medium text-on-surface">Search:</label>
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
      <div class="bg-surface-container rounded-lg shadow">
        <div class="px-4 py-3 border-b border-outline-variant">
          <h3 class="text-lg font-semibold text-on-surface">
            Connected Agents ({length(@agents)})
          </h3>
        </div>

        <div class="overflow-x-auto">
          <table class="min-w-full divide-y divide-outline-variant">
            <thead class="bg-surface-container-low">
              <tr>
                <th class="px-6 py-3 text-left text-xs font-medium text-on-surface-variant uppercase tracking-wider">
                  Agent
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-on-surface-variant uppercase tracking-wider">
                  Status
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-on-surface-variant uppercase tracking-wider">
                  Last Seen
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-on-surface-variant uppercase tracking-wider">
                  IP Address
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-on-surface-variant uppercase tracking-wider">
                  Secrets Accessed
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-on-surface-variant uppercase tracking-wider">
                  Uptime
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-on-surface-variant uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody class="bg-surface-container divide-y divide-outline-variant">
              <%= for agent <- filtered_agents(@agents, @filter_status, @search_query) do %>
                <tr
                  class="hover:bg-surface-container-low cursor-pointer transition-colors"
                  phx-click="select_agent"
                  phx-value-id={agent.id}
                >
                  <td class="px-6 py-4 whitespace-nowrap">
                    <div class="flex items-center">
                      <div class={"w-3 h-3 rounded-full mr-3 #{status_color(agent.status)}"}></div>
                      <div>
                        <div class="text-sm font-medium text-on-surface">{agent.name}</div>
                        <div class="text-sm text-on-surface-variant">{agent.os}</div>
                      </div>
                    </div>
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap">
                    <span class={"inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium #{status_badge_color(agent.status)}"}>
                      {Atom.to_string(agent.status)}
                    </span>
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm text-on-surface-variant">
                    {format_timestamp(agent.last_seen)}
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm text-on-surface">
                    {agent.ip_address}
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm text-on-surface">
                    {agent.secrets_accessed}
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm text-on-surface-variant">
                    {format_uptime(agent.uptime_hours)}
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
                    <div class="flex space-x-2">
                      <%= if agent.status == :disconnected do %>
                        <button
                          class="text-secondary hover:text-secondary"
                          phx-click="reconnect_agent"
                          phx-value-id={agent.id}
                        >
                          Reconnect
                        </button>
                      <% end %>

                      <button
                        class="text-error hover:text-error"
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
    Agents.list_agents()
    |> Enum.map(&agent_to_display/1)
  end

  defp agent_to_display(agent) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    uptime_hours =
      if agent.status == :active && agent.authenticated_at do
        DateTime.diff(now, agent.authenticated_at, :second) / 3600
      else
        nil
      end

    %{
      id: agent.agent_id,
      name: agent.name || agent.agent_id,
      status: map_agent_status(agent.status),
      last_seen: agent.last_seen_at,
      secrets_accessed: agent.secret_access_count || 0,
      uptime_hours: uptime_hours,
      os: Map.get(agent.metadata || %{}, "os", "unknown"),
      ip_address: agent.ip_address || "unknown",
      version: Map.get(agent.metadata || %{}, "version", "unknown"),
      certificate_fingerprint: nil,
      connection_time: agent.authenticated_at,
      last_policy_check: agent.last_seen_at
    }
  end

  defp map_agent_status(:active), do: :connected
  defp map_agent_status(:disconnected), do: :disconnected
  defp map_agent_status(:pending_bootstrap), do: :disconnected
  defp map_agent_status(:suspended), do: :error
  defp map_agent_status(:revoked), do: :error
  defp map_agent_status(_), do: :disconnected

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

  defp status_color(:connected), do: "bg-success"
  defp status_color(:disconnected), do: "bg-outline"
  defp status_color(:error), do: "bg-error text-error-content"

  defp status_badge_color(:connected), do: "bg-success/10 text-success"
  defp status_badge_color(:disconnected), do: "bg-surface-container text-on-surface"
  defp status_badge_color(:error), do: "bg-error/10 text-error"

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
