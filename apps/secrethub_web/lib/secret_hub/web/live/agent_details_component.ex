defmodule SecretHub.Web.AgentDetailsComponent do
  @moduledoc """
  LiveComponent for displaying detailed agent information.
  """

  use SecretHub.Web, :live_component
  require Logger

  @impl true
  def update(assigns, socket) do
    socket = assign(socket, assigns)
    {:ok, socket}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="bg-white rounded-lg shadow p-6">
      <div class="flex justify-between items-start mb-6">
        <div>
          <h3 class="text-xl font-semibold text-gray-900">
            {@agent.name}
          </h3>
          <p class="text-sm text-gray-500">
            Agent ID: <code class="bg-gray-100 px-1 py-0.5 rounded">{@agent.id}</code>
          </p>
        </div>
        <div class="flex space-x-2">
          <button class="btn-secondary btn-sm">
            View Logs
          </button>
          <button class="btn-primary btn-sm">
            Edit Config
          </button>
        </div>
      </div>

      <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
        <!-- Connection Info -->
        <div class="space-y-4">
          <h4 class="text-lg font-medium text-gray-900">Connection Information</h4>

          <div class="space-y-3">
            <div class="flex justify-between">
              <span class="text-sm font-medium text-gray-500">Status</span>
              <span class={"inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium #{status_badge_color(@agent.status)}"}>
                {Atom.to_string(@agent.status)}
              </span>
            </div>

            <div class="flex justify-between">
              <span class="text-sm font-medium text-gray-500">IP Address</span>
              <span class="text-sm text-gray-900">{@agent.ip_address}</span>
            </div>

            <div class="flex justify-between">
              <span class="text-sm font-medium text-gray-500">Operating System</span>
              <span class="text-sm text-gray-900">{@agent.os}</span>
            </div>

            <div class="flex justify-between">
              <span class="text-sm font-medium text-gray-500">Agent Version</span>
              <span class="text-sm text-gray-900">{@agent.version}</span>
            </div>

            <%= if @agent.connection_time do %>
              <div class="flex justify-between">
                <span class="text-sm font-medium text-gray-500">Connected Since</span>
                <span class="text-sm text-gray-900">
                  {format_datetime(@agent.connection_time)}
                </span>
              </div>
            <% end %>

            <div class="flex justify-between">
              <span class="text-sm font-medium text-gray-500">Last Seen</span>
              <span class="text-sm text-gray-900">
                {format_datetime(@agent.last_seen)}
              </span>
            </div>

            <div class="flex justify-between">
              <span class="text-sm font-medium text-gray-500">Uptime</span>
              <span class="text-sm text-gray-900">
                {format_uptime(@agent.uptime_hours)}
              </span>
            </div>
          </div>
        </div>
        
    <!-- Security Info -->
        <div class="space-y-4">
          <h4 class="text-lg font-medium text-gray-900">Security Information</h4>

          <div class="space-y-3">
            <div class="flex justify-between">
              <span class="text-sm font-medium text-gray-500">Certificate Fingerprint</span>
              <span class="text-xs text-gray-600 font-mono">
                {@agent.certificate_fingerprint}
              </span>
            </div>

            <div class="flex justify-between">
              <span class="text-sm font-medium text-gray-500">Last Policy Check</span>
              <span class="text-sm text-gray-900">
                {format_datetime(@agent.last_policy_check)}
              </span>
            </div>

            <div class="flex justify-between">
              <span class="text-sm font-medium text-gray-500">Secrets Accessed</span>
              <span class="text-sm text-gray-900">{@agent.secrets_accessed}</span>
            </div>
          </div>
        </div>
      </div>
      
    <!-- Recent Activity -->
      <div class="mt-6">
        <h4 class="text-lg font-medium text-gray-900 mb-4">Recent Activity</h4>
        <div class="bg-gray-50 rounded-lg p-4">
          <div class="space-y-3">
            <%= for activity <- recent_activities(@agent.id) do %>
              <div class="flex items-start space-x-3">
                <div class={"w-2 h-2 rounded-full mt-2 #{activity_icon_color(activity.type)}"}></div>
                <div class="flex-1">
                  <div class="text-sm text-gray-900">{activity.description}</div>
                  <div class="text-xs text-gray-500">
                    {format_datetime(activity.timestamp)}
                  </div>
                </div>
              </div>
            <% end %>
          </div>
        </div>
      </div>
      
    <!-- Agent Actions -->
      <div class="mt-6 border-t pt-6">
        <h4 class="text-lg font-medium text-gray-900 mb-4">Agent Actions</h4>
        <div class="flex space-x-4">
          <button
            phx-click="restart_agent"
            phx-value-id={@agent.id}
            phx-target={@myself}
            class="btn-secondary"
            phx-confirm="Are you sure you want to restart this agent?"
          >
            Restart Agent
          </button>

          <button
            phx-click="disconnect_agent"
            phx-value-id={@agent.id}
            phx-target={@myself}
            class="btn-danger"
            phx-confirm="Are you sure you want to disconnect this agent?"
          >
            Force Disconnect
          </button>

          <button class="btn-secondary">
            Download Logs
          </button>

          <button class="btn-secondary">
            View Configuration
          </button>
        </div>
      </div>
    </div>
    """
  end

  @impl true
  def handle_event("restart_agent", %{"id" => agent_id}, socket) do
    Logger.info("Restarting agent: #{agent_id}")

    # FIXME: Call SecretHub.Core.Connections.restart_agent(agent_id)

    socket =
      socket
      |> put_flash(:info, "Restart signal sent to agent")
      |> push_patch(to: "/admin/agents")

    {:noreply, socket}
  end

  @impl true
  def handle_event("disconnect_agent", %{"id" => agent_id}, socket) do
    Logger.info("Force disconnecting agent: #{agent_id}")

    # FIXME: Call SecretHub.Core.Connections.force_disconnect_agent(agent_id)

    socket =
      socket
      |> put_flash(:info, "Agent disconnected successfully")
      |> push_patch(to: "/admin/agents")

    {:noreply, socket}
  end

  # Helper functions
  defp status_badge_color(:connected), do: "bg-green-100 text-green-800"
  defp status_badge_color(:disconnected), do: "bg-gray-100 text-gray-800"
  defp status_badge_color(:error), do: "bg-red-100 text-red-800"

  defp format_datetime(nil), do: "Never"

  defp format_datetime(datetime) do
    DateTime.to_string(datetime)
  end

  defp format_uptime(nil), do: "Offline"
  defp format_uptime(hours) when hours < 1, do: "< 1 hour"
  defp format_uptime(hours) when hours < 24, do: "#{Float.round(hours, 1)} hours"
  defp format_uptime(hours) when hours < 168, do: "#{Float.round(hours / 24, 1)} days"
  defp format_uptime(hours), do: "#{Float.round(hours / 168, 1)} weeks"

  defp activity_icon_color("secret_access"), do: "bg-blue-500"
  defp activity_icon_color("policy_check"), do: "bg-green-500"
  defp activity_icon_color("error"), do: "bg-red-500"
  defp activity_icon_color("connection"), do: "bg-yellow-500"
  defp activity_icon_color(_), do: "bg-gray-500"

  defp recent_activities(_agent_id) do
    # FIXME: Replace with actual activity data from audit logs
    [
      %{
        type: "secret_access",
        description: "Accessed secret: prod.db.postgres.password",
        timestamp: DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.add(-300, :second)
      },
      %{
        type: "policy_check",
        description: "Policy validation passed",
        timestamp: DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.add(-600, :second)
      },
      %{
        type: "connection",
        description: "WebSocket connection established",
        timestamp:
          DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.add(-1800, :second)
      }
    ]
  end
end
