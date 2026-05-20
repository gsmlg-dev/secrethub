defmodule SecretHub.Web.AgentDetailsComponent do
  @moduledoc """
  LiveComponent for displaying detailed agent information.
  """

  use SecretHub.Web, :live_component
  require Logger

  @remove_confirmation_text "I know this is dangerous"

  @impl true
  def update(assigns, socket) do
    socket =
      socket
      |> assign(assigns)
      |> assign_new(:show_remove_modal, fn -> false end)
      |> assign_new(:remove_validation_errors, fn -> [] end)
      |> assign_new(:remove_confirmation_text, fn -> @remove_confirmation_text end)

    {:ok, socket}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="bg-surface-container rounded-lg shadow p-6">
      <div class="flex justify-between items-start mb-6">
        <div>
          <h3 class="text-xl font-semibold text-on-surface">
            {@agent.name}
          </h3>
          <p class="text-sm text-on-surface-variant">
            Agent ID: <code class="bg-surface-container px-1 py-0.5 rounded">{@agent.id}</code>
          </p>
        </div>
        <div class="flex space-x-2">
          <button class="btn btn-secondary btn-sm">
            View Logs
          </button>
          <button class="btn btn-primary btn-sm">
            Edit Config
          </button>
        </div>
      </div>

      <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
        <!-- Connection Info -->
        <div class="space-y-4">
          <h4 class="text-lg font-medium text-on-surface">Connection Information</h4>

          <div class="space-y-3">
            <div class="flex justify-between">
              <span class="text-sm font-medium text-on-surface-variant">Status</span>
              <span class={"inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium #{status_badge_color(@agent.status)}"}>
                {Atom.to_string(@agent.status)}
              </span>
            </div>

            <div class="flex justify-between">
              <span class="text-sm font-medium text-on-surface-variant">IP Address</span>
              <span class="text-sm text-on-surface">{@agent.ip_address}</span>
            </div>

            <div class="flex justify-between">
              <span class="text-sm font-medium text-on-surface-variant">Operating System</span>
              <span class="text-sm text-on-surface">{@agent.os}</span>
            </div>

            <div class="flex justify-between">
              <span class="text-sm font-medium text-on-surface-variant">Agent Version</span>
              <span class="text-sm text-on-surface">{@agent.version}</span>
            </div>

            <%= if @agent.connection_time do %>
              <div class="flex justify-between">
                <span class="text-sm font-medium text-on-surface-variant">Connected Since</span>
                <span class="text-sm text-on-surface">
                  {format_datetime(@agent.connection_time)}
                </span>
              </div>
            <% end %>

            <div class="flex justify-between">
              <span class="text-sm font-medium text-on-surface-variant">Last Seen</span>
              <span class="text-sm text-on-surface">
                {format_datetime(@agent.last_seen)}
              </span>
            </div>

            <div class="flex justify-between">
              <span class="text-sm font-medium text-on-surface-variant">Uptime</span>
              <span class="text-sm text-on-surface">
                {format_uptime(@agent.uptime_hours)}
              </span>
            </div>
          </div>
        </div>
        
    <!-- Security Info -->
        <div class="space-y-4">
          <h4 class="text-lg font-medium text-on-surface">Security Information</h4>

          <div class="space-y-3">
            <div class="flex justify-between">
              <span class="text-sm font-medium text-on-surface-variant">Certificate Fingerprint</span>
              <span class="text-xs text-on-surface-variant font-mono">
                {@agent.certificate_fingerprint}
              </span>
            </div>

            <div class="flex justify-between">
              <span class="text-sm font-medium text-on-surface-variant">Last Policy Check</span>
              <span class="text-sm text-on-surface">
                {format_datetime(@agent.last_policy_check)}
              </span>
            </div>

            <div class="flex justify-between">
              <span class="text-sm font-medium text-on-surface-variant">Secrets Accessed</span>
              <span class="text-sm text-on-surface">{@agent.secrets_accessed}</span>
            </div>
          </div>
        </div>
      </div>
      
    <!-- Recent Activity -->
      <div class="mt-6">
        <h4 class="text-lg font-medium text-on-surface mb-4">Recent Activity</h4>
        <div class="bg-surface-container-low rounded-lg p-4">
          <div class="space-y-3">
            <%= for activity <- recent_activities(@agent.id) do %>
              <div class="flex items-start space-x-3">
                <div class={"w-2 h-2 rounded-full mt-2 #{activity_icon_color(activity.type)}"}></div>
                <div class="flex-1">
                  <div class="text-sm text-on-surface">{activity.description}</div>
                  <div class="text-xs text-on-surface-variant">
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
        <h4 class="text-lg font-medium text-on-surface mb-4">Agent Actions</h4>
        <div class="flex space-x-4">
          <button
            phx-click="restart_agent"
            phx-value-id={@agent.id}
            phx-target={@myself}
            class="btn btn-secondary"
            phx-confirm="Are you sure you want to restart this agent?"
          >
            Restart Agent
          </button>

          <button
            phx-click="disconnect_agent"
            phx-value-id={@agent.id}
            phx-target={@myself}
            class="btn btn-danger"
            phx-confirm="Are you sure you want to disconnect this agent?"
          >
            Force Disconnect
          </button>

          <button class="btn btn-secondary">
            Download Logs
          </button>

          <button class="btn btn-secondary">
            View Configuration
          </button>

          <button
            id="remove-agent-action"
            phx-click="show_remove_agent_modal"
            phx-value-id={@agent.id}
            phx-target={@myself}
            class="btn btn-danger"
          >
            Remove Agent
          </button>
        </div>
      </div>

      <%= if @show_remove_modal do %>
        <div class="fixed inset-0 bg-surface-container-low0 bg-opacity-75 z-50 flex items-center justify-center p-4">
          <div class="bg-surface-container rounded-lg shadow-xl max-w-2xl w-full">
            <div class="px-6 py-4 border-b border-outline-variant">
              <h3 class="text-lg font-medium text-error">Remove Agent</h3>
            </div>

            <form
              phx-submit="confirm_remove_agent"
              phx-target={@myself}
              class="px-6 py-4 space-y-4"
            >
              <p class="text-sm text-on-surface">
                Removing {@agent.name} permanently deletes the agent registration and disconnects the agent from SecretHub Core.
              </p>
              <p class="text-sm text-on-surface-variant">
                Type this exact text to continue:
              </p>
              <pre class="bg-surface-container-low p-3 rounded-md text-xs font-mono border border-outline-variant whitespace-pre-wrap">{@remove_confirmation_text}</pre>
              <input
                type="text"
                name="remove[confirmation]"
                autocomplete="off"
                class="input block w-full border border-outline-variant rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-error focus:border-error sm:text-sm"
              />

              <%= if !Enum.empty?(@remove_validation_errors) do %>
                <div class="bg-error/5 border-l-4 border-error p-4">
                  <ul class="text-sm text-error list-disc list-inside">
                    <%= for error <- @remove_validation_errors do %>
                      <li>{error}</li>
                    <% end %>
                  </ul>
                </div>
              <% end %>

              <div class="flex justify-end space-x-3 pt-4">
                <button
                  type="button"
                  phx-click="cancel_remove_agent"
                  phx-target={@myself}
                  class="btn btn-secondary"
                >
                  Cancel
                </button>
                <button type="submit" class="btn btn-danger">
                  Remove Agent
                </button>
              </div>
            </form>
          </div>
        </div>
      <% end %>
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

  @impl true
  def handle_event("show_remove_agent_modal", _params, socket) do
    socket =
      socket
      |> assign(:show_remove_modal, true)
      |> assign(:remove_validation_errors, [])

    {:noreply, socket}
  end

  @impl true
  def handle_event("cancel_remove_agent", _params, socket) do
    socket =
      socket
      |> assign(:show_remove_modal, false)
      |> assign(:remove_validation_errors, [])

    {:noreply, socket}
  end

  @impl true
  def handle_event(
        "confirm_remove_agent",
        %{"remove" => %{"confirmation" => @remove_confirmation_text}},
        socket
      ) do
    agent_id = socket.assigns.agent.id
    Logger.info("Removing agent: #{agent_id}")
    send(self(), {:remove_agent, agent_id})

    socket =
      socket
      |> assign(:show_remove_modal, false)
      |> assign(:remove_validation_errors, [])

    {:noreply, socket}
  end

  @impl true
  def handle_event("confirm_remove_agent", _params, socket) do
    socket =
      socket
      |> assign(:remove_validation_errors, ["Confirmation text does not match"])

    {:noreply, socket}
  end

  # Helper functions
  defp status_badge_color(:connected), do: "bg-success/10 text-success"
  defp status_badge_color(:disconnected), do: "bg-surface-container text-on-surface"
  defp status_badge_color(:error), do: "bg-error/10 text-error"

  defp format_datetime(nil), do: "Never"

  defp format_datetime(datetime) do
    DateTime.to_string(datetime)
  end

  defp format_uptime(nil), do: "Offline"
  defp format_uptime(hours) when hours < 1, do: "< 1 hour"
  defp format_uptime(hours) when hours < 24, do: "#{Float.round(hours, 1)} hours"
  defp format_uptime(hours) when hours < 168, do: "#{Float.round(hours / 24, 1)} days"
  defp format_uptime(hours), do: "#{Float.round(hours / 168, 1)} weeks"

  defp activity_icon_color("secret_access"), do: "bg-primary text-primary-content"
  defp activity_icon_color("policy_check"), do: "bg-success"
  defp activity_icon_color("error"), do: "bg-error text-error-content"
  defp activity_icon_color("connection"), do: "bg-warning"
  defp activity_icon_color(_), do: "bg-surface-container-low0"

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
