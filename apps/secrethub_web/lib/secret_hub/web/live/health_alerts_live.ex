defmodule SecretHub.Web.HealthAlertsLive do
  @moduledoc """
  LiveView for managing health alert configurations.

  Displays:
  - List of all configured alerts
  - Enable/disable alerts
  - View alert details
  - (Future: Create/edit/delete alerts)
  """

  use SecretHub.Web, :live_view
  require Logger
  alias SecretHub.Core.HealthAlerts

  @impl true
  def mount(_params, _session, socket) do
    socket =
      socket
      |> assign(:loading, true)
      |> load_alerts()

    {:ok, socket}
  end

  @impl true
  def handle_event("toggle_alert", %{"id" => id}, socket) do
    case HealthAlerts.get_alert(id) do
      {:ok, alert} ->
        result =
          if alert.enabled do
            HealthAlerts.disable_alert(id)
          else
            HealthAlerts.enable_alert(id)
          end

        case result do
          {:ok, _} ->
            {:noreply, load_alerts(socket)}

          {:error, _} ->
            {:noreply, put_flash(socket, :error, "Failed to toggle alert")}
        end

      {:error, _} ->
        {:noreply, put_flash(socket, :error, "Alert not found")}
    end
  end

  @impl true
  def handle_event("refresh", _params, socket) do
    {:noreply, load_alerts(socket)}
  end

  # Private helpers

  defp load_alerts(socket) do
    alerts = HealthAlerts.list_alerts()

    socket
    |> assign(:loading, false)
    |> assign(:alerts, alerts)
    |> assign(:error, nil)
  rescue
    e ->
      Logger.error("Failed to load alerts: #{Exception.message(e)}")

      socket
      |> assign(:loading, false)
      |> assign(:error, "Failed to load alerts")
  end

  defp alert_type_badge(type, assigns \\ %{}) do
    case type do
      "node_down" ->
        ~H"""
        <span class="badge badge-error">Node Down</span>
        """

      "high_cpu" ->
        ~H"""
        <span class="badge badge-warning">High CPU</span>
        """

      "high_memory" ->
        ~H"""
        <span class="badge badge-warning">High Memory</span>
        """

      "database_latency" ->
        ~H"""
        <span class="badge badge-info">DB Latency</span>
        """

      "vault_sealed" ->
        ~H"""
        <span class="badge badge-error">Vault Sealed</span>
        """

      _ ->
        assigns = assign(assigns, :type, type)

        ~H"""
        <span class="badge badge-ghost">{@type}</span>
        """
    end
  end

  defp format_threshold(nil, _), do: "N/A"

  defp format_threshold(value, operator) do
    "#{operator} #{value}"
  end

  defp format_channels([]), do: "None"

  defp format_channels(channels) do
    Enum.join(channels, ", ")
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="container mx-auto p-6">
      <div class="flex justify-between items-center mb-6">
        <div>
          <h1 class="text-3xl font-bold">Health Alerts</h1>
          <p class="text-gray-600 mt-1">Configure and manage health monitoring alerts</p>
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

          <button phx-click="refresh" class="btn btn-primary">
            Refresh
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
      
    <!-- Alerts List -->
      <div class="card bg-base-100 shadow-xl">
        <div class="card-body">
          <%= if Enum.any?(@alerts) do %>
            <div class="overflow-x-auto">
              <table class="table table-zebra">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Type</th>
                    <th>Threshold</th>
                    <th>Cooldown</th>
                    <th>Channels</th>
                    <th>Last Triggered</th>
                    <th>Status</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  <%= for alert <- @alerts do %>
                    <tr>
                      <td class="font-medium">{alert.name}</td>
                      <td>{alert_type_badge(alert.alert_type)}</td>
                      <td class="text-sm">
                        {format_threshold(alert.threshold_value, alert.threshold_operator)}
                      </td>
                      <td class="text-sm">{alert.cooldown_minutes} min</td>
                      <td class="text-sm">{format_channels(alert.notification_channels)}</td>
                      <td class="text-sm">
                        <%= if alert.last_triggered_at do %>
                          {Calendar.strftime(alert.last_triggered_at, "%Y-%m-%d %H:%M")}
                        <% else %>
                          Never
                        <% end %>
                      </td>
                      <td>
                        <%= if alert.enabled do %>
                          <span class="badge badge-success">Enabled</span>
                        <% else %>
                          <span class="badge badge-ghost">Disabled</span>
                        <% end %>
                      </td>
                      <td>
                        <button
                          phx-click="toggle_alert"
                          phx-value-id={alert.id}
                          class="btn btn-sm btn-outline"
                        >
                          {if alert.enabled, do: "Disable", else: "Enable"}
                        </button>
                      </td>
                    </tr>
                  <% end %>
                </tbody>
              </table>
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
              <span>No health alerts configured yet.</span>
            </div>
          <% end %>
        </div>
      </div>
      
    <!-- Info Card -->
      <div class="card bg-base-200 shadow-xl mt-6">
        <div class="card-body">
          <h2 class="card-title">About Health Alerts</h2>
          <p class="text-sm text-gray-600">
            Health alerts monitor node metrics and trigger notifications when thresholds are exceeded.
            Configure alerts to be notified of issues before they impact your system.
          </p>

          <div class="mt-4">
            <h3 class="font-semibold mb-2">Available Alert Types:</h3>
            <ul class="list-disc list-inside text-sm space-y-1">
              <li><strong>Node Down:</strong> Triggers when a node stops sending heartbeats</li>
              <li><strong>High CPU:</strong> Triggers when CPU usage exceeds threshold</li>
              <li><strong>High Memory:</strong> Triggers when memory usage exceeds threshold</li>
              <li><strong>DB Latency:</strong> Triggers when database latency exceeds threshold</li>
              <li><strong>Vault Sealed:</strong> Triggers when vault becomes sealed</li>
            </ul>
          </div>

          <div class="alert alert-warning mt-4">
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
            <span>
              Alert creation UI coming soon. For now, alerts can be configured via the database or API.
            </span>
          </div>
        </div>
      </div>
    </div>
    """
  end
end
