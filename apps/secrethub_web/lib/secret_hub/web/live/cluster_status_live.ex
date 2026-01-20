defmodule SecretHub.Web.ClusterStatusLive do
  @moduledoc """
  LiveView for cluster status dashboard showing all SecretHub Core nodes.

  Displays:
  - All cluster nodes and their current status
  - Health check status for each node
  - Seal state (sealed/unsealed)
  - Active/standby (leader) designation
  - Real-time updates every 5 seconds
  """

  use SecretHub.Web, :live_view
  require Logger
  alias SecretHub.Core.{ClusterState, Health}

  @refresh_interval 5_000

  @impl true
  def mount(_params, _session, socket) do
    # Load initial cluster state
    if connected?(socket) do
      schedule_refresh()
    end

    socket =
      socket
      |> assign(:loading, true)
      |> assign(:auto_refresh, true)
      |> assign(:last_refresh, DateTime.utc_now())
      |> load_cluster_data()

    {:ok, socket}
  end

  @impl true
  def handle_info(:refresh, socket) do
    if socket.assigns.auto_refresh do
      schedule_refresh()
    end

    socket =
      socket
      |> assign(:last_refresh, DateTime.utc_now())
      |> load_cluster_data()

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
  def handle_event("refresh_now", _params, socket) do
    socket =
      socket
      |> assign(:last_refresh, DateTime.utc_now())
      |> load_cluster_data()

    {:noreply, socket}
  end

  # Private helpers

  defp schedule_refresh do
    Process.send_after(self(), :refresh, @refresh_interval)
  end

  defp load_cluster_data(socket) do
    case ClusterState.cluster_info() do
      {:ok, cluster_info} ->
        # Get health status for overall cluster
        health_status = Health.health(details: true)

        socket
        |> assign(:loading, false)
        |> assign(:cluster_info, cluster_info)
        |> assign(:health_status, health_status)
        |> assign(:error, nil)

      {:error, reason} ->
        Logger.error("Failed to load cluster info: #{inspect(reason)}")

        socket
        |> assign(:loading, false)
        |> assign(:cluster_info, nil)
        |> assign(:health_status, nil)
        |> assign(:error, "Failed to load cluster data: #{inspect(reason)}")
    end
  end

  defp node_status_badge(status) do
    case status do
      "unsealed" -> {"bg-green-100 text-green-800", "Unsealed"}
      "sealed" -> {"bg-yellow-100 text-yellow-800", "Sealed"}
      "initializing" -> {"bg-blue-100 text-blue-800", "Initializing"}
      "starting" -> {"bg-gray-100 text-gray-800", "Starting"}
      "shutdown" -> {"bg-red-100 text-red-800", "Shutdown"}
      _ -> {"bg-gray-100 text-gray-800", status}
    end
  end

  defp health_badge(:healthy), do: {"bg-green-100 text-green-800", "Healthy"}
  defp health_badge(:degraded), do: {"bg-yellow-100 text-yellow-800", "Degraded"}
  defp health_badge(:unhealthy), do: {"bg-red-100 text-red-800", "Unhealthy"}
  defp health_badge(_), do: {"bg-gray-100 text-gray-800", "Unknown"}

  defp format_timestamp(nil), do: "Never"

  defp format_timestamp(timestamp) do
    diff = DateTime.diff(DateTime.utc_now(), timestamp, :second)

    cond do
      diff < 60 -> "#{diff}s ago"
      diff < 3600 -> "#{div(diff, 60)}m ago"
      diff < 86400 -> "#{div(diff, 3600)}h ago"
      true -> "#{div(diff, 86400)}d ago"
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="p-6">
      <!-- Header -->
      <div class="mb-6">
        <div class="flex items-center justify-between">
          <div>
            <h1 class="text-3xl font-bold text-gray-900">Cluster Status</h1>
            <p class="mt-2 text-sm text-gray-600">
              Monitor the status and health of all SecretHub Core nodes in your cluster
            </p>
          </div>
          <div class="flex items-center space-x-3">
            <button
              phx-click="refresh_now"
              class="inline-flex items-center px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
            >
              <svg
                class="h-4 w-4 mr-2"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
                xmlns="http://www.w3.org/2000/svg"
              >
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width="2"
                  d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
                />
              </svg>
              Refresh Now
            </button>
            <button
              phx-click="toggle_refresh"
              class={[
                "inline-flex items-center px-4 py-2 border rounded-md shadow-sm text-sm font-medium focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500",
                if(@auto_refresh,
                  do: "border-blue-600 text-blue-700 bg-blue-50 hover:bg-blue-100",
                  else: "border-gray-300 text-gray-700 bg-white hover:bg-gray-50"
                )
              ]}
            >
              <%= if @auto_refresh do %>
                <svg
                  class="h-4 w-4 mr-2 animate-spin"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <path
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    stroke-width="2"
                    d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
                  />
                </svg>
                Auto-refresh ON
              <% else %>
                Auto-refresh OFF
              <% end %>
            </button>
          </div>
        </div>
        
    <!-- Last refresh time -->
        <div class="mt-2 text-xs text-gray-500">
          Last updated: {format_timestamp(@last_refresh)}
        </div>
      </div>

      <%= if @error do %>
        <!-- Error state -->
        <div class="rounded-md bg-red-50 p-4">
          <div class="flex">
            <div class="flex-shrink-0">
              <svg
                class="h-5 w-5 text-red-400"
                fill="currentColor"
                viewBox="0 0 20 20"
                xmlns="http://www.w3.org/2000/svg"
              >
                <path
                  fill-rule="evenodd"
                  d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z"
                  clip-rule="evenodd"
                />
              </svg>
            </div>
            <div class="ml-3">
              <h3 class="text-sm font-medium text-red-800">Error loading cluster data</h3>
              <p class="mt-2 text-sm text-red-700">{@error}</p>
            </div>
          </div>
        </div>
      <% else %>
        <%= if @loading do %>
          <!-- Loading state -->
          <div class="text-center py-12">
            <svg
              class="animate-spin h-12 w-12 mx-auto text-blue-600"
              fill="none"
              viewBox="0 0 24 24"
              xmlns="http://www.w3.org/2000/svg"
            >
              <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4">
              </circle>
              <path
                class="opacity-75"
                fill="currentColor"
                d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
              />
            </svg>
            <p class="mt-4 text-gray-600">Loading cluster data...</p>
          </div>
        <% else %>
          <%= if @cluster_info do %>
            <!-- Cluster overview cards -->
            <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
              <div class="bg-white rounded-lg shadow p-6">
                <div class="text-sm font-medium text-gray-500 uppercase">Total Nodes</div>
                <div class="mt-2 text-3xl font-bold text-gray-900">
                  {@cluster_info.node_count}
                </div>
              </div>

              <div class="bg-white rounded-lg shadow p-6">
                <div class="text-sm font-medium text-gray-500 uppercase">Unsealed</div>
                <div class="mt-2 text-3xl font-bold text-green-600">
                  {@cluster_info.unsealed_count}
                </div>
              </div>

              <div class="bg-white rounded-lg shadow p-6">
                <div class="text-sm font-medium text-gray-500 uppercase">Sealed</div>
                <div class="mt-2 text-3xl font-bold text-yellow-600">
                  {@cluster_info.sealed_count}
                </div>
              </div>

              <div class="bg-white rounded-lg shadow p-6">
                <div class="text-sm font-medium text-gray-500 uppercase">Initialized</div>
                <div class="mt-2 text-3xl font-bold">
                  <span class={
                    if @cluster_info.initialized, do: "text-green-600", else: "text-gray-400"
                  }>
                    {if @cluster_info.initialized, do: "Yes", else: "No"}
                  </span>
                </div>
              </div>
            </div>
            
    <!-- Quick Actions -->
            <div class="mb-6 bg-white rounded-lg shadow p-6">
              <h3 class="text-lg font-semibold text-gray-900 mb-4">Cluster Management</h3>
              <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                <.link
                  navigate={~p"/admin/cluster/alerts"}
                  class="flex items-center justify-between p-4 border border-gray-200 rounded-lg hover:bg-gray-50 transition"
                >
                  <div class="flex items-center">
                    <svg
                      class="h-8 w-8 text-blue-600 mr-3"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                      xmlns="http://www.w3.org/2000/svg"
                    >
                      <path
                        stroke-linecap="round"
                        stroke-linejoin="round"
                        stroke-width="2"
                        d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"
                      />
                    </svg>
                    <div>
                      <div class="text-sm font-medium text-gray-900">Health Alerts</div>
                      <div class="text-xs text-gray-500">Configure monitoring alerts</div>
                    </div>
                  </div>
                  <svg
                    class="h-5 w-5 text-gray-400"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                    xmlns="http://www.w3.org/2000/svg"
                  >
                    <path
                      stroke-linecap="round"
                      stroke-linejoin="round"
                      stroke-width="2"
                      d="M9 5l7 7-7 7"
                    />
                  </svg>
                </.link>

                <.link
                  navigate={~p"/admin/cluster/auto-unseal"}
                  class="flex items-center justify-between p-4 border border-gray-200 rounded-lg hover:bg-gray-50 transition"
                >
                  <div class="flex items-center">
                    <svg
                      class="h-8 w-8 text-green-600 mr-3"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                      xmlns="http://www.w3.org/2000/svg"
                    >
                      <path
                        stroke-linecap="round"
                        stroke-linejoin="round"
                        stroke-width="2"
                        d="M8 11V7a4 4 0 118 0m-4 8v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2z"
                      />
                    </svg>
                    <div>
                      <div class="text-sm font-medium text-gray-900">Auto-Unseal</div>
                      <div class="text-xs text-gray-500">Manage automatic unsealing</div>
                    </div>
                  </div>
                  <svg
                    class="h-5 w-5 text-gray-400"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                    xmlns="http://www.w3.org/2000/svg"
                  >
                    <path
                      stroke-linecap="round"
                      stroke-linejoin="round"
                      stroke-width="2"
                      d="M9 5l7 7-7 7"
                    />
                  </svg>
                </.link>

                <.link
                  navigate={~p"/admin/cluster/deployment"}
                  class="flex items-center justify-between p-4 border border-gray-200 rounded-lg hover:bg-gray-50 transition"
                >
                  <div class="flex items-center">
                    <svg
                      class="h-8 w-8 text-purple-600 mr-3"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                      xmlns="http://www.w3.org/2000/svg"
                    >
                      <path
                        stroke-linecap="round"
                        stroke-linejoin="round"
                        stroke-width="2"
                        d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"
                      />
                    </svg>
                    <div>
                      <div class="text-sm font-medium text-gray-900">Deployment</div>
                      <div class="text-xs text-gray-500">View Kubernetes status</div>
                    </div>
                  </div>
                  <svg
                    class="h-5 w-5 text-gray-400"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                    xmlns="http://www.w3.org/2000/svg"
                  >
                    <path
                      stroke-linecap="round"
                      stroke-linejoin="round"
                      stroke-width="2"
                      d="M9 5l7 7-7 7"
                    />
                  </svg>
                </.link>
              </div>
            </div>
            
    <!-- Overall health status -->
            <%= if @health_status do %>
              <div class="mb-6 bg-white rounded-lg shadow p-6">
                <h3 class="text-lg font-semibold text-gray-900 mb-4">Overall Health</h3>
                <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div>
                    <div class="text-sm text-gray-500">Status</div>
                    <div class="mt-1">
                      <span class={
                        "px-2 py-1 text-xs font-semibold rounded-full #{elem(health_badge(@health_status.status), 0)}"
                      }>
                        {elem(health_badge(@health_status.status), 1)}
                      </span>
                    </div>
                  </div>
                  <div>
                    <div class="text-sm text-gray-500">Initialized</div>
                    <div class="mt-1 text-sm font-medium">
                      {if @health_status.initialized, do: "Yes", else: "No"}
                    </div>
                  </div>
                  <div>
                    <div class="text-sm text-gray-500">Sealed</div>
                    <div class="mt-1 text-sm font-medium">
                      {if @health_status.sealed, do: "Yes", else: "No"}
                    </div>
                  </div>
                </div>
              </div>
            <% end %>
            
    <!-- Nodes table -->
            <div class="bg-white rounded-lg shadow overflow-hidden">
              <div class="px-6 py-4 border-b border-gray-200">
                <h3 class="text-lg font-semibold text-gray-900">Cluster Nodes</h3>
              </div>

              <%= if Enum.empty?(@cluster_info.nodes) do %>
                <div class="p-6 text-center text-gray-500">
                  No nodes registered in the cluster
                </div>
              <% else %>
                <div class="overflow-x-auto">
                  <table class="min-w-full divide-y divide-gray-200">
                    <thead class="bg-gray-50">
                      <tr>
                        <th
                          scope="col"
                          class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
                        >
                          Node
                        </th>
                        <th
                          scope="col"
                          class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
                        >
                          Status
                        </th>
                        <th
                          scope="col"
                          class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
                        >
                          Seal State
                        </th>
                        <th
                          scope="col"
                          class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
                        >
                          Role
                        </th>
                        <th
                          scope="col"
                          class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
                        >
                          Last Seen
                        </th>
                        <th
                          scope="col"
                          class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
                        >
                          Uptime
                        </th>
                        <th
                          scope="col"
                          class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
                        >
                          Version
                        </th>
                        <th
                          scope="col"
                          class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
                        >
                          Health
                        </th>
                        <th
                          scope="col"
                          class="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider"
                        >
                          Actions
                        </th>
                      </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200">
                      <%= for node <- @cluster_info.nodes do %>
                        <tr class="hover:bg-gray-50">
                          <td class="px-6 py-4 whitespace-nowrap">
                            <div class="flex items-center">
                              <div class="flex-shrink-0 h-10 w-10">
                                <div class="h-10 w-10 rounded-full bg-blue-100 flex items-center justify-center">
                                  <svg
                                    class="h-6 w-6 text-blue-600"
                                    fill="none"
                                    stroke="currentColor"
                                    viewBox="0 0 24 24"
                                    xmlns="http://www.w3.org/2000/svg"
                                  >
                                    <path
                                      stroke-linecap="round"
                                      stroke-linejoin="round"
                                      stroke-width="2"
                                      d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01"
                                    />
                                  </svg>
                                </div>
                              </div>
                              <div class="ml-4">
                                <div class="text-sm font-medium text-gray-900">
                                  {Map.get(node, :hostname, "Unknown")}
                                </div>
                                <div class="text-sm text-gray-500">
                                  {Map.get(node, :node_id, "N/A")}
                                </div>
                              </div>
                            </div>
                          </td>
                          <td class="px-6 py-4 whitespace-nowrap">
                            <span class={
                              "px-2 inline-flex text-xs leading-5 font-semibold rounded-full #{elem(node_status_badge(Map.get(node, :status, "unknown")), 0)}"
                            }>
                              {elem(node_status_badge(Map.get(node, :status, "unknown")), 1)}
                            </span>
                          </td>
                          <td class="px-6 py-4 whitespace-nowrap">
                            <%= if Map.get(node, :sealed, true) do %>
                              <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-yellow-100 text-yellow-800">
                                Sealed
                              </span>
                            <% else %>
                              <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">
                                Unsealed
                              </span>
                            <% end %>
                          </td>
                          <td class="px-6 py-4 whitespace-nowrap">
                            <%= if Map.get(node, :leader, false) do %>
                              <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-purple-100 text-purple-800">
                                Leader
                              </span>
                            <% else %>
                              <span class="text-sm text-gray-500">Standby</span>
                            <% end %>
                          </td>
                          <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                            {format_timestamp(Map.get(node, :last_seen_at))}
                          </td>
                          <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                            <%= if Map.get(node, :started_at) do %>
                              {format_timestamp(Map.get(node, :started_at))}
                            <% else %>
                              N/A
                            <% end %>
                          </td>
                          <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                            {Map.get(node, :version, "N/A")}
                          </td>
                          <td class="px-6 py-4 whitespace-nowrap">
                            <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">
                              Monitoring
                            </span>
                          </td>
                          <td class="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                            <.link
                              navigate={~p"/admin/cluster/nodes/#{Map.get(node, :node_id)}"}
                              class="text-blue-600 hover:text-blue-900"
                            >
                              View Details
                            </.link>
                          </td>
                        </tr>
                      <% end %>
                    </tbody>
                  </table>
                </div>
              <% end %>
            </div>
          <% else %>
            <!-- No data state -->
            <div class="text-center py-12 bg-white rounded-lg shadow">
              <svg
                class="h-12 w-12 mx-auto text-gray-400"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
                xmlns="http://www.w3.org/2000/svg"
              >
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width="2"
                  d="M9.172 16.172a4 4 0 015.656 0M9 10h.01M15 10h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
                />
              </svg>
              <p class="mt-4 text-gray-600">No cluster data available</p>
            </div>
          <% end %>
        <% end %>
      <% end %>
    </div>
    """
  end
end
