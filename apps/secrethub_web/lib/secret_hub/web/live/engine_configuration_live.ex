defmodule SecretHub.Web.EngineConfigurationLive do
  @moduledoc """
  LiveView for managing dynamic secret engine configurations.

  Displays:
  - List of all engine configurations
  - Enable/disable engines
  - Health status for each engine
  - Quick actions (edit, delete, test connection)
  - Navigation to setup wizards for each engine type
  """

  use SecretHub.Web, :live_view
  require Logger
  alias SecretHub.Core.EngineConfigurations

  @refresh_interval 30_000

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      schedule_refresh()
    end

    socket =
      socket
      |> assign(:loading, true)
      |> assign(:auto_refresh, true)
      |> assign(:delete_modal, nil)
      |> load_configurations()

    {:ok, socket}
  end

  @impl true
  def handle_info(:refresh, socket) do
    if socket.assigns.auto_refresh do
      schedule_refresh()
    end

    {:noreply, load_configurations(socket)}
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
    {:noreply, load_configurations(socket)}
  end

  @impl true
  def handle_event("toggle_engine", %{"id" => id}, socket) do
    case EngineConfigurations.get_configuration(id) do
      {:ok, config} ->
        result =
          if config.enabled do
            EngineConfigurations.disable_configuration(id)
          else
            EngineConfigurations.enable_configuration(id)
          end

        case result do
          {:ok, _} ->
            {:noreply, load_configurations(socket)}

          {:error, _} ->
            {:noreply, put_flash(socket, :error, "Failed to toggle engine")}
        end

      {:error, _} ->
        {:noreply, put_flash(socket, :error, "Engine not found")}
    end
  end

  @impl true
  def handle_event("show_delete_modal", %{"id" => id}, socket) do
    {:noreply, assign(socket, :delete_modal, id)}
  end

  @impl true
  def handle_event("cancel_delete", _params, socket) do
    {:noreply, assign(socket, :delete_modal, nil)}
  end

  @impl true
  def handle_event("confirm_delete", %{"id" => id}, socket) do
    case EngineConfigurations.get_configuration(id) do
      {:ok, config} ->
        case EngineConfigurations.delete_configuration(config) do
          {:ok, _} ->
            socket =
              socket
              |> put_flash(:info, "Engine configuration deleted successfully")
              |> assign(:delete_modal, nil)
              |> load_configurations()

            {:noreply, socket}

          {:error, _} ->
            {:noreply, put_flash(socket, :error, "Failed to delete engine configuration")}
        end

      {:error, _} ->
        {:noreply, put_flash(socket, :error, "Engine configuration not found")}
    end
  end

  @impl true
  def handle_event("run_health_checks", _params, socket) do
    # Run health checks in background
    Task.start(fn ->
      EngineConfigurations.perform_all_health_checks()
    end)

    socket = put_flash(socket, :info, "Health checks started")
    {:noreply, socket}
  end

  # Private helpers

  defp schedule_refresh do
    Process.send_after(self(), :refresh, @refresh_interval)
  end

  defp load_configurations(socket) do
    configurations = EngineConfigurations.list_configurations()

    # Group by engine type for statistics
    by_type =
      configurations
      |> Enum.group_by(& &1.engine_type)
      |> Enum.map(fn {type, configs} -> {type, length(configs)} end)
      |> Map.new()

    stats = %{
      total: length(configurations),
      enabled: Enum.count(configurations, & &1.enabled),
      healthy: Enum.count(configurations, &(&1.health_status == :healthy)),
      by_type: by_type
    }

    socket
    |> assign(:loading, false)
    |> assign(:configurations, configurations)
    |> assign(:stats, stats)
    |> assign(:error, nil)
  rescue
    e ->
      Logger.error("Failed to load engine configurations: #{Exception.message(e)}")

      socket
      |> assign(:loading, false)
      |> assign(:error, "Failed to load engine configurations")
  end

  defp engine_type_badge(type, assigns \\ %{}) do
    case type do
      :postgresql ->
        ~H"""
        <span class="badge badge-primary">PostgreSQL</span>
        """

      :redis ->
        ~H"""
        <span class="badge badge-warning">Redis</span>
        """

      :aws_sts ->
        ~H"""
        <span class="badge badge-info">AWS STS</span>
        """

      _ ->
        assigns = assign(assigns, :type, type)

        ~H"""
        <span class="badge badge-ghost">{to_string(@type)}</span>
        """
    end
  end

  defp health_status_badge(status, assigns \\ %{}) do
    case status do
      :healthy ->
        ~H"""
        <span class="badge badge-success">Healthy</span>
        """

      :degraded ->
        ~H"""
        <span class="badge badge-warning">Degraded</span>
        """

      :unhealthy ->
        ~H"""
        <span class="badge badge-error">Unhealthy</span>
        """

      :unknown ->
        ~H"""
        <span class="badge badge-ghost">Unknown</span>
        """

      _ ->
        assigns = assign(assigns, :status, status)

        ~H"""
        <span class="badge badge-ghost">{to_string(@status)}</span>
        """
    end
  end

  defp format_timestamp(nil), do: "Never"

  defp format_timestamp(timestamp) do
    diff = DateTime.diff(DateTime.utc_now() |> DateTime.truncate(:second), timestamp, :second)

    cond do
      diff < 60 -> "#{diff}s ago"
      diff < 3600 -> "#{div(diff, 60)}m ago"
      diff < 86_400 -> "#{div(diff, 3600)}h ago"
      true -> "#{div(diff, 86_400)}d ago"
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="container mx-auto p-6">
      <div class="flex justify-between items-center mb-6">
        <div>
          <h1 class="text-3xl font-bold">Dynamic Secret Engines</h1>
          <p class="text-gray-600 mt-1">Configure and manage secret engine backends</p>
        </div>

        <div class="flex gap-2">
          <.link navigate={~p"/admin/dashboard"} class="btn btn-outline">
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
            Back to Dashboard
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
      
    <!-- Statistics Cards -->
      <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <div class="stat bg-base-100 shadow rounded-lg">
          <div class="stat-title">Total Engines</div>
          <div class="stat-value text-3xl">{@stats.total}</div>
          <div class="stat-desc">Configured backends</div>
        </div>

        <div class="stat bg-base-100 shadow rounded-lg">
          <div class="stat-title">Enabled</div>
          <div class="stat-value text-3xl text-green-600">{@stats.enabled}</div>
          <div class="stat-desc">Active engines</div>
        </div>

        <div class="stat bg-base-100 shadow rounded-lg">
          <div class="stat-title">Healthy</div>
          <div class="stat-value text-3xl text-blue-600">{@stats.healthy}</div>
          <div class="stat-desc">Passing health checks</div>
        </div>

        <div class="stat bg-base-100 shadow rounded-lg">
          <div class="stat-title">By Type</div>
          <div class="stat-value text-sm">
            <%= for {type, count} <- @stats.by_type do %>
              <div class="text-xs">
                {String.capitalize(to_string(type))}: {count}
              </div>
            <% end %>
          </div>
          <div class="stat-desc">Engine distribution</div>
        </div>
      </div>
      
    <!-- Quick Actions -->
      <div class="mb-6 bg-base-100 shadow rounded-lg p-6">
        <h3 class="text-lg font-semibold mb-4">Quick Actions</h3>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
          <.link
            navigate={~p"/admin/engines/new/redis"}
            class="flex items-center justify-between p-4 border border-gray-200 rounded-lg hover:bg-gray-50 transition"
          >
            <div class="flex items-center">
              <svg
                class="h-8 w-8 text-red-600 mr-3"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
                xmlns="http://www.w3.org/2000/svg"
              >
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width="2"
                  d="M12 4v16m8-8H4"
                />
              </svg>
              <div>
                <div class="text-sm font-medium text-gray-900">Add Redis Engine</div>
                <div class="text-xs text-gray-500">Dynamic ACL users</div>
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
            navigate={~p"/admin/engines/new/aws"}
            class="flex items-center justify-between p-4 border border-gray-200 rounded-lg hover:bg-gray-50 transition"
          >
            <div class="flex items-center">
              <svg
                class="h-8 w-8 text-orange-600 mr-3"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
                xmlns="http://www.w3.org/2000/svg"
              >
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width="2"
                  d="M12 4v16m8-8H4"
                />
              </svg>
              <div>
                <div class="text-sm font-medium text-gray-900">Add AWS Engine</div>
                <div class="text-xs text-gray-500">STS temporary credentials</div>
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

          <button
            phx-click="run_health_checks"
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
                  d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
                />
              </svg>
              <div>
                <div class="text-sm font-medium text-gray-900">Run Health Checks</div>
                <div class="text-xs text-gray-500">Test all engines</div>
              </div>
            </div>
          </button>
        </div>
      </div>
      
    <!-- Engines List -->
      <div class="card bg-base-100 shadow-xl">
        <div class="card-body">
          <h2 class="card-title">Configured Engines</h2>

          <%= if Enum.any?(@configurations) do %>
            <div class="overflow-x-auto mt-4">
              <table class="table table-zebra">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Type</th>
                    <th>Description</th>
                    <th>Health Status</th>
                    <th>Last Check</th>
                    <th>Status</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  <%= for config <- @configurations do %>
                    <tr>
                      <td class="font-medium">{config.name}</td>
                      <td>{engine_type_badge(config.engine_type)}</td>
                      <td class="text-sm">{config.description || "-"}</td>
                      <td>{health_status_badge(config.health_status)}</td>
                      <td class="text-sm">{format_timestamp(config.last_health_check_at)}</td>
                      <td>
                        <%= if config.enabled do %>
                          <span class="badge badge-success">Enabled</span>
                        <% else %>
                          <span class="badge badge-ghost">Disabled</span>
                        <% end %>
                      </td>
                      <td>
                        <div class="flex gap-2">
                          <.link
                            navigate={~p"/admin/engines/#{config.id}/health"}
                            class="btn btn-sm btn-info btn-outline"
                          >
                            Health
                          </.link>
                          <button
                            phx-click="toggle_engine"
                            phx-value-id={config.id}
                            class="btn btn-sm btn-outline"
                          >
                            {if config.enabled, do: "Disable", else: "Enable"}
                          </button>
                          <button
                            phx-click="show_delete_modal"
                            phx-value-id={config.id}
                            class="btn btn-sm btn-error btn-outline"
                          >
                            Delete
                          </button>
                        </div>
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
              <span>
                No engine configurations yet. Add your first engine using the quick actions above.
              </span>
            </div>
          <% end %>
        </div>
      </div>
      
    <!-- Delete Confirmation Modal -->
      <%= if @delete_modal do %>
        <div class="modal modal-open">
          <div class="modal-box">
            <h3 class="font-bold text-lg">Confirm Delete</h3>
            <p class="py-4">
              Are you sure you want to delete this engine configuration? This action cannot be undone.
            </p>

            <div class="modal-action">
              <button phx-click="cancel_delete" class="btn">Cancel</button>
              <button phx-click="confirm_delete" phx-value-id={@delete_modal} class="btn btn-error">
                Delete
              </button>
            </div>
          </div>
        </div>
      <% end %>
    </div>
    """
  end
end
