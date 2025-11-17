defmodule SecretHub.WebWeb.RotationHistoryLive do
  @moduledoc """
  LiveView for viewing rotation history and statistics.

  Displays detailed rotation history for a specific schedule, including
  success/failure status, duration, version information, and allows
  manual rotation triggers.
  """

  use SecretHub.WebWeb, :live_view

  alias SecretHub.Core.RotationManager
  alias SecretHub.Core.Workers.RotationWorker

  @impl true
  def mount(%{"id" => schedule_id}, _session, socket) do
    case RotationManager.get_schedule(schedule_id) do
      {:ok, schedule} ->
        if connected?(socket) do
          # Auto-refresh every 10 seconds
          Process.send_after(self(), :refresh, 10_000)

          history = RotationManager.list_history(schedule_id, limit: 50)
          stats = RotationManager.get_rotation_stats(schedule_id)

          {:ok,
           socket
           |> assign(:schedule, schedule)
           |> assign(:history, history)
           |> assign(:stats, stats)
           |> assign(:page_title, "Rotation History - #{schedule.name}")}
        else
          {:ok,
           socket
           |> assign(:schedule, schedule)
           |> assign(:history, [])
           |> assign(:stats, %{})
           |> assign(:page_title, "Rotation History")}
        end

      {:error, :not_found} ->
        {:ok,
         socket
         |> put_flash(:error, "Rotation schedule not found")
         |> push_navigate(to: ~p"/admin/rotations")}
    end
  end

  @impl true
  def handle_info(:refresh, socket) do
    schedule_id = socket.assigns.schedule.id

    history = RotationManager.list_history(schedule_id, limit: 50)
    stats = RotationManager.get_rotation_stats(schedule_id)

    # Schedule next refresh
    Process.send_after(self(), :refresh, 10_000)

    {:noreply,
     socket
     |> assign(:history, history)
     |> assign(:stats, stats)}
  end

  @impl true
  def handle_event("trigger_rotation", _params, socket) do
    schedule = socket.assigns.schedule

    unless schedule.enabled do
      {:noreply, put_flash(socket, :error, "Cannot rotate disabled schedule")}
    else
      case RotationWorker.schedule_rotation(schedule) do
        {:ok, _job} ->
          {:noreply,
           socket
           |> put_flash(:info, "Rotation job scheduled successfully")
           |> push_navigate(to: ~p"/admin/rotations/#{schedule.id}/history")}

        {:error, _} ->
          {:noreply, put_flash(socket, :error, "Failed to schedule rotation job")}
      end
    end
  end

  @impl true
  def handle_event("view_details", %{"id" => history_id}, socket) do
    history_record = Enum.find(socket.assigns.history, &(&1.id == history_id))

    if history_record do
      {:noreply, assign(socket, :selected_history, history_record)}
    else
      {:noreply, socket}
    end
  end

  @impl true
  def handle_event("close_details", _params, socket) do
    {:noreply, assign(socket, :selected_history, nil)}
  end

  @impl true
  def handle_event("noop", _params, socket) do
    # No-op event handler to prevent event propagation
    {:noreply, socket}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="px-4 sm:px-6 lg:px-8">
      <div class="sm:flex sm:items-center">
        <div class="sm:flex-auto">
          <h1 class="text-2xl font-semibold text-gray-900">Rotation History</h1>
          <p class="mt-2 text-sm text-gray-700">
            {@schedule.name} - {@schedule.description}
          </p>
        </div>
        <div class="mt-4 sm:mt-0 sm:ml-16 flex gap-2">
          <.link navigate={~p"/admin/rotations/#{@schedule.id}"} class="btn btn-ghost">
            Back to Schedule
          </.link>
          <button phx-click="trigger_rotation" class="btn btn-primary" disabled={!@schedule.enabled}>
            Trigger Rotation Now
          </button>
        </div>
      </div>

      <.statistics_cards stats={@stats} />

      <.history_table history={@history} schedule={@schedule} />

      <%= if assigns[:selected_history] do %>
        <.history_detail_modal history={@selected_history} />
      <% end %>
    </div>
    """
  end

  defp statistics_cards(assigns) do
    ~H"""
    <div class="mt-8 grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4">
      <div class="bg-white overflow-hidden shadow rounded-lg">
        <div class="px-4 py-5 sm:p-6">
          <dt class="text-sm font-medium text-gray-500 truncate">Total Rotations</dt>
          <dd class="mt-1 text-3xl font-semibold text-gray-900">{@stats.total || 0}</dd>
        </div>
      </div>

      <div class="bg-white overflow-hidden shadow rounded-lg">
        <div class="px-4 py-5 sm:p-6">
          <dt class="text-sm font-medium text-gray-500 truncate">Successful</dt>
          <dd class="mt-1 text-3xl font-semibold text-green-600">{@stats.successful || 0}</dd>
        </div>
      </div>

      <div class="bg-white overflow-hidden shadow rounded-lg">
        <div class="px-4 py-5 sm:p-6">
          <dt class="text-sm font-medium text-gray-500 truncate">Failed</dt>
          <dd class="mt-1 text-3xl font-semibold text-red-600">{@stats.failed || 0}</dd>
        </div>
      </div>

      <div class="bg-white overflow-hidden shadow rounded-lg">
        <div class="px-4 py-5 sm:p-6">
          <dt class="text-sm font-medium text-gray-500 truncate">Success Rate</dt>
          <dd class="mt-1 text-3xl font-semibold text-gray-900">
            {Float.round(@stats.success_rate || 0.0, 1)}%
          </dd>
        </div>
      </div>
    </div>
    """
  end

  defp history_table(assigns) do
    ~H"""
    <div class="mt-8 flex flex-col">
      <div class="-my-2 -mx-4 overflow-x-auto sm:-mx-6 lg:-mx-8">
        <div class="inline-block min-w-full py-2 align-middle md:px-6 lg:px-8">
          <div class="overflow-hidden shadow ring-1 ring-black ring-opacity-5 md:rounded-lg">
            <table class="min-w-full divide-y divide-gray-300">
              <thead class="bg-gray-50">
                <tr>
                  <th class="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">Started</th>
                  <th class="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">
                    Completed
                  </th>
                  <th class="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">Status</th>
                  <th class="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">
                    Duration
                  </th>
                  <th class="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">
                    Old Version
                  </th>
                  <th class="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">
                    New Version
                  </th>
                  <th class="relative py-3.5 pl-3 pr-4 sm:pr-6">
                    <span class="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody class="divide-y divide-gray-200 bg-white">
                <%= for record <- @history do %>
                  <tr class="hover:bg-gray-50">
                    <td class="whitespace-nowrap px-3 py-4 text-sm text-gray-900">
                      {Calendar.strftime(record.started_at, "%Y-%m-%d %H:%M:%S")}
                    </td>
                    <td class="whitespace-nowrap px-3 py-4 text-sm text-gray-500">
                      <%= if record.completed_at do %>
                        {Calendar.strftime(record.completed_at, "%Y-%m-%d %H:%M:%S")}
                      <% else %>
                        <span class="text-yellow-600">In Progress...</span>
                      <% end %>
                    </td>
                    <td class="whitespace-nowrap px-3 py-4 text-sm">
                      <.rotation_status_badge status={record.status} />
                      <%= if record.rollback_performed do %>
                        <span class="ml-2 badge badge-warning badge-sm">Rolled Back</span>
                      <% end %>
                    </td>
                    <td class="whitespace-nowrap px-3 py-4 text-sm text-gray-500">
                      <%= if record.duration_ms do %>
                        {format_duration(record.duration_ms)}
                      <% else %>
                        -
                      <% end %>
                    </td>
                    <td class="whitespace-nowrap px-3 py-4 text-sm text-gray-500">
                      <%= if record.old_version do %>
                        <code class="text-xs">{String.slice(record.old_version, 0..20)}</code>
                      <% else %>
                        -
                      <% end %>
                    </td>
                    <td class="whitespace-nowrap px-3 py-4 text-sm text-gray-500">
                      <%= if record.new_version do %>
                        <code class="text-xs">{String.slice(record.new_version, 0..20)}</code>
                      <% else %>
                        -
                      <% end %>
                    </td>
                    <td class="relative whitespace-nowrap py-4 pl-3 pr-4 text-right text-sm font-medium sm:pr-6">
                      <button
                        phx-click="view_details"
                        phx-value-id={record.id}
                        class="text-primary-600 hover:text-primary-900"
                      >
                        Details
                      </button>
                    </td>
                  </tr>
                <% end %>

                <%= if @history == [] do %>
                  <tr>
                    <td colspan="7" class="px-3 py-8 text-center text-sm text-gray-500">
                      No rotation history yet. Trigger a rotation to see results here.
                    </td>
                  </tr>
                <% end %>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
    """
  end

  defp history_detail_modal(assigns) do
    ~H"""
    <div class="fixed inset-0 z-50 overflow-y-auto" phx-click="close_details">
      <div class="flex items-center justify-center min-h-screen px-4 pt-4 pb-20 text-center sm:block sm:p-0">
        <div class="fixed inset-0 transition-opacity bg-gray-500 bg-opacity-75"></div>

        <span class="hidden sm:inline-block sm:align-middle sm:h-screen">&#8203;</span>

        <div
          class="inline-block overflow-hidden text-left align-bottom transition-all transform bg-white rounded-lg shadow-xl sm:my-8 sm:align-middle sm:max-w-2xl sm:w-full"
          phx-click="noop"
        >
          <div class="px-4 pt-5 pb-4 bg-white sm:p-6 sm:pb-4">
            <div class="sm:flex sm:items-start">
              <div class="w-full mt-3 text-center sm:mt-0 sm:text-left">
                <h3 class="text-lg font-medium leading-6 text-gray-900">
                  Rotation Details
                </h3>

                <div class="mt-4">
                  <dl class="divide-y divide-gray-200">
                    <div class="py-3 sm:grid sm:grid-cols-3 sm:gap-4">
                      <dt class="text-sm font-medium text-gray-500">Status</dt>
                      <dd class="mt-1 text-sm text-gray-900 sm:col-span-2 sm:mt-0">
                        <.rotation_status_badge status={@history.status} />
                      </dd>
                    </div>

                    <div class="py-3 sm:grid sm:grid-cols-3 sm:gap-4">
                      <dt class="text-sm font-medium text-gray-500">Started At</dt>
                      <dd class="mt-1 text-sm text-gray-900 sm:col-span-2 sm:mt-0">
                        {Calendar.strftime(@history.started_at, "%Y-%m-%d %H:%M:%S UTC")}
                      </dd>
                    </div>

                    <%= if @history.completed_at do %>
                      <div class="py-3 sm:grid sm:grid-cols-3 sm:gap-4">
                        <dt class="text-sm font-medium text-gray-500">Completed At</dt>
                        <dd class="mt-1 text-sm text-gray-900 sm:col-span-2 sm:mt-0">
                          {Calendar.strftime(@history.completed_at, "%Y-%m-%d %H:%M:%S UTC")}
                        </dd>
                      </div>
                    <% end %>

                    <%= if @history.duration_ms do %>
                      <div class="py-3 sm:grid sm:grid-cols-3 sm:gap-4">
                        <dt class="text-sm font-medium text-gray-500">Duration</dt>
                        <dd class="mt-1 text-sm text-gray-900 sm:col-span-2 sm:mt-0">
                          {format_duration(@history.duration_ms)}
                        </dd>
                      </div>
                    <% end %>

                    <%= if @history.old_version do %>
                      <div class="py-3 sm:grid sm:grid-cols-3 sm:gap-4">
                        <dt class="text-sm font-medium text-gray-500">Old Version</dt>
                        <dd class="mt-1 text-sm text-gray-900 sm:col-span-2 sm:mt-0">
                          <code class="text-xs bg-gray-100 px-2 py-1 rounded">
                            {@history.old_version}
                          </code>
                        </dd>
                      </div>
                    <% end %>

                    <%= if @history.new_version do %>
                      <div class="py-3 sm:grid sm:grid-cols-3 sm:gap-4">
                        <dt class="text-sm font-medium text-gray-500">New Version</dt>
                        <dd class="mt-1 text-sm text-gray-900 sm:col-span-2 sm:mt-0">
                          <code class="text-xs bg-gray-100 px-2 py-1 rounded">
                            {@history.new_version}
                          </code>
                        </dd>
                      </div>
                    <% end %>

                    <%= if @history.error_message do %>
                      <div class="py-3 sm:grid sm:grid-cols-3 sm:gap-4">
                        <dt class="text-sm font-medium text-gray-500">Error</dt>
                        <dd class="mt-1 text-sm text-red-600 sm:col-span-2 sm:mt-0">
                          {@history.error_message}
                        </dd>
                      </div>
                    <% end %>

                    <%= if @history.rollback_performed do %>
                      <div class="py-3 sm:grid sm:grid-cols-3 sm:gap-4">
                        <dt class="text-sm font-medium text-gray-500">Rollback</dt>
                        <dd class="mt-1 text-sm text-gray-900 sm:col-span-2 sm:mt-0">
                          <span class="badge badge-warning">Rollback Performed</span>
                        </dd>
                      </div>
                    <% end %>

                    <%= if @history.metadata && map_size(@history.metadata) > 0 do %>
                      <div class="py-3 sm:grid sm:grid-cols-3 sm:gap-4">
                        <dt class="text-sm font-medium text-gray-500">Metadata</dt>
                        <dd class="mt-1 text-sm text-gray-900 sm:col-span-2 sm:mt-0">
                          <pre class="text-xs bg-gray-50 p-3 rounded overflow-x-auto"><%= Jason.encode!(@history.metadata, pretty: true) %></pre>
                        </dd>
                      </div>
                    <% end %>
                  </dl>
                </div>
              </div>
            </div>
          </div>

          <div class="px-4 py-3 bg-gray-50 sm:px-6 sm:flex sm:flex-row-reverse">
            <button
              type="button"
              phx-click="close_details"
              class="btn btn-primary"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
    """
  end

  defp rotation_status_badge(assigns) do
    color =
      case assigns.status do
        :success -> "badge-success"
        :failed -> "badge-error"
        :in_progress -> "badge-warning"
        :rolled_back -> "badge-warning"
        _ -> "badge-ghost"
      end

    label =
      assigns.status
      |> Atom.to_string()
      |> String.split("_")
      |> Enum.map(&String.capitalize/1)
      |> Enum.join(" ")

    assigns = assign(assigns, :color, color)
    assigns = assign(assigns, :label, label)

    ~H"""
    <span class={"badge #{@color}"}>{@label}</span>
    """
  end

  defp format_duration(ms) when is_integer(ms) do
    cond do
      ms < 1000 -> "#{ms}ms"
      ms < 60_000 -> "#{Float.round(ms / 1000, 1)}s"
      true -> "#{Float.round(ms / 60_000, 1)}m"
    end
  end

  defp format_duration(_), do: "-"
end
