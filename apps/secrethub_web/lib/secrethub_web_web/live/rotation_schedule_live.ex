defmodule SecretHub.WebWeb.RotationScheduleLive do
  @moduledoc """
  LiveView for managing rotation schedules.

  Allows administrators to create, update, and manage automatic secret rotation
  schedules with cron-based timing, grace periods, and configuration.
  """

  use SecretHub.WebWeb, :live_view

  alias SecretHub.Core.RotationManager

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      schedules = RotationManager.list_schedules()

      {:ok,
       socket
       |> assign(:schedules, schedules)
       |> assign(:selected_schedule, nil)
       |> assign(:form_mode, :list)
       |> assign(:page_title, "Rotation Schedules")}
    else
      {:ok,
       socket
       |> assign(:schedules, [])
       |> assign(:selected_schedule, nil)
       |> assign(:form_mode, :list)
       |> assign(:page_title, "Rotation Schedules")}
    end
  end

  @impl true
  def handle_params(params, _url, socket) do
    case params do
      %{"id" => id} ->
        case RotationManager.get_schedule(id) do
          {:ok, schedule} ->
            {:noreply,
             socket
             |> assign(:selected_schedule, schedule)
             |> assign(:form_mode, :view)}

          {:error, :not_found} ->
            {:noreply,
             socket
             |> put_flash(:error, "Rotation schedule not found")
             |> push_navigate(to: ~p"/admin/rotations")}
        end

      %{"new" => "true"} ->
        {:noreply,
         socket
         |> assign(:selected_schedule, nil)
         |> assign(:form_mode, :new)}

      _ ->
        {:noreply, socket}
    end
  end

  @impl true
  def handle_event("new_schedule", _params, socket) do
    {:noreply, push_patch(socket, to: ~p"/admin/rotations?new=true")}
  end

  @impl true
  def handle_event("view_schedule", %{"id" => id}, socket) do
    {:noreply, push_patch(socket, to: ~p"/admin/rotations/#{id}")}
  end

  @impl true
  def handle_event("edit_schedule", %{"id" => id}, socket) do
    case RotationManager.get_schedule(id) do
      {:ok, schedule} ->
        {:noreply,
         socket
         |> assign(:selected_schedule, schedule)
         |> assign(:form_mode, :edit)}

      {:error, :not_found} ->
        {:noreply, put_flash(socket, :error, "Schedule not found")}
    end
  end

  @impl true
  def handle_event("create_schedule", params, socket) do
    attrs = %{
      name: params["name"],
      description: params["description"],
      rotation_type: String.to_existing_atom(params["rotation_type"]),
      target_type: String.to_existing_atom(params["target_type"]),
      config: Jason.decode!(params["config"] || "{}"),
      schedule_cron: params["schedule_cron"],
      grace_period_seconds: String.to_integer(params["grace_period_seconds"] || "300"),
      enabled: params["enabled"] == "true"
    }

    case RotationManager.create_schedule(attrs) do
      {:ok, schedule} ->
        # Calculate and set next rotation time
        RotationManager.update_next_rotation(schedule)

        schedules = RotationManager.list_schedules()

        {:noreply,
         socket
         |> assign(:schedules, schedules)
         |> assign(:form_mode, :list)
         |> put_flash(:info, "Rotation schedule created successfully")
         |> push_navigate(to: ~p"/admin/rotations")}

      {:error, changeset} ->
        errors = format_changeset_errors(changeset)

        {:noreply,
         socket
         |> put_flash(:error, "Failed to create schedule: #{errors}")}
    end
  end

  @impl true
  def handle_event("update_schedule", params, socket) do
    schedule = socket.assigns.selected_schedule

    attrs = %{
      name: params["name"],
      description: params["description"],
      config: Jason.decode!(params["config"] || "{}"),
      schedule_cron: params["schedule_cron"],
      grace_period_seconds: String.to_integer(params["grace_period_seconds"] || "300"),
      enabled: params["enabled"] == "true"
    }

    case RotationManager.update_schedule(schedule, attrs) do
      {:ok, updated_schedule} ->
        # Recalculate next rotation time if cron changed
        if attrs.schedule_cron != schedule.schedule_cron do
          RotationManager.update_next_rotation(updated_schedule)
        end

        schedules = RotationManager.list_schedules()

        {:noreply,
         socket
         |> assign(:schedules, schedules)
         |> assign(:selected_schedule, updated_schedule)
         |> assign(:form_mode, :view)
         |> put_flash(:info, "Rotation schedule updated successfully")}

      {:error, changeset} ->
        errors = format_changeset_errors(changeset)

        {:noreply,
         socket
         |> put_flash(:error, "Failed to update schedule: #{errors}")}
    end
  end

  @impl true
  def handle_event("delete_schedule", %{"id" => id}, socket) do
    case RotationManager.get_schedule(id) do
      {:ok, schedule} ->
        case RotationManager.delete_schedule(schedule) do
          {:ok, _} ->
            schedules = RotationManager.list_schedules()

            {:noreply,
             socket
             |> assign(:schedules, schedules)
             |> assign(:form_mode, :list)
             |> put_flash(:info, "Rotation schedule deleted successfully")
             |> push_navigate(to: ~p"/admin/rotations")}

          {:error, _} ->
            {:noreply, put_flash(socket, :error, "Failed to delete schedule")}
        end

      {:error, :not_found} ->
        {:noreply, put_flash(socket, :error, "Schedule not found")}
    end
  end

  @impl true
  def handle_event("toggle_enabled", %{"id" => id, "enabled" => enabled}, socket) do
    enabled = enabled == "true"

    result =
      if enabled do
        RotationManager.enable_schedule(id)
      else
        RotationManager.disable_schedule(id)
      end

    case result do
      {:ok, _schedule} ->
        schedules = RotationManager.list_schedules()

        {:noreply,
         socket
         |> assign(:schedules, schedules)
         |> put_flash(:info, "Schedule #{if enabled, do: "enabled", else: "disabled"}")}

      {:error, _} ->
        {:noreply, put_flash(socket, :error, "Failed to update schedule")}
    end
  end

  @impl true
  def handle_event("cancel", _params, socket) do
    {:noreply,
     socket
     |> assign(:form_mode, :list)
     |> push_navigate(to: ~p"/admin/rotations")}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="px-4 sm:px-6 lg:px-8">
      <div class="sm:flex sm:items-center">
        <div class="sm:flex-auto">
          <h1 class="text-2xl font-semibold text-gray-900">Rotation Schedules</h1>
          <p class="mt-2 text-sm text-gray-700">
            Manage automatic secret rotation schedules for long-lived credentials.
          </p>
        </div>
        <div class="mt-4 sm:mt-0 sm:ml-16 sm:flex-none">
          <button
            :if={@form_mode == :list}
            phx-click="new_schedule"
            type="button"
            class="btn btn-primary"
          >
            New Schedule
          </button>
        </div>
      </div>

      <%= if @form_mode == :list do %>
        <.schedule_list schedules={@schedules} />
      <% end %>

      <%= if @form_mode == :new do %>
        <.schedule_form mode={:new} schedule={nil} />
      <% end %>

      <%= if @form_mode == :edit do %>
        <.schedule_form mode={:edit} schedule={@selected_schedule} />
      <% end %>

      <%= if @form_mode == :view do %>
        <.schedule_detail schedule={@selected_schedule} />
      <% end %>
    </div>
    """
  end

  defp schedule_list(assigns) do
    ~H"""
    <div class="mt-8 flex flex-col">
      <div class="-my-2 -mx-4 overflow-x-auto sm:-mx-6 lg:-mx-8">
        <div class="inline-block min-w-full py-2 align-middle md:px-6 lg:px-8">
          <div class="overflow-hidden shadow ring-1 ring-black ring-opacity-5 md:rounded-lg">
            <table class="min-w-full divide-y divide-gray-300">
              <thead class="bg-gray-50">
                <tr>
                  <th class="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">Name</th>
                  <th class="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">Type</th>
                  <th class="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">Schedule</th>
                  <th class="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">
                    Next Rotation
                  </th>
                  <th class="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">Status</th>
                  <th class="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">
                    Last Status
                  </th>
                  <th class="relative py-3.5 pl-3 pr-4 sm:pr-6">
                    <span class="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody class="divide-y divide-gray-200 bg-white">
                <%= for schedule <- @schedules do %>
                  <tr class="hover:bg-gray-50">
                    <td class="whitespace-nowrap px-3 py-4 text-sm">
                      <div class="font-medium text-gray-900">{schedule.name}</div>
                      <div class="text-gray-500">{schedule.description}</div>
                    </td>
                    <td class="whitespace-nowrap px-3 py-4 text-sm text-gray-500">
                      <.rotation_type_badge type={schedule.rotation_type} />
                    </td>
                    <td class="whitespace-nowrap px-3 py-4 text-sm text-gray-500">
                      <code class="text-xs">{schedule.schedule_cron}</code>
                    </td>
                    <td class="whitespace-nowrap px-3 py-4 text-sm text-gray-500">
                      <%= if schedule.next_rotation_at do %>
                        {Calendar.strftime(schedule.next_rotation_at, "%Y-%m-%d %H:%M UTC")}
                      <% else %>
                        <span class="text-gray-400">Not scheduled</span>
                      <% end %>
                    </td>
                    <td class="whitespace-nowrap px-3 py-4 text-sm">
                      <.enabled_badge enabled={schedule.enabled} />
                    </td>
                    <td class="whitespace-nowrap px-3 py-4 text-sm">
                      <%= if schedule.last_rotation_status do %>
                        <.rotation_status_badge status={schedule.last_rotation_status} />
                      <% else %>
                        <span class="text-gray-400">Never run</span>
                      <% end %>
                    </td>
                    <td class="relative whitespace-nowrap py-4 pl-3 pr-4 text-right text-sm font-medium sm:pr-6">
                      <button
                        phx-click="view_schedule"
                        phx-value-id={schedule.id}
                        class="text-primary-600 hover:text-primary-900 mr-4"
                      >
                        View
                      </button>
                      <button
                        phx-click="toggle_enabled"
                        phx-value-id={schedule.id}
                        phx-value-enabled={!schedule.enabled}
                        class="text-primary-600 hover:text-primary-900"
                      >
                        {if schedule.enabled, do: "Disable", else: "Enable"}
                      </button>
                    </td>
                  </tr>
                <% end %>

                <%= if @schedules == [] do %>
                  <tr>
                    <td colspan="7" class="px-3 py-8 text-center text-sm text-gray-500">
                      No rotation schedules configured. Click "New Schedule" to create one.
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

  defp schedule_form(assigns) do
    rotation_types = [
      {:database_password, "Database Password"},
      {:aws_iam_key, "AWS IAM Key"},
      {:api_key, "API Key"},
      {:service_account, "Service Account"}
    ]

    target_types = [
      {:database, "Database"},
      {:aws_account, "AWS Account"},
      {:external_service, "External Service"}
    ]

    assigns =
      assigns
      |> assign(:rotation_types, rotation_types)
      |> assign(:target_types, target_types)

    ~H"""
    <div class="mt-8">
      <div class="bg-white shadow sm:rounded-lg">
        <div class="px-4 py-5 sm:p-6">
          <h3 class="text-lg font-medium leading-6 text-gray-900">
            {if @mode == :new, do: "Create Rotation Schedule", else: "Edit Rotation Schedule"}
          </h3>

          <form
            phx-submit={if @mode == :new, do: "create_schedule", else: "update_schedule"}
            class="mt-6 space-y-6"
          >
            <div>
              <label for="name" class="block text-sm font-medium text-gray-700">Name</label>
              <input
                type="text"
                name="name"
                id="name"
                value={if @schedule, do: @schedule.name, else: ""}
                required
                class="input input-bordered w-full mt-1"
                placeholder="e.g., Production DB Password Rotation"
              />
            </div>

            <div>
              <label for="description" class="block text-sm font-medium text-gray-700">
                Description
              </label>
              <textarea
                name="description"
                id="description"
                rows="3"
                class="textarea textarea-bordered w-full mt-1"
                placeholder="Brief description of what this rotation manages"
              ><%= if @schedule, do: @schedule.description, else: "" %></textarea>
            </div>

            <div class="grid grid-cols-1 gap-6 sm:grid-cols-2">
              <div>
                <label for="rotation_type" class="block text-sm font-medium text-gray-700">
                  Rotation Type
                </label>
                <select
                  name="rotation_type"
                  id="rotation_type"
                  required
                  disabled={@mode == :edit}
                  class="select select-bordered w-full mt-1"
                >
                  <%= for {value, label} <- @rotation_types do %>
                    <option
                      value={value}
                      selected={@schedule && @schedule.rotation_type == value}
                    >
                      {label}
                    </option>
                  <% end %>
                </select>
                <%= if @mode == :edit do %>
                  <p class="mt-1 text-sm text-gray-500">Rotation type cannot be changed</p>
                <% end %>
              </div>

              <div>
                <label for="target_type" class="block text-sm font-medium text-gray-700">
                  Target Type
                </label>
                <select
                  name="target_type"
                  id="target_type"
                  required
                  disabled={@mode == :edit}
                  class="select select-bordered w-full mt-1"
                >
                  <%= for {value, label} <- @target_types do %>
                    <option value={value} selected={@schedule && @schedule.target_type == value}>
                      {label}
                    </option>
                  <% end %>
                </select>
              </div>
            </div>

            <div class="grid grid-cols-1 gap-6 sm:grid-cols-2">
              <div>
                <label for="schedule_cron" class="block text-sm font-medium text-gray-700">
                  Cron Schedule
                </label>
                <input
                  type="text"
                  name="schedule_cron"
                  id="schedule_cron"
                  value={if @schedule, do: @schedule.schedule_cron, else: "0 2 * * 0"}
                  required
                  class="input input-bordered w-full mt-1 font-mono text-sm"
                  placeholder="0 2 * * 0"
                />
                <p class="mt-1 text-sm text-gray-500">
                  Example: "0 2 * * 0" = Weekly on Sunday at 2 AM
                </p>
              </div>

              <div>
                <label for="grace_period_seconds" class="block text-sm font-medium text-gray-700">
                  Grace Period (seconds)
                </label>
                <input
                  type="number"
                  name="grace_period_seconds"
                  id="grace_period_seconds"
                  value={if @schedule, do: @schedule.grace_period_seconds, else: 300}
                  required
                  min="0"
                  class="input input-bordered w-full mt-1"
                />
                <p class="mt-1 text-sm text-gray-500">
                  Time window for applications to transition to new credentials
                </p>
              </div>
            </div>

            <div>
              <label for="config" class="block text-sm font-medium text-gray-700">
                Configuration (JSON)
              </label>
              <textarea
                name="config"
                id="config"
                rows="8"
                class="textarea textarea-bordered w-full mt-1 font-mono text-sm"
                placeholder='{"connection": {"host": "localhost", "port": 5432, ...}}'
              ><%= if @schedule, do: Jason.encode!(@schedule.config, pretty: true), else: "{}" %></textarea>
              <p class="mt-1 text-sm text-gray-500">
                Engine-specific configuration in JSON format
              </p>
            </div>

            <div class="flex items-center">
              <input
                type="checkbox"
                name="enabled"
                id="enabled"
                value="true"
                checked={!@schedule || @schedule.enabled}
                class="checkbox checkbox-primary"
              />
              <label for="enabled" class="ml-2 block text-sm text-gray-900">
                Enable schedule immediately
              </label>
            </div>

            <div class="flex justify-end gap-3">
              <button type="button" phx-click="cancel" class="btn btn-ghost">
                Cancel
              </button>
              <button type="submit" class="btn btn-primary">
                {if @mode == :new, do: "Create Schedule", else: "Update Schedule"}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
    """
  end

  defp schedule_detail(assigns) do
    ~H"""
    <div class="mt-8">
      <div class="bg-white shadow sm:rounded-lg">
        <div class="px-4 py-5 sm:p-6">
          <div class="sm:flex sm:items-center sm:justify-between">
            <div>
              <h3 class="text-lg font-medium leading-6 text-gray-900">{@schedule.name}</h3>
              <p class="mt-1 text-sm text-gray-500">{@schedule.description}</p>
            </div>
            <div class="mt-4 sm:mt-0 flex gap-2">
              <button
                phx-click="edit_schedule"
                phx-value-id={@schedule.id}
                class="btn btn-sm btn-outline"
              >
                Edit
              </button>
              <button
                phx-click="delete_schedule"
                phx-value-id={@schedule.id}
                data-confirm="Are you sure you want to delete this rotation schedule?"
                class="btn btn-sm btn-error btn-outline"
              >
                Delete
              </button>
            </div>
          </div>

          <div class="mt-6 border-t border-gray-200">
            <dl class="divide-y divide-gray-200">
              <div class="py-4 sm:grid sm:grid-cols-3 sm:gap-4">
                <dt class="text-sm font-medium text-gray-500">Rotation Type</dt>
                <dd class="mt-1 text-sm text-gray-900 sm:col-span-2 sm:mt-0">
                  <.rotation_type_badge type={@schedule.rotation_type} />
                </dd>
              </div>

              <div class="py-4 sm:grid sm:grid-cols-3 sm:gap-4">
                <dt class="text-sm font-medium text-gray-500">Target Type</dt>
                <dd class="mt-1 text-sm text-gray-900 sm:col-span-2 sm:mt-0">
                  {format_atom(@schedule.target_type)}
                </dd>
              </div>

              <div class="py-4 sm:grid sm:grid-cols-3 sm:gap-4">
                <dt class="text-sm font-medium text-gray-500">Schedule</dt>
                <dd class="mt-1 text-sm text-gray-900 sm:col-span-2 sm:mt-0">
                  <code class="text-xs bg-gray-100 px-2 py-1 rounded">{@schedule.schedule_cron}</code>
                </dd>
              </div>

              <div class="py-4 sm:grid sm:grid-cols-3 sm:gap-4">
                <dt class="text-sm font-medium text-gray-500">Grace Period</dt>
                <dd class="mt-1 text-sm text-gray-900 sm:col-span-2 sm:mt-0">
                  {@schedule.grace_period_seconds} seconds
                </dd>
              </div>

              <div class="py-4 sm:grid sm:grid-cols-3 sm:gap-4">
                <dt class="text-sm font-medium text-gray-500">Status</dt>
                <dd class="mt-1 text-sm text-gray-900 sm:col-span-2 sm:mt-0">
                  <.enabled_badge enabled={@schedule.enabled} />
                </dd>
              </div>

              <div class="py-4 sm:grid sm:grid-cols-3 sm:gap-4">
                <dt class="text-sm font-medium text-gray-500">Next Rotation</dt>
                <dd class="mt-1 text-sm text-gray-900 sm:col-span-2 sm:mt-0">
                  <%= if @schedule.next_rotation_at do %>
                    {Calendar.strftime(@schedule.next_rotation_at, "%Y-%m-%d %H:%M:%S UTC")}
                  <% else %>
                    <span class="text-gray-400">Not scheduled</span>
                  <% end %>
                </dd>
              </div>

              <div class="py-4 sm:grid sm:grid-cols-3 sm:gap-4">
                <dt class="text-sm font-medium text-gray-500">Last Rotation</dt>
                <dd class="mt-1 text-sm text-gray-900 sm:col-span-2 sm:mt-0">
                  <%= if @schedule.last_rotation_at do %>
                    <div>
                      {Calendar.strftime(@schedule.last_rotation_at, "%Y-%m-%d %H:%M:%S UTC")}
                      <.rotation_status_badge status={@schedule.last_rotation_status} />
                    </div>
                    <%= if @schedule.last_rotation_error do %>
                      <div class="mt-2 text-sm text-red-600">{@schedule.last_rotation_error}</div>
                    <% end %>
                  <% else %>
                    <span class="text-gray-400">Never run</span>
                  <% end %>
                </dd>
              </div>

              <div class="py-4 sm:grid sm:grid-cols-3 sm:gap-4">
                <dt class="text-sm font-medium text-gray-500">Rotation Count</dt>
                <dd class="mt-1 text-sm text-gray-900 sm:col-span-2 sm:mt-0">
                  {@schedule.rotation_count}
                </dd>
              </div>

              <div class="py-4 sm:grid sm:grid-cols-3 sm:gap-4">
                <dt class="text-sm font-medium text-gray-500">Configuration</dt>
                <dd class="mt-1 text-sm text-gray-900 sm:col-span-2 sm:mt-0">
                  <pre class="bg-gray-50 p-4 rounded text-xs overflow-x-auto"><%= Jason.encode!(@schedule.config, pretty: true) %></pre>
                </dd>
              </div>
            </dl>
          </div>

          <div class="mt-6 flex justify-between">
            <button phx-click="cancel" class="btn btn-ghost">
              Back to List
            </button>
            <.link navigate={~p"/admin/rotations/#{@schedule.id}/history"} class="btn btn-primary">
              View Rotation History
            </.link>
          </div>
        </div>
      </div>
    </div>
    """
  end

  defp rotation_type_badge(assigns) do
    type_str = to_string(assigns.type)

    color =
      case assigns.type do
        :database_password -> "badge-info"
        :aws_iam_key -> "badge-warning"
        :api_key -> "badge-success"
        :service_account -> "badge-primary"
        _ -> "badge-ghost"
      end

    assigns = assign(assigns, :color, color)
    assigns = assign(assigns, :label, format_atom(assigns.type))

    ~H"""
    <span class={"badge #{@color}"}>{@label}</span>
    """
  end

  defp enabled_badge(assigns) do
    ~H"""
    <span class={if @enabled, do: "badge badge-success", else: "badge badge-ghost"}>
      {if @enabled, do: "Enabled", else: "Disabled"}
    </span>
    """
  end

  defp rotation_status_badge(assigns) do
    status_str = to_string(assigns.status)

    color =
      case assigns.status do
        :success -> "badge-success"
        :failed -> "badge-error"
        :in_progress -> "badge-warning"
        :pending -> "badge-ghost"
        _ -> "badge-ghost"
      end

    assigns = assign(assigns, :color, color)
    assigns = assign(assigns, :label, format_atom(assigns.status))

    ~H"""
    <span class={"badge #{@color}"}>{@label}</span>
    """
  end

  defp format_atom(atom) when is_atom(atom) do
    atom
    |> Atom.to_string()
    |> String.split("_")
    |> Enum.map(&String.capitalize/1)
    |> Enum.join(" ")
  end

  defp format_changeset_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, _opts} -> msg end)
    |> Enum.map(fn {field, errors} -> "#{field}: #{Enum.join(errors, ", ")}" end)
    |> Enum.join("; ")
  end
end
