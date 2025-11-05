defmodule SecretHub.WebWeb.SecretVersionHistoryLive do
  @moduledoc """
  LiveView for displaying secret version history and managing rollbacks.

  Features:
  - Version timeline visualization
  - Version comparison and diff viewer
  - Rollback to previous versions
  - Version metadata display
  """

  use SecretHub.WebWeb, :live_view

  alias SecretHub.Core.{Repo, Secrets}
  alias SecretHub.Shared.Schemas.{Secret, SecretVersion}

  @impl true
  def mount(%{"id" => secret_id}, _session, socket) do
    case Secrets.get_secret(secret_id) do
      {:ok, secret} ->
        versions = Secrets.list_secret_versions(secret_id, limit: 100)

        socket =
          socket
          |> assign(:page_title, "Version History")
          |> assign(:secret, secret)
          |> assign(:versions, versions)
          |> assign(:selected_version_a, nil)
          |> assign(:selected_version_b, nil)
          |> assign(:comparison, nil)
          |> assign(:show_rollback_modal, false)
          |> assign(:rollback_target, nil)

        {:ok, socket}

      {:error, _reason} ->
        socket =
          socket
          |> put_flash(:error, "Secret not found")
          |> push_navigate(to: "/admin/secrets")

        {:ok, socket}
    end
  end

  @impl true
  def handle_event("select_version_a", %{"version" => version}, socket) do
    {:noreply, assign(socket, :selected_version_a, String.to_integer(version))}
  end

  @impl true
  def handle_event("select_version_b", %{"version" => version}, socket) do
    {:noreply, assign(socket, :selected_version_b, String.to_integer(version))}
  end

  @impl true
  def handle_event("compare_versions", _params, socket) do
    case {socket.assigns.selected_version_a, socket.assigns.selected_version_b} do
      {nil, _} ->
        {:noreply, put_flash(socket, :error, "Please select first version to compare")}

      {_, nil} ->
        {:noreply, put_flash(socket, :error, "Please select second version to compare")}

      {version_a, version_b} ->
        case Secrets.compare_versions(socket.assigns.secret.id, version_a, version_b) do
          {:ok, comparison} ->
            {:noreply, assign(socket, :comparison, comparison)}

          {:error, _reason} ->
            {:noreply, put_flash(socket, :error, "Failed to compare versions")}
        end
    end
  end

  @impl true
  def handle_event("clear_comparison", _params, socket) do
    socket =
      socket
      |> assign(:comparison, nil)
      |> assign(:selected_version_a, nil)
      |> assign(:selected_version_b, nil)

    {:noreply, socket}
  end

  @impl true
  def handle_event("show_rollback_modal", %{"version" => version}, socket) do
    socket =
      socket
      |> assign(:show_rollback_modal, true)
      |> assign(:rollback_target, String.to_integer(version))

    {:noreply, socket}
  end

  @impl true
  def handle_event("cancel_rollback", _params, socket) do
    socket =
      socket
      |> assign(:show_rollback_modal, false)
      |> assign(:rollback_target, nil)

    {:noreply, socket}
  end

  @impl true
  def handle_event("confirm_rollback", _params, socket) do
    target_version = socket.assigns.rollback_target

    case Secrets.rollback_secret(socket.assigns.secret.id, target_version,
           created_by: "admin@web"
         ) do
      {:ok, updated_secret} ->
        versions = Secrets.list_secret_versions(socket.assigns.secret.id, limit: 100)

        socket =
          socket
          |> assign(:secret, updated_secret)
          |> assign(:versions, versions)
          |> assign(:show_rollback_modal, false)
          |> assign(:rollback_target, nil)
          |> put_flash(:info, "Successfully rolled back to version #{target_version}")

        {:noreply, socket}

      {:error, _reason} ->
        socket =
          socket
          |> assign(:show_rollback_modal, false)
          |> put_flash(:error, "Failed to rollback secret")

        {:noreply, socket}
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="space-y-6">
      <.header>
        {@secret.name} - Version History
        <:subtitle>
          Path: {@secret.secret_path} | Current Version: v{@secret.version} | Total Versions: {@secret.version_count}
        </:subtitle>
        <:actions>
          <.button navigate="/admin/secrets">
            <.icon name="arrow-left" class="h-5 w-5 mr-2" /> Back to Secrets
          </.button>
        </:actions>
      </.header>
      
    <!-- Comparison Tool -->
      <div class="bg-white rounded-lg border shadow-sm p-6">
        <h3 class="text-lg font-semibold mb-4">Compare Versions</h3>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">
              Version A
            </label>
            <select
              phx-change="select_version_a"
              name="version"
              class="w-full px-3 py-2 border rounded-md"
            >
              <option value="">Select version...</option>
              <%= for version <- @versions do %>
                <option
                  value={version.version_number}
                  selected={@selected_version_a == version.version_number}
                >
                  v{version.version_number} - {Calendar.strftime(
                    version.archived_at,
                    "%Y-%m-%d %H:%M"
                  )}
                </option>
              <% end %>
            </select>
          </div>
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">
              Version B
            </label>
            <select
              phx-change="select_version_b"
              name="version"
              class="w-full px-3 py-2 border rounded-md"
            >
              <option value="">Select version...</option>
              <%= for version <- @versions do %>
                <option
                  value={version.version_number}
                  selected={@selected_version_b == version.version_number}
                >
                  v{version.version_number} - {Calendar.strftime(
                    version.archived_at,
                    "%Y-%m-%d %H:%M"
                  )}
                </option>
              <% end %>
            </select>
          </div>
          <div class="flex items-end">
            <.button phx-click="compare_versions" class="w-full">
              Compare
            </.button>
          </div>
        </div>

        <%= if @comparison do %>
          <div class="mt-6">
            <div class="flex justify-between items-center mb-4">
              <h4 class="text-md font-semibold">Comparison Result</h4>
              <button phx-click="clear_comparison" class="text-sm text-gray-600 hover:text-gray-900">
                Clear
              </button>
            </div>
            <.version_diff comparison={@comparison} />
          </div>
        <% end %>
      </div>
      
    <!-- Version Timeline -->
      <div class="bg-white rounded-lg border shadow-sm">
        <div class="px-6 py-4 border-b">
          <h3 class="text-lg font-semibold">Version Timeline</h3>
        </div>
        <div class="divide-y">
          <%= for version <- @versions do %>
            <div class="px-6 py-4 hover:bg-gray-50">
              <div class="flex items-start justify-between">
                <div class="flex-1">
                  <div class="flex items-center gap-3">
                    <span class="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-blue-100 text-blue-800">
                      v{version.version_number}
                    </span>
                    <%= if version.version_number == @secret.version do %>
                      <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800">
                        Current
                      </span>
                    <% end %>
                    <span class="text-sm text-gray-500">
                      {Calendar.strftime(version.archived_at, "%Y-%m-%d %H:%M:%S")}
                    </span>
                  </div>
                  <%= if version.change_description do %>
                    <p class="mt-2 text-sm text-gray-900">{version.change_description}</p>
                  <% end %>
                  <div class="mt-2 flex items-center gap-4 text-xs text-gray-500">
                    <%= if version.created_by do %>
                      <span>
                        <.icon name="user" class="h-4 w-4 inline" /> {version.created_by}
                      </span>
                    <% end %>
                    <span>
                      <.icon name="document" class="h-4 w-4 inline" /> {format_bytes(
                        SecretVersion.data_size(version)
                      )}
                    </span>
                    <%= if version.description do %>
                      <span title={version.description}>
                        <.icon name="information-circle" class="h-4 w-4 inline" />
                      </span>
                    <% end %>
                  </div>
                </div>
                <%= if version.version_number != @secret.version do %>
                  <button
                    phx-click="show_rollback_modal"
                    phx-value-version={version.version_number}
                    class="ml-4 px-3 py-1 text-sm text-indigo-600 hover:text-indigo-900 border border-indigo-600 rounded-md hover:bg-indigo-50"
                  >
                    Rollback
                  </button>
                <% end %>
              </div>
            </div>
          <% end %>

          <%= if @versions == [] do %>
            <div class="px-6 py-12 text-center">
              <.icon name="clock" class="mx-auto h-12 w-12 text-gray-400" />
              <h3 class="mt-2 text-sm font-medium text-gray-900">No version history</h3>
              <p class="mt-1 text-sm text-gray-500">
                This secret has not been updated yet.
              </p>
            </div>
          <% end %>
        </div>
      </div>
      
    <!-- Rollback Confirmation Modal -->
      <%= if @show_rollback_modal do %>
        <div class="fixed inset-0 bg-gray-500 bg-opacity-75 flex items-center justify-center z-50">
          <div class="bg-white rounded-lg p-6 max-w-md w-full mx-4">
            <h3 class="text-lg font-semibold mb-4">Confirm Rollback</h3>
            <p class="text-sm text-gray-600 mb-6">
              Are you sure you want to rollback to version {@rollback_target}? This will create a new version (v{@secret.version +
                1}) with the data from v{@rollback_target}.
            </p>
            <div class="flex gap-2 justify-end">
              <.button phx-click="cancel_rollback" color="secondary">
                Cancel
              </.button>
              <.button phx-click="confirm_rollback">
                Confirm Rollback
              </.button>
            </div>
          </div>
        </div>
      <% end %>
    </div>
    """
  end

  defp version_diff(assigns) do
    ~H"""
    <div class="bg-gray-50 rounded-lg p-4 space-y-4">
      <div class="grid grid-cols-2 gap-4 text-sm">
        <div>
          <span class="font-medium">Version:</span> v{elem(@comparison.version_numbers, 0)}
        </div>
        <div>
          <span class="font-medium">Version:</span> v{elem(@comparison.version_numbers, 1)}
        </div>
        <div>
          <span class="font-medium">Changed At:</span>
          {Calendar.strftime(elem(@comparison.changed_at, 0), "%Y-%m-%d %H:%M")}
        </div>
        <div>
          <span class="font-medium">Changed At:</span>
          {Calendar.strftime(elem(@comparison.changed_at, 1), "%Y-%m-%d %H:%M")}
        </div>
        <div>
          <span class="font-medium">Created By:</span>
          {elem(@comparison.created_by, 0) || "unknown"}
        </div>
        <div>
          <span class="font-medium">Created By:</span>
          {elem(@comparison.created_by, 1) || "unknown"}
        </div>
      </div>

      <div>
        <h5 class="font-medium text-sm mb-2">Data Size Change</h5>
        <p class="text-sm">
          <%= if @comparison.data_size_diff > 0 do %>
            <span class="text-green-600">
              +{format_bytes(@comparison.data_size_diff)}
            </span>
          <% else %>
            <span class="text-red-600">
              {format_bytes(@comparison.data_size_diff)}
            </span>
          <% end %>
        </p>
      </div>

      <%= if @comparison.metadata_diff.added != [] || @comparison.metadata_diff.removed != [] || @comparison.metadata_diff.changed != [] do %>
        <div>
          <h5 class="font-medium text-sm mb-2">Metadata Changes</h5>
          <%= if @comparison.metadata_diff.added != [] do %>
            <div class="mb-2">
              <span class="text-xs font-medium text-green-700">Added:</span>
              <ul class="text-sm text-gray-700 ml-4">
                <%= for {key, value} <- @comparison.metadata_diff.added do %>
                  <li><code class="text-xs"><%= key %></code>: {inspect(value)}</li>
                <% end %>
              </ul>
            </div>
          <% end %>
          <%= if @comparison.metadata_diff.removed != [] do %>
            <div class="mb-2">
              <span class="text-xs font-medium text-red-700">Removed:</span>
              <ul class="text-sm text-gray-700 ml-4">
                <%= for {key, value} <- @comparison.metadata_diff.removed do %>
                  <li><code class="text-xs"><%= key %></code>: {inspect(value)}</li>
                <% end %>
              </ul>
            </div>
          <% end %>
          <%= if @comparison.metadata_diff.changed != [] do %>
            <div>
              <span class="text-xs font-medium text-yellow-700">Changed:</span>
              <ul class="text-sm text-gray-700 ml-4">
                <%= for {key, {old_val, new_val}} <- @comparison.metadata_diff.changed do %>
                  <li>
                    <code class="text-xs"><%= key %></code>:
                    <span class="line-through text-red-600">{inspect(old_val)}</span>
                    → <span class="text-green-600">{inspect(new_val)}</span>
                  </li>
                <% end %>
              </ul>
            </div>
          <% end %>
        </div>
      <% else %>
        <p class="text-sm text-gray-500">No metadata changes</p>
      <% end %>
    </div>
    """
  end

  defp format_bytes(bytes) when bytes < 1024, do: "#{bytes} B"
  defp format_bytes(bytes) when bytes < 1024 * 1024, do: "#{Float.round(bytes / 1024, 1)} KB"

  defp format_bytes(bytes),
    do: "#{Float.round(bytes / (1024 * 1024), 1)} MB"
end
