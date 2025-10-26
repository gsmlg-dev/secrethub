defmodule SecretHub.WebWeb.SecretManagementLive do
  @moduledoc """
  LiveView for secret management with CRUD operations and policy validation.
  """

  use SecretHub.WebWeb, :live_view
  require Logger
  alias SecretHub.Core.{Policies, Secrets}
  alias SecretHub.Shared.Schemas.Secret

  @impl true
  def mount(_params, _session, socket) do
    secrets = fetch_secrets()
    engines = fetch_secret_engines()
    policies = fetch_policies()

    socket =
      socket
      |> assign(:secrets, secrets)
      |> assign(:engines, engines)
      |> assign(:policies, policies)
      |> assign(:selected_secret, nil)
      |> assign(:show_form, false)
      |> assign(:form_mode, :create)
      |> assign(:filter_engine, "all")
      |> assign(:search_query, "")
      |> assign(:loading, false)
      |> assign(:form_changeset, changeset_for_secret(%SecretHub.Shared.Schemas.Secret{}))

    {:ok, socket}
  end

  @impl true
  def handle_params(%{"id" => secret_id}, _url, socket) do
    secret = Enum.find(socket.assigns.secrets, &(&1.id == secret_id))

    socket =
      socket
      |> assign(:selected_secret, secret)
      |> assign(:show_form, false)

    {:noreply, socket}
  end

  def handle_params(_params, _url, socket) do
    socket = assign(socket, :selected_secret, nil)
    {:noreply, socket}
  end

  @impl true
  def handle_event("new_secret", _params, socket) do
    socket =
      socket
      |> assign(:show_form, true)
      |> assign(:form_mode, :create)
      |> assign(:form_changeset, changeset_for_secret(%SecretHub.Shared.Schemas.Secret{}))

    {:noreply, socket}
  end

  @impl true
  def handle_event("edit_secret", %{"id" => secret_id}, socket) do
    secret = Enum.find(socket.assigns.secrets, &(&1.id == secret_id))
    changeset = changeset_for_secret(secret)

    socket =
      socket
      |> assign(:show_form, true)
      |> assign(:form_mode, :edit)
      |> assign(:selected_secret, secret)
      |> assign(:form_changeset, changeset)

    {:noreply, socket}
  end

  @impl true
  def handle_event("delete_secret", %{"id" => secret_id}, socket) do
    Logger.info("Deleting secret: #{secret_id}")

    case Secrets.delete_secret(secret_id) do
      {:ok, _deleted_secret} ->
        secrets = fetch_secrets()

        socket =
          socket
          |> assign(:secrets, secrets)
          |> put_flash(:info, "Secret deleted successfully")
          |> push_patch(to: "/admin/secrets")

        {:noreply, socket}

      {:error, reason} ->
        socket =
          socket
          |> put_flash(:error, "Failed to delete secret: #{inspect(reason)}")

        {:noreply, socket}
    end
  end

  @impl true
  def handle_event("rotate_secret", %{"id" => secret_id}, socket) do
    Logger.info("Rotating secret: #{secret_id}")

    # FIXME: Call SecretHub.Core.Secrets.rotate_secret(secret_id)

    socket =
      socket
      |> put_flash(:info, "Secret rotation initiated")
      |> assign(:loading, true)

    :timer.send_after(2000, :refresh_secrets)

    {:noreply, socket}
  end

  @impl true
  def handle_event("filter_secrets", %{"engine" => engine}, socket) do
    socket = assign(socket, :filter_engine, engine)
    {:noreply, socket}
  end

  @impl true
  def handle_event("search_secrets", %{"query" => query}, socket) do
    socket = assign(socket, :search_query, query)
    {:noreply, socket}
  end

  @impl true
  def handle_event("validate_secret", %{"secret" => secret_params}, socket) do
    changeset =
      %Secret{}
      |> Secret.changeset(secret_params)
      |> Map.put(:action, :validate)

    {:noreply, assign(socket, :form_changeset, changeset)}
  end

  @impl true
  def handle_event("save_secret", %{"secret" => secret_params}, socket) do
    case socket.assigns.form_mode do
      :create ->
        create_secret(socket, secret_params)

      :edit ->
        update_secret(socket, socket.assigns.selected_secret.id, secret_params)
    end
  end

  @impl true
  def handle_event("cancel_form", _params, socket) do
    socket =
      socket
      |> assign(:show_form, false)
      |> push_patch(to: "/admin/secrets")

    {:noreply, socket}
  end

  @impl true
  def handle_info(:refresh_secrets, socket) do
    secrets = fetch_secrets()

    socket =
      socket
      |> assign(:secrets, secrets)
      |> assign(:loading, false)

    {:noreply, socket}
  end

  @impl true
  def handle_info({:save_secret, secret_params}, socket) do
    case create_secret(socket, secret_params) do
      {:ok, _secret} ->
        secrets = fetch_secrets()

        socket =
          socket
          |> assign(:secrets, secrets)
          |> assign(:show_form, false)
          |> put_flash(:info, "Secret created successfully")
          |> push_patch(to: "/admin/secrets")

        {:noreply, socket}

      {:error, _changeset} ->
        socket =
          socket
          |> put_flash(:error, "Failed to create secret")

        {:noreply, socket}
    end
  end

  @impl true
  def handle_info({:update_secret, secret_id, secret_params}, socket) do
    case update_secret(socket, secret_id, secret_params) do
      {:ok, _secret} ->
        secrets = fetch_secrets()

        socket =
          socket
          |> assign(:secrets, secrets)
          |> assign(:show_form, false)
          |> put_flash(:info, "Secret updated successfully")
          |> push_patch(to: "/admin/secrets")

        {:noreply, socket}

      {:error, _changeset} ->
        socket =
          socket
          |> put_flash(:error, "Failed to update secret")

        {:noreply, socket}
    end
  end

  @impl true
  def handle_info({:cancel_form}, socket) do
    socket =
      socket
      |> assign(:show_form, false)
      |> push_patch(to: "/admin/secrets")

    {:noreply, socket}
  end

  @impl true
  def handle_info({:close_event_details}, socket) do
    socket = assign(socket, :selected_event, nil)
    {:noreply, socket}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="space-y-6">
      <!-- Header and Actions -->
      <div class="flex justify-between items-center">
        <h2 class="text-2xl font-bold text-gray-900">Secret Management</h2>
        <button
          class="btn-primary"
          phx-click="new_secret"
        >
          <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
          </svg>
          New Secret
        </button>
      </div>
      
    <!-- Filters and Search -->
      <div class="bg-white p-4 rounded-lg shadow">
        <div class="flex flex-wrap gap-4 items-center">
          <div class="flex items-center space-x-2">
            <label class="text-sm font-medium text-gray-700">Engine:</label>
            <select
              class="form-select"
              phx-change="filter_secrets"
              name="engine"
              value={@filter_engine}
            >
              <option value="all">All</option>
              <%= for engine <- @engines do %>
                <option value={engine.type}>{engine.name}</option>
              <% end %>
            </select>
          </div>

          <div class="flex items-center space-x-2 flex-1">
            <label class="text-sm font-medium text-gray-700">Search:</label>
            <input
              type="text"
              class="form-input flex-1"
              placeholder="Search secrets by name or path..."
              phx-change="search_secrets"
              name="query"
              value={@search_query}
            />
          </div>
        </div>
      </div>
      
    <!-- Secret Form Modal -->
      <%= if @show_form do %>
        <.live_component
          module={SecretHub.WebWeb.SecretFormComponent}
          id="secret-form"
          changeset={@form_changeset}
          mode={@form_mode}
          engines={@engines}
          policies={@policies}
          return_to="/admin/secrets"
        />
      <% end %>
      
    <!-- Secret List -->
      <div class="bg-white rounded-lg shadow">
        <div class="overflow-x-auto">
          <table class="min-w-full divide-y divide-gray-200">
            <thead class="bg-gray-50">
              <tr>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Name
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Path
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Engine
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Type
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Status
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Last Rotation
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Next Rotation
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody class="bg-white divide-y divide-gray-200">
              <%= for secret <- filtered_secrets(@secrets, @filter_engine, @search_query) do %>
                <tr class="hover:bg-gray-50 transition-colors">
                  <td class="px-6 py-4 whitespace-nowrap">
                    <div class="text-sm font-medium text-gray-900">{secret.name}</div>
                    <div class="text-sm text-gray-500">{secret.description}</div>
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap">
                    <code class="text-sm bg-gray-100 px-1 py-0.5 rounded">{secret.path}</code>
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {secret.engine_type}
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap">
                    <span class={"inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium #{secret_type_badge_color(secret.type)}"}>
                      {Atom.to_string(secret.type)}
                    </span>
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap">
                    <div class="flex items-center">
                      <div class={"w-2 h-2 rounded-full mr-2 #{status_color(secret.status)}"}></div>
                      <span class="text-sm text-gray-900">{secret.status}</span>
                    </div>
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {format_datetime(secret.last_rotation)}
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {format_datetime(secret.next_rotation)}
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
                    <div class="flex space-x-2">
                      <button
                        class="text-indigo-600 hover:text-indigo-900"
                        phx-click="edit_secret"
                        phx-value-id={secret.id}
                      >
                        Edit
                      </button>

                      <button
                        class="text-green-600 hover:text-green-900"
                        phx-click="rotate_secret"
                        phx-value-id={secret.id}
                        phx-disable-with="Rotating..."
                      >
                        Rotate
                      </button>

                      <button
                        class="text-red-600 hover:text-red-900"
                        phx-click="delete_secret"
                        phx-value-id={secret.id}
                        phx-confirm="Are you sure you want to delete this secret?"
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
      </div>
      
    <!-- Loading State -->
      <%= if @loading do %>
        <div class="fixed inset-0 bg-gray-600 bg-opacity-50 flex items-center justify-center z-50">
          <div class="bg-white rounded-lg p-6 shadow-xl">
            <div class="flex items-center">
              <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
              <span class="ml-2 text-gray-600">Processing...</span>
            </div>
          </div>
        </div>
      <% end %>
    </div>
    """
  end

  # Private functions
  defp create_secret(socket, secret_params) do
    case %Secret{} |> Secret.changeset(secret_params) |> Secret.create() do
      {:ok, secret} ->
        Logger.info("Created secret: #{secret.id}")

        secrets = fetch_secrets()

        socket =
          socket
          |> assign(:secrets, secrets)
          |> assign(:show_form, false)
          |> put_flash(:info, "Secret created successfully")
          |> push_patch(to: "/admin/secrets")

        {:noreply, socket}

      {:error, changeset} ->
        socket =
          socket
          |> assign(:form_changeset, changeset)
          |> put_flash(:error, "Failed to create secret")

        {:noreply, socket}
    end
  end

  defp update_secret(socket, secret_id, secret_params) do
    case Secret.update(secret_id, secret_params) do
      {:ok, secret} ->
        Logger.info("Updated secret: #{secret.id}")

        secrets = fetch_secrets()

        socket =
          socket
          |> assign(:secrets, secrets)
          |> assign(:show_form, false)
          |> put_flash(:info, "Secret updated successfully")
          |> push_patch(to: "/admin/secrets")

        {:noreply, socket}

      {:error, changeset} ->
        socket =
          socket
          |> assign(:form_changeset, changeset)
          |> put_flash(:error, "Failed to update secret")

        {:noreply, socket}
    end
  end

  defp fetch_secrets do
    Secrets.list_secrets()
    |> Enum.map(&format_secret_for_display/1)
  end

  defp format_secret_for_display(secret) do
    %{
      id: secret.id,
      name: secret.name,
      description: secret.description,
      path: secret.secret_path,
      engine_type: secret.engine_type || "static",
      type: secret.secret_type,
      status: determine_secret_status(secret),
      last_rotation: secret.last_rotated_at,
      next_rotation: calculate_next_rotation(secret),
      policies: Enum.map(secret.policies || [], & &1.name)
    }
  end

  defp determine_secret_status(secret) do
    cond do
      secret.rotation_in_progress -> "rotating"
      secret.rotation_enabled -> "active"
      true -> "inactive"
    end
  end

  defp calculate_next_rotation(secret) do
    if secret.rotation_enabled && secret.last_rotated_at do
      DateTime.add(secret.last_rotated_at, secret.rotation_period_hours * 3600, :second)
    else
      nil
    end
  end

  defp fetch_secret_engines do
    # FIXME: Replace with actual SecretHub.Core.Engines.list_engines()
    [
      %{type: "static", name: "Static Secrets"},
      %{type: "postgresql", name: "PostgreSQL"},
      %{type: "redis", name: "Redis"},
      %{type: "aws", name: "AWS"},
      %{type: "gcp", name: "GCP"}
    ]
  end

  defp fetch_policies do
    Policies.list_policies()
    |> Enum.map(&%{id: &1.id, name: &1.name})
  end

  defp filtered_secrets(secrets, "all", ""), do: secrets

  defp filtered_secrets(secrets, engine, ""),
    do: Enum.filter(secrets, &(&1.engine_type == engine))

  defp filtered_secrets(secrets, "all", query) do
    query = String.downcase(query)

    Enum.filter(secrets, fn secret ->
      String.contains?(String.downcase(secret.name), query) or
        String.contains?(String.downcase(secret.path), query) or
        String.contains?(String.downcase(secret.description || ""), query)
    end)
  end

  defp filtered_secrets(secrets, engine, query) do
    secrets
    |> Enum.filter(&(&1.engine_type == engine))
    |> filtered_secrets("all", query)
  end

  defp changeset_for_secret(secret) do
    Secret.changeset(secret, %{
      name: secret.name || "",
      description: secret.description || "",
      path: secret.path || "",
      engine_type: secret.engine_type || "static",
      type: secret.type || :static,
      ttl_hours: secret.ttl_hours || 24,
      rotation_period_hours: secret.rotation_period_hours || 168
    })
  end

  defp secret_type_badge_color(:static), do: "bg-blue-100 text-blue-800"
  defp secret_type_badge_color(:dynamic), do: "bg-green-100 text-green-800"
  defp secret_type_badge_color(_), do: "bg-gray-100 text-gray-800"

  defp status_color("active"), do: "bg-green-500"
  defp status_color("rotating"), do: "bg-yellow-500"
  defp status_color("error"), do: "bg-red-500"
  defp status_color(_), do: "bg-gray-500"

  defp format_datetime(nil), do: "Never"

  defp format_datetime(datetime) do
    DateTime.to_string(datetime)
  end
end
