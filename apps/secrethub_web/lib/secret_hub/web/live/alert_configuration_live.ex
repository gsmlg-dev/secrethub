defmodule SecretHub.Web.AlertConfigurationLive do
  @moduledoc """
  LiveView for managing alert routing configurations.

  Allows administrators to configure:
  - Alert channels (Email, Slack, Webhook, PagerDuty, Opsgenie)
  - Severity-based routing
  - Channel-specific settings
  - Enable/disable alert routes
  """

  use SecretHub.Web, :live_view

  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.AlertRoutingConfig

  import Ecto.Query

  @impl true
  def mount(_params, _session, socket) do
    socket =
      socket
      |> assign(:page_title, "Alert Configuration")
      |> assign(:configs, list_configs())
      |> assign(:show_form, false)
      |> assign(:editing_config, nil)
      |> assign(:form_data, default_form_data())

    {:ok, socket}
  end

  @impl true
  def handle_event("new_config", _params, socket) do
    socket =
      socket
      |> assign(:show_form, true)
      |> assign(:editing_config, nil)
      |> assign(:form_data, default_form_data())

    {:noreply, socket}
  end

  @impl true
  def handle_event("edit_config", %{"id" => id}, socket) do
    config = Repo.get!(AlertRoutingConfig, id)

    socket =
      socket
      |> assign(:show_form, true)
      |> assign(:editing_config, config)
      |> assign(:form_data, config_to_form_data(config))

    {:noreply, socket}
  end

  @impl true
  def handle_event("cancel_form", _params, socket) do
    socket =
      socket
      |> assign(:show_form, false)
      |> assign(:editing_config, nil)
      |> assign(:form_data, default_form_data())

    {:noreply, socket}
  end

  @impl true
  def handle_event("save_config", params, socket) do
    case save_config(socket.assigns.editing_config, params) do
      {:ok, _config} ->
        socket =
          socket
          |> assign(:show_form, false)
          |> assign(:editing_config, nil)
          |> assign(:form_data, default_form_data())
          |> assign(:configs, list_configs())
          |> put_flash(:info, "Alert configuration saved successfully")

        {:noreply, socket}

      {:error, changeset} ->
        socket = put_flash(socket, :error, "Failed to save: #{inspect(changeset.errors)}")
        {:noreply, socket}
    end
  end

  @impl true
  def handle_event("toggle_enabled", %{"id" => id}, socket) do
    config = Repo.get!(AlertRoutingConfig, id)

    case AlertRoutingConfig.toggle(config) |> Repo.update() do
      {:ok, _config} ->
        socket =
          socket
          |> assign(:configs, list_configs())
          |> put_flash(
            :info,
            "Configuration #{if config.enabled, do: "disabled", else: "enabled"}"
          )

        {:noreply, socket}

      {:error, _changeset} ->
        {:noreply, put_flash(socket, :error, "Failed to toggle configuration")}
    end
  end

  @impl true
  def handle_event("delete_config", %{"id" => id}, socket) do
    config = Repo.get!(AlertRoutingConfig, id)

    case Repo.delete(config) do
      {:ok, _config} ->
        socket =
          socket
          |> assign(:configs, list_configs())
          |> put_flash(:info, "Configuration deleted successfully")

        {:noreply, socket}

      {:error, _changeset} ->
        {:noreply, put_flash(socket, :error, "Failed to delete configuration")}
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="space-y-6">
      <.header>
        Alert Configuration
        <:subtitle>Configure alert routing and delivery channels</:subtitle>
        <:actions>
          <.button phx-click="new_config">
            <.icon name="plus" class="h-5 w-5 mr-2" /> New Alert Route
          </.button>
        </:actions>
      </.header>
      
    <!-- Configuration Form -->
      <%= if @show_form do %>
        <div class="bg-white p-6 rounded-lg border shadow-sm">
          <h3 class="text-lg font-semibold mb-4">
            {if @editing_config, do: "Edit Alert Route", else: "New Alert Route"}
          </h3>

          <form phx-submit="save_config" class="space-y-4">
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-2">
                Route Name
              </label>
              <input
                type="text"
                name="name"
                value={@form_data.name}
                class="w-full px-3 py-2 border rounded-md"
                required
              />
            </div>

            <div>
              <label class="block text-sm font-medium text-gray-700 mb-2">
                Channel Type
              </label>
              <select name="channel_type" class="w-full px-3 py-2 border rounded-md" required>
                <option value="email" selected={@form_data.channel_type == :email}>Email</option>
                <option value="slack" selected={@form_data.channel_type == :slack}>Slack</option>
                <option value="webhook" selected={@form_data.channel_type == :webhook}>
                  Webhook
                </option>
                <option value="pagerduty" selected={@form_data.channel_type == :pagerduty}>
                  PagerDuty
                </option>
                <option value="opsgenie" selected={@form_data.channel_type == :opsgenie}>
                  Opsgenie
                </option>
              </select>
            </div>

            <div>
              <label class="block text-sm font-medium text-gray-700 mb-2">
                Severity Filter (comma-separated)
              </label>
              <input
                type="text"
                name="severity_filter"
                value={Enum.join(@form_data.severity_filter, ",")}
                placeholder="critical,high,medium,low,info"
                class="w-full px-3 py-2 border rounded-md"
              />
              <p class="text-sm text-gray-500 mt-1">
                Leave empty to receive all severity levels
              </p>
            </div>

            <div>
              <label class="block text-sm font-medium text-gray-700 mb-2">
                Configuration (JSON)
              </label>
              <textarea
                name="config"
                rows="6"
                class="w-full px-3 py-2 border rounded-md font-mono text-sm"
                placeholder='{"webhook_url": "https://...", "recipients": ["admin@example.com"]}'
              ><%= Jason.encode!(@form_data.config, pretty: true) %></textarea>
              <p class="text-sm text-gray-500 mt-1">
                Channel-specific configuration in JSON format
              </p>
            </div>

            <div class="flex items-center">
              <input
                type="checkbox"
                name="enabled"
                id="enabled"
                checked={@form_data.enabled}
                class="rounded border-gray-300"
              />
              <label for="enabled" class="ml-2 text-sm text-gray-700">
                Enable this alert route
              </label>
            </div>

            <div class="flex gap-2">
              <.button type="submit">
                Save Configuration
              </.button>
              <.button type="button" phx-click="cancel_form" class="btn-secondary">
                Cancel
              </.button>
            </div>
          </form>
        </div>
      <% end %>
      
    <!-- Configuration List -->
      <div class="bg-white rounded-lg border shadow-sm overflow-hidden">
        <table class="min-w-full divide-y divide-gray-200">
          <thead class="bg-gray-50">
            <tr>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                Name
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                Channel
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                Severity Filter
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                Status
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                Last Used
              </th>
              <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase">
                Actions
              </th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-200">
            <%= for config <- @configs do %>
              <tr>
                <td class="px-6 py-4 whitespace-nowrap">
                  <div class="text-sm font-medium text-gray-900">{config.name}</div>
                </td>
                <td class="px-6 py-4 whitespace-nowrap">
                  <.channel_badge type={config.channel_type} />
                </td>
                <td class="px-6 py-4 whitespace-nowrap">
                  <div class="text-sm text-gray-500">
                    {if config.severity_filter == [],
                      do: "All",
                      else: Enum.join(config.severity_filter, ", ")}
                  </div>
                </td>
                <td class="px-6 py-4 whitespace-nowrap">
                  <.status_badge enabled={config.enabled} />
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                  <%= if config.last_used_at do %>
                    {Calendar.strftime(config.last_used_at, "%Y-%m-%d %H:%M")}
                  <% else %>
                    Never
                  <% end %>
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                  <div class="flex gap-2 justify-end">
                    <button
                      phx-click="toggle_enabled"
                      phx-value-id={config.id}
                      class="text-indigo-600 hover:text-indigo-900"
                    >
                      {if config.enabled, do: "Disable", else: "Enable"}
                    </button>
                    <button
                      phx-click="edit_config"
                      phx-value-id={config.id}
                      class="text-blue-600 hover:text-blue-900"
                    >
                      Edit
                    </button>
                    <button
                      phx-click="delete_config"
                      phx-value-id={config.id}
                      data-confirm="Are you sure you want to delete this configuration?"
                      class="text-red-600 hover:text-red-900"
                    >
                      Delete
                    </button>
                  </div>
                </td>
              </tr>
            <% end %>
          </tbody>
        </table>

        <%= if @configs == [] do %>
          <div class="text-center py-12">
            <.icon name="bell-slash" class="mx-auto h-12 w-12 text-gray-400" />
            <h3 class="mt-2 text-sm font-medium text-gray-900">No alert routes configured</h3>
            <p class="mt-1 text-sm text-gray-500">
              Get started by creating a new alert routing configuration.
            </p>
            <div class="mt-6">
              <.button phx-click="new_config">
                <.icon name="plus" class="h-5 w-5 mr-2" /> New Alert Route
              </.button>
            </div>
          </div>
        <% end %>
      </div>
    </div>
    """
  end

  defp channel_badge(assigns) do
    color =
      case assigns.type do
        :email -> "blue"
        :slack -> "purple"
        :webhook -> "gray"
        :pagerduty -> "red"
        :opsgenie -> "orange"
        _ -> "gray"
      end

    assigns = assign(assigns, :color, color)

    ~H"""
    <span class={"inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-#{@color}-100 text-#{@color}-800"}>
      {String.capitalize(to_string(@type))}
    </span>
    """
  end

  defp status_badge(assigns) do
    ~H"""
    <%= if @enabled do %>
      <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
        Enabled
      </span>
    <% else %>
      <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-800">
        Disabled
      </span>
    <% end %>
    """
  end

  defp list_configs do
    AlertRoutingConfig
    |> order_by([c], desc: c.enabled, asc: c.name)
    |> Repo.all()
  end

  defp default_form_data do
    %{
      name: "",
      channel_type: :email,
      severity_filter: [],
      config: %{},
      enabled: true
    }
  end

  defp config_to_form_data(config) do
    %{
      name: config.name,
      channel_type: config.channel_type,
      severity_filter: config.severity_filter || [],
      config: config.config || %{},
      enabled: config.enabled
    }
  end

  defp save_config(nil, params) do
    # Creating new config
    attrs = parse_form_params(params)

    %AlertRoutingConfig{}
    |> AlertRoutingConfig.changeset(attrs)
    |> Repo.insert()
  end

  defp save_config(config, params) do
    # Updating existing config
    attrs = parse_form_params(params)

    config
    |> AlertRoutingConfig.changeset(attrs)
    |> Repo.update()
  end

  defp parse_form_params(params) do
    severity_filter =
      case params["severity_filter"] do
        "" ->
          []

        nil ->
          []

        str ->
          str
          |> String.split(",")
          |> Enum.map(&String.trim/1)
          |> Enum.reject(&(&1 == ""))
          |> Enum.map(&String.to_existing_atom/1)
      end

    config =
      case params["config"] do
        "" -> %{}
        nil -> %{}
        json -> Jason.decode!(json)
      end

    %{
      name: params["name"],
      channel_type: String.to_existing_atom(params["channel_type"]),
      severity_filter: severity_filter,
      config: config,
      enabled: params["enabled"] == "on" || params["enabled"] == "true"
    }
  end
end
