defmodule SecretHub.WebWeb.SecretFormComponent do
  @moduledoc """
  LiveComponent for secret creation and editing form.
  """

  use SecretHub.WebWeb, :live_component
  require Logger
  alias SecretHub.Shared.Schemas.Secret

  @impl true
  def update(assigns, socket) do
    socket = assign(socket, assigns)
    {:ok, socket}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="fixed inset-0 bg-gray-600 bg-opacity-50 flex items-center justify-center z-50">
      <div class="bg-white rounded-lg shadow-xl max-w-2xl w-full mx-4">
        <div class="px-6 py-4 border-b border-gray-200">
          <h3 class="text-lg font-semibold text-gray-900">
            <%= if @mode == :create do %>
              Create New Secret
            <% else %>
              Edit Secret
            <% end %>
          </h3>
        </div>

        <form phx-target={@myself} phx-submit="save" phx-change="validate" class="p-6">
          <div class="space-y-6">
            <!-- Basic Information -->
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div class="md:col-span-2">
                <label class="block text-sm font-medium text-gray-700 mb-1">
                  Secret Name
                </label>
                <input
                  type="text"
                  name="secret[name]"
                  value={Phoenix.HTML.Form.input_value(@changeset, :name)}
                  class="form-input w-full"
                  placeholder="e.g., Production Database"
                />
                <%= if error = Phoenix.HTML.Form.input_error(@changeset, :name) do %>
                  <p class="mt-1 text-sm text-red-600"><%= error %></p>
                <% end %>
              </div>

              <div class="md:col-span-2">
                <label class="block text-sm font-medium text-gray-700 mb-1">
                  Description
                </label>
                <textarea
                  name="secret[description]"
                  rows="2"
                  class="form-input w-full"
                  placeholder="Brief description of what this secret provides access to"
                ><%= Phoenix.HTML.Form.input_value(@changeset, :description) %></textarea>
                <%= if error = Phoenix.HTML.Form.input_error(@changeset, :description) do %>
                  <p class="mt-1 text-sm text-red-600"><%= error %></p>
                <% end %>
              </div>

              <div class="md:col-span-2">
                <label class="block text-sm font-medium text-gray-700 mb-1">
                  Secret Path
                </label>
                <input
                  type="text"
                  name="secret[path]"
                  value={Phoenix.HTML.Form.input_value(@changeset, :path)}
                  class="form-input w-full"
                  placeholder="e.g., prod/db/postgres"
                />
                <p class="mt-1 text-xs text-gray-500">
                  Hierarchical path for secret organization (e.g., environment/service/credential)
                </p>
                <%= if error = Phoenix.HTML.Form.input_error(@changeset, :path) do %>
                  <p class="mt-1 text-sm text-red-600"><%= error %></p>
                <% end %>
              </div>
            </div>

            <!-- Engine Configuration -->
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <label class="block text-sm font-medium text-gray-700 mb-1">
                  Secret Engine
                </label>
                <select
                  name="secret[engine_type]"
                  class="form-select w-full"
                  phx-change="engine_changed"
                >
                  <%= for engine <- @engines do %>
                    <option
                      value={engine.type}
                      selected={Phoenix.HTML.Form.input_value(@changeset, :engine_type) == engine.type}
                    >
                      <%= engine.name %>
                    </option>
                  <% end %>
                </select>
                <%= if error = Phoenix.HTML.Form.input_error(@changeset, :engine_type) do %>
                  <p class="mt-1 text-sm text-red-600"><%= error %></p>
                <% end %>
              </div>

              <div>
                <label class="block text-sm font-medium text-gray-700 mb-1">
                  Secret Type
                </label>
                <select
                  name="secret[type]"
                  class="form-select w-full"
                >
                  <option value="static" selected={Phoenix.HTML.Form.input_value(@changeset, :type) == :static}>
                    Static (long-lived)
                  </option>
                  <option value="dynamic" selected={Phoenix.HTML.Form.input_value(@changeset, :type) == :dynamic}>
                    Dynamic (temporary)
                  </option>
                </select>
                <%= if error = Phoenix.HTML.Form.input_error(@changeset, :type) do %>
                  <p class="mt-1 text-sm text-red-600"><%= error %></p>
                <% end %>
              </div>
            </div>

            <!-- Rotation Settings -->
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <label class="block text-sm font-medium text-gray-700 mb-1">
                  TTL (hours)
                </label>
                <input
                  type="number"
                  name="secret[ttl_hours]"
                  value={Phoenix.HTML.Form.input_value(@changeset, :ttl_hours)}
                  class="form-input w-full"
                  min="1"
                  placeholder="24"
                />
                <p class="mt-1 text-xs text-gray-500">
                  Time to live for dynamic secrets (hours)
                </p>
                <%= if error = Phoenix.HTML.Form.input_error(@changeset, :ttl_hours) do %>
                  <p class="mt-1 text-sm text-red-600"><%= error %></p>
                <% end %>
              </div>

              <div>
                <label class="block text-sm font-medium text-gray-700 mb-1">
                  Rotation Period (hours)
                </label>
                <input
                  type="number"
                  name="secret[rotation_period_hours]"
                  value={Phoenix.HTML.Form.input_value(@changeset, :rotation_period_hours)}
                  class="form-input w-full"
                  min="1"
                  placeholder="168"
                />
                <p class="mt-1 text-xs text-gray-500">
                  How often to rotate static secrets (hours)
                </p>
                <%= if error = Phoenix.HTML.Form.input_error(@changeset, :rotation_period_hours) do %>
                  <p class="mt-1 text-sm text-red-600"><%= error %></p>
                <% end %>
              </div>
            </div>

            <!-- Policies -->
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">
                Access Policies
              </label>
              <div class="space-y-2">
                <%= for policy <- @policies do %>
                  <label class="flex items-center">
                    <input
                      type="checkbox"
                      name="secret[policies][]"
                      value={policy.id}
                      class="form-checkbox h-4 w-4 text-blue-600 rounded"
                    />
                    <span class="ml-2 text-sm text-gray-700"><%= policy.name %></span>
                  </label>
                <% end %>
              </div>
              <p class="mt-1 text-xs text-gray-500">
                Select which policies can access this secret
              </p>
            </div>

            <!-- Engine-specific Configuration -->
            <div id="engine-config" class="space-y-4">
              <%= render_engine_config(assigns) %>
            </div>
          </div>

          <!-- Form Actions -->
          <div class="px-6 py-4 border-t border-gray-200 flex justify-end space-x-4">
            <button
              type="button"
              class="btn-secondary"
              phx-click="cancel"
              phx-target={@myself}
            >
              Cancel
            </button>
            <button
              type="submit"
              class="btn-primary"
              phx-disable-with="Saving..."
            >
              <%= if @mode == :create do %>
                Create Secret
              <% else %>
                Update Secret
              <% end %>
            </button>
          </div>
        </form>
      </div>
    </div>
    """
  end

  @impl true
  def handle_event("save", %{"secret" => secret_params}, socket) do
    case socket.assigns.mode do
      :create ->
        send(self(), {:save_secret, secret_params})
        {:noreply, socket}

      :edit ->
        send(self(), {:update_secret, socket.assigns.secret.id, secret_params})
        {:noreply, socket}
    end
  end

  @impl true
  def handle_event("validate", %{"secret" => secret_params}, socket) do
    changeset =
      %SecretHub.Shared.Schemas.Secret{}
      |> SecretHub.Shared.Schemas.Secret.changeset(secret_params)
      |> Map.put(:action, :validate)

    socket = assign(socket, :changeset, changeset)
    {:noreply, socket}
  end

  @impl true
  def handle_event("cancel", _params, socket) do
    send(self(), {:cancel_form})
    {:noreply, socket}
  end

  # Helper functions for rendering engine-specific configuration
  defp render_engine_config(assigns) do
    engine_type = Phoenix.HTML.Form.input_value(assigns.changeset, :engine_type)

    case engine_type do
      "static" ->
        ~H"""
        <div class="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
          <h4 class="text-sm font-medium text-yellow-800 mb-2">Static Secret Configuration</h4>
          <p class="text-sm text-yellow-700">
            Static secrets store long-lived credentials that are rotated periodically.
            After creation, you'll need to configure the actual secret values through the engine settings.
          </p>
        </div>
        """

      "postgresql" ->
        ~H"""
        <div class="space-y-4">
          <h4 class="text-sm font-medium text-gray-900">PostgreSQL Configuration</h4>
          <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">Database Host</label>
              <input type="text" name="secret[engine_config][host]" class="form-input w-full" placeholder="localhost" />
            </div>
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">Database Port</label>
              <input type="number" name="secret[engine_config][port]" class="form-input w-full" placeholder="5432" />
            </div>
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">Database Name</label>
              <input type="text" name="secret[engine_config][database]" class="form-input w-full" placeholder="myapp" />
            </div>
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">Username</label>
              <input type="text" name="secret[engine_config][username]" class="form-input w-full" placeholder="myuser" />
            </div>
          </div>
        </div>
        """

      "redis" ->
        ~H"""
        <div class="space-y-4">
          <h4 class="text-sm font-medium text-gray-900">Redis Configuration</h4>
          <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">Redis Host</label>
              <input type="text" name="secret[engine_config][host]" class="form-input w-full" placeholder="localhost" />
            </div>
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">Redis Port</label>
              <input type="number" name="secret[engine_config][port]" class="form-input w-full" placeholder="6379" />
            </div>
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">Database</label>
              <input type="number" name="secret[engine_config][database]" class="form-input w-full" placeholder="0" />
            </div>
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">Password</label>
              <input type="password" name="secret[engine_config][password]" class="form-input w-full" placeholder="optional" />
            </div>
          </div>
        </div>
        """

      "aws" ->
        ~H"""
        <div class="space-y-4">
          <h4 class="text-sm font-medium text-gray-900">AWS Configuration</h4>
          <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">AWS Region</label>
              <select name="secret[engine_config][region]" class="form-select w-full">
                <option value="us-east-1">US East (N. Virginia)</option>
                <option value="us-west-2">US West (Oregon)</option>
                <option value="eu-west-1">EU West (Ireland)</option>
                <option value="ap-southeast-1">AP Southeast (Singapore)</option>
              </select>
            </div>
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">Service Type</label>
              <select name="secret[engine_config][service]" class="form-select w-full">
                <option value="iam">IAM Users</option>
                <option value="s3">S3 Access</option>
                <option value="ec2">EC2 Instances</option>
                <option value="rds">RDS Database</option>
              </select>
            </div>
          </div>
        </div>
        """

      _ ->
        ~H"""
        <div class="bg-gray-50 border border-gray-200 rounded-lg p-4">
          <p class="text-sm text-gray-600">
            No specific configuration needed for this engine type.
          </p>
        </div>
        """
    end
  end
end