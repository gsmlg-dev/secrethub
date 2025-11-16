defmodule SecretHub.WebWeb.DynamicPostgreSQLConfigLive do
  @moduledoc """
  LiveView for managing PostgreSQL dynamic secret engine configuration.

  Allows administrators to:
  - Configure PostgreSQL connection parameters
  - Create and edit roles for dynamic secret generation
  - Define SQL statement templates for user creation, renewal, and revocation
  - Test database connectivity
  - Manage role-based permissions
  """
  use SecretHub.WebWeb, :live_view
  require Logger

  @impl true
  def mount(_params, _session, socket) do
    roles = list_roles()

    socket =
      socket
      |> assign(:page_title, "PostgreSQL Dynamic Engine")
      |> assign(:roles, roles)
      |> assign(:selected_role, nil)
      |> assign(:form_mode, :list)
      |> assign(:connection_test_result, nil)
      |> assign(:form_data, default_form_data())
      |> assign(:validation_errors, %{})

    {:ok, socket}
  end

  @impl true
  def handle_event("new_role", _params, socket) do
    socket =
      socket
      |> assign(:form_mode, :create)
      |> assign(:selected_role, nil)
      |> assign(:form_data, default_form_data())
      |> assign(:validation_errors, %{})
      |> assign(:connection_test_result, nil)

    {:noreply, socket}
  end

  @impl true
  def handle_event("edit_role", %{"role" => role_name}, socket) do
    case get_role_config(role_name) do
      nil ->
        {:noreply, put_flash(socket, :error, "Role not found: #{role_name}")}

      config ->
        socket =
          socket
          |> assign(:form_mode, :edit)
          |> assign(:selected_role, role_name)
          |> assign(:form_data, config_to_form_data(config))
          |> assign(:validation_errors, %{})
          |> assign(:connection_test_result, nil)

        {:noreply, socket}
    end
  end

  @impl true
  def handle_event("cancel", _params, socket) do
    socket =
      socket
      |> assign(:form_mode, :list)
      |> assign(:selected_role, nil)
      |> assign(:form_data, default_form_data())
      |> assign(:validation_errors, %{})
      |> assign(:connection_test_result, nil)

    {:noreply, socket}
  end

  @impl true
  def handle_event("test_connection", _params, socket) do
    form_data = socket.assigns.form_data

    config = %{
      host: form_data.host,
      port: String.to_integer(form_data.port),
      database: form_data.database,
      username: form_data.username,
      password: form_data.password,
      ssl: form_data.ssl == "true"
    }

    case test_database_connection(config) do
      :ok ->
        socket =
          socket
          |> assign(:connection_test_result, {:ok, "Connection successful!"})
          |> put_flash(:info, "Database connection successful")

        {:noreply, socket}

      {:error, reason} ->
        socket =
          socket
          |> assign(:connection_test_result, {:error, "Connection failed: #{inspect(reason)}"})
          |> put_flash(:error, "Database connection failed")

        {:noreply, socket}
    end
  end

  @impl true
  def handle_event("update_field", %{"field" => field, "value" => value}, socket) do
    form_data = Map.put(socket.assigns.form_data, String.to_atom(field), value)
    {:noreply, assign(socket, :form_data, form_data)}
  end

  @impl true
  def handle_event("save_role", _params, socket) do
    form_data = socket.assigns.form_data

    case validate_form(form_data) do
      {:ok, valid_config} ->
        role_name = form_data.role_name

        case save_role_config(role_name, valid_config, socket.assigns.form_mode) do
          :ok ->
            socket =
              socket
              |> assign(:roles, list_roles())
              |> assign(:form_mode, :list)
              |> assign(:selected_role, nil)
              |> assign(:form_data, default_form_data())
              |> assign(:validation_errors, %{})
              |> put_flash(:info, "Role '#{role_name}' saved successfully")

            {:noreply, socket}

          {:error, reason} ->
            {:noreply, put_flash(socket, :error, "Failed to save role: #{inspect(reason)}")}
        end

      {:error, errors} ->
        socket =
          socket
          |> assign(:validation_errors, errors)
          |> put_flash(:error, "Please fix validation errors")

        {:noreply, socket}
    end
  end

  @impl true
  def handle_event("delete_role", %{"role" => role_name}, socket) do
    case delete_role_config(role_name) do
      :ok ->
        socket =
          socket
          |> assign(:roles, list_roles())
          |> put_flash(:info, "Role '#{role_name}' deleted successfully")

        {:noreply, socket}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to delete role: #{inspect(reason)}")}
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="container mx-auto px-4 py-8">
      <div class="mb-6">
        <h1 class="text-3xl font-bold text-gray-900">PostgreSQL Dynamic Engine</h1>
        <p class="mt-2 text-gray-600">
          Configure roles for PostgreSQL dynamic secret generation
        </p>
      </div>

      <%= if @form_mode == :list do %>
        <div class="mb-6">
          <button
            phx-click="new_role"
            class="btn btn-primary"
          >
            + New Role
          </button>
        </div>

        <div class="bg-white shadow-md rounded-lg overflow-hidden">
          <table class="min-w-full divide-y divide-gray-200">
            <thead class="bg-gray-50">
              <tr>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Role Name
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Database
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Host
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Default TTL
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Max TTL
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody class="bg-white divide-y divide-gray-200">
              <%= for role <- @roles do %>
                <tr>
                  <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                    {role.name}
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {role.database}
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {role.host}:{role.port}
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {role.default_ttl}s
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {role.max_ttl}s
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
                    <button
                      phx-click="edit_role"
                      phx-value-role={role.name}
                      class="text-indigo-600 hover:text-indigo-900 mr-4"
                    >
                      Edit
                    </button>
                    <button
                      phx-click="delete_role"
                      phx-value-role={role.name}
                      class="text-red-600 hover:text-red-900"
                      data-confirm={"Are you sure you want to delete role '#{role.name}'?"}
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              <% end %>
            </tbody>
          </table>

          <%= if @roles == [] do %>
            <div class="px-6 py-12 text-center text-gray-500">
              No roles configured. Click "New Role" to create one.
            </div>
          <% end %>
        </div>
      <% else %>
        <!-- Create/Edit Form -->
        <div class="bg-white shadow-md rounded-lg p-6">
          <h2 class="text-2xl font-bold mb-6">
            {if @form_mode == :create, do: "Create New Role", else: "Edit Role"}
          </h2>

          <form phx-submit="save_role">
            <!-- Role Name -->
            <div class="mb-4">
              <label class="block text-sm font-medium text-gray-700 mb-2">
                Role Name
              </label>
              <input
                type="text"
                phx-blur="update_field"
                phx-value-field="role_name"
                value={@form_data.role_name}
                class={"input input-bordered w-full #{if @validation_errors[:role_name], do: "border-red-500"}"}
                disabled={@form_mode == :edit}
                required
              />
              <%= if error = @validation_errors[:role_name] do %>
                <p class="text-red-500 text-sm mt-1">{error}</p>
              <% end %>
            </div>
            
    <!-- Connection Parameters -->
            <div class="mb-6">
              <h3 class="text-lg font-semibold mb-3">Connection Parameters</h3>

              <div class="grid grid-cols-2 gap-4">
                <div>
                  <label class="block text-sm font-medium text-gray-700 mb-2">
                    Host
                  </label>
                  <input
                    type="text"
                    phx-blur="update_field"
                    phx-value-field="host"
                    value={@form_data.host}
                    class={"input input-bordered w-full #{if @validation_errors[:host], do: "border-red-500"}"}
                    required
                  />
                  <%= if error = @validation_errors[:host] do %>
                    <p class="text-red-500 text-sm mt-1">{error}</p>
                  <% end %>
                </div>

                <div>
                  <label class="block text-sm font-medium text-gray-700 mb-2">
                    Port
                  </label>
                  <input
                    type="number"
                    phx-blur="update_field"
                    phx-value-field="port"
                    value={@form_data.port}
                    class={"input input-bordered w-full #{if @validation_errors[:port], do: "border-red-500"}"}
                    required
                  />
                  <%= if error = @validation_errors[:port] do %>
                    <p class="text-red-500 text-sm mt-1">{error}</p>
                  <% end %>
                </div>

                <div>
                  <label class="block text-sm font-medium text-gray-700 mb-2">
                    Database
                  </label>
                  <input
                    type="text"
                    phx-blur="update_field"
                    phx-value-field="database"
                    value={@form_data.database}
                    class={"input input-bordered w-full #{if @validation_errors[:database], do: "border-red-500"}"}
                    required
                  />
                  <%= if error = @validation_errors[:database] do %>
                    <p class="text-red-500 text-sm mt-1">{error}</p>
                  <% end %>
                </div>

                <div>
                  <label class="block text-sm font-medium text-gray-700 mb-2">
                    Username
                  </label>
                  <input
                    type="text"
                    phx-blur="update_field"
                    phx-value-field="username"
                    value={@form_data.username}
                    class={"input input-bordered w-full #{if @validation_errors[:username], do: "border-red-500"}"}
                    required
                  />
                  <%= if error = @validation_errors[:username] do %>
                    <p class="text-red-500 text-sm mt-1">{error}</p>
                  <% end %>
                </div>

                <div>
                  <label class="block text-sm font-medium text-gray-700 mb-2">
                    Password
                  </label>
                  <input
                    type="password"
                    phx-blur="update_field"
                    phx-value-field="password"
                    value={@form_data.password}
                    class={"input input-bordered w-full #{if @validation_errors[:password], do: "border-red-500"}"}
                    required
                  />
                  <%= if error = @validation_errors[:password] do %>
                    <p class="text-red-500 text-sm mt-1">{error}</p>
                  <% end %>
                </div>

                <div>
                  <label class="block text-sm font-medium text-gray-700 mb-2">
                    SSL
                  </label>
                  <select
                    phx-change="update_field"
                    phx-value-field="ssl"
                    class="select select-bordered w-full"
                  >
                    <option value="false" selected={@form_data.ssl == "false"}>Disabled</option>
                    <option value="true" selected={@form_data.ssl == "true"}>Enabled</option>
                  </select>
                </div>
              </div>

              <div class="mt-4">
                <button
                  type="button"
                  phx-click="test_connection"
                  class="btn btn-secondary"
                >
                  Test Connection
                </button>

                <%= if @connection_test_result do %>
                  <%= case @connection_test_result do %>
                    <% {:ok, message} -> %>
                      <span class="ml-4 text-green-600">{message}</span>
                    <% {:error, message} -> %>
                      <span class="ml-4 text-red-600">{message}</span>
                  <% end %>
                <% end %>
              </div>
            </div>
            
    <!-- TTL Configuration -->
            <div class="mb-6">
              <h3 class="text-lg font-semibold mb-3">TTL Configuration</h3>

              <div class="grid grid-cols-2 gap-4">
                <div>
                  <label class="block text-sm font-medium text-gray-700 mb-2">
                    Default TTL (seconds)
                  </label>
                  <input
                    type="number"
                    phx-blur="update_field"
                    phx-value-field="default_ttl"
                    value={@form_data.default_ttl}
                    class={"input input-bordered w-full #{if @validation_errors[:default_ttl], do: "border-red-500"}"}
                    required
                  />
                  <%= if error = @validation_errors[:default_ttl] do %>
                    <p class="text-red-500 text-sm mt-1">{error}</p>
                  <% end %>
                </div>

                <div>
                  <label class="block text-sm font-medium text-gray-700 mb-2">
                    Max TTL (seconds)
                  </label>
                  <input
                    type="number"
                    phx-blur="update_field"
                    phx-value-field="max_ttl"
                    value={@form_data.max_ttl}
                    class={"input input-bordered w-full #{if @validation_errors[:max_ttl], do: "border-red-500"}"}
                    required
                  />
                  <%= if error = @validation_errors[:max_ttl] do %>
                    <p class="text-red-500 text-sm mt-1">{error}</p>
                  <% end %>
                </div>
              </div>
            </div>
            
    <!-- SQL Statement Templates -->
            <div class="mb-6">
              <h3 class="text-lg font-semibold mb-3">SQL Statement Templates</h3>
              <p class="text-sm text-gray-600 mb-3">
                Use template variables: {"{{username}}, {{password}}, {{expiration}}"}
              </p>

              <div class="mb-4">
                <label class="block text-sm font-medium text-gray-700 mb-2">
                  Creation Statements
                </label>
                <textarea
                  phx-blur="update_field"
                  phx-value-field="creation_statements"
                  rows="4"
                  class={"textarea textarea-bordered w-full font-mono text-sm #{if @validation_errors[:creation_statements], do: "border-red-500"}"}
                  required
                ><%= @form_data.creation_statements %></textarea>
                <%= if error = @validation_errors[:creation_statements] do %>
                  <p class="text-red-500 text-sm mt-1">{error}</p>
                <% end %>
              </div>

              <div class="mb-4">
                <label class="block text-sm font-medium text-gray-700 mb-2">
                  Renewal Statements (optional)
                </label>
                <textarea
                  phx-blur="update_field"
                  phx-value-field="renewal_statements"
                  rows="2"
                  class="textarea textarea-bordered w-full font-mono text-sm"
                ><%= @form_data.renewal_statements %></textarea>
              </div>

              <div class="mb-4">
                <label class="block text-sm font-medium text-gray-700 mb-2">
                  Revocation Statements
                </label>
                <textarea
                  phx-blur="update_field"
                  phx-value-field="revocation_statements"
                  rows="2"
                  class={"textarea textarea-bordered w-full font-mono text-sm #{if @validation_errors[:revocation_statements], do: "border-red-500"}"}
                  required
                ><%= @form_data.revocation_statements %></textarea>
                <%= if error = @validation_errors[:revocation_statements] do %>
                  <p class="text-red-500 text-sm mt-1">{error}</p>
                <% end %>
              </div>
            </div>
            
    <!-- Form Actions -->
            <div class="flex justify-end space-x-3">
              <button
                type="button"
                phx-click="cancel"
                class="btn btn-ghost"
              >
                Cancel
              </button>
              <button
                type="submit"
                class="btn btn-primary"
              >
                {if @form_mode == :create, do: "Create Role", else: "Update Role"}
              </button>
            </div>
          </form>
        </div>
      <% end %>
    </div>
    """
  end

  # Private helper functions

  defp default_form_data do
    %{
      role_name: "",
      host: "localhost",
      port: "5432",
      database: "postgres",
      username: "",
      password: "",
      ssl: "false",
      default_ttl: "3600",
      max_ttl: "86400",
      creation_statements: """
      CREATE USER \"{{username}}\" WITH PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';
      GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{username}}\";
      """,
      renewal_statements: "ALTER USER \"{{username}}\" VALID UNTIL '{{expiration}}';",
      revocation_statements: "DROP USER IF EXISTS \"{{username}}\";"
    }
  end

  defp config_to_form_data(config) do
    %{
      role_name: config.role_name || "",
      host: config.host || "localhost",
      port: to_string(config.port || 5432),
      database: config.database || "postgres",
      username: config.username || "",
      password: config.password || "",
      ssl: to_string(config.ssl || false),
      default_ttl: to_string(config.default_ttl || 3600),
      max_ttl: to_string(config.max_ttl || 86400),
      creation_statements: config.creation_statements || "",
      renewal_statements: config.renewal_statements || "",
      revocation_statements: config.revocation_statements || ""
    }
  end

  defp validate_form(form_data) do
    errors = %{}

    errors =
      if String.trim(form_data.role_name) == "" do
        Map.put(errors, :role_name, "Role name is required")
      else
        errors
      end

    errors =
      if String.trim(form_data.host) == "" do
        Map.put(errors, :host, "Host is required")
      else
        errors
      end

    errors =
      case Integer.parse(form_data.port) do
        {port, ""} when port > 0 and port < 65536 -> errors
        _ -> Map.put(errors, :port, "Port must be a valid number between 1 and 65535")
      end

    errors =
      if String.trim(form_data.database) == "" do
        Map.put(errors, :database, "Database name is required")
      else
        errors
      end

    errors =
      if String.trim(form_data.username) == "" do
        Map.put(errors, :username, "Username is required")
      else
        errors
      end

    errors =
      if String.trim(form_data.password) == "" do
        Map.put(errors, :password, "Password is required")
      else
        errors
      end

    errors =
      case Integer.parse(form_data.default_ttl) do
        {ttl, ""} when ttl > 0 -> errors
        _ -> Map.put(errors, :default_ttl, "Default TTL must be a positive number")
      end

    errors =
      case Integer.parse(form_data.max_ttl) do
        {ttl, ""} when ttl > 0 -> errors
        _ -> Map.put(errors, :max_ttl, "Max TTL must be a positive number")
      end

    errors =
      with {default_ttl, ""} <- Integer.parse(form_data.default_ttl),
           {max_ttl, ""} <- Integer.parse(form_data.max_ttl) do
        if default_ttl > max_ttl do
          Map.put(errors, :max_ttl, "Max TTL must be greater than or equal to default TTL")
        else
          errors
        end
      else
        _ -> errors
      end

    errors =
      if String.trim(form_data.creation_statements) == "" do
        Map.put(errors, :creation_statements, "Creation statements are required")
      else
        errors
      end

    errors =
      if String.trim(form_data.revocation_statements) == "" do
        Map.put(errors, :revocation_statements, "Revocation statements are required")
      else
        errors
      end

    if errors == %{} do
      {port, _} = Integer.parse(form_data.port)
      {default_ttl, _} = Integer.parse(form_data.default_ttl)
      {max_ttl, _} = Integer.parse(form_data.max_ttl)

      config = %{
        role_name: String.trim(form_data.role_name),
        host: String.trim(form_data.host),
        port: port,
        database: String.trim(form_data.database),
        username: String.trim(form_data.username),
        password: form_data.password,
        ssl: form_data.ssl == "true",
        default_ttl: default_ttl,
        max_ttl: max_ttl,
        creation_statements: String.trim(form_data.creation_statements),
        renewal_statements: String.trim(form_data.renewal_statements),
        revocation_statements: String.trim(form_data.revocation_statements)
      }

      {:ok, config}
    else
      {:error, errors}
    end
  end

  # Stub functions for configuration storage
  # In production, these would interact with a database or configuration store

  defp list_roles do
    # TODO: Implement role listing from database/config store
    # For now, return empty list or read from Application.get_env
    Application.get_env(:secrethub_core, :dynamic_postgresql_roles, [])
  end

  defp get_role_config(role_name) do
    # TODO: Implement role config retrieval
    list_roles()
    |> Enum.find(fn role -> role.name == role_name end)
  end

  defp save_role_config(role_name, config, mode) do
    # TODO: Implement role config persistence
    # For now, store in application environment (not persistent across restarts)
    roles = list_roles()

    updated_roles =
      case mode do
        :create ->
          [Map.put(config, :name, role_name) | roles]

        :edit ->
          Enum.map(roles, fn role ->
            if role.name == role_name do
              Map.put(config, :name, role_name)
            else
              role
            end
          end)
      end

    Application.put_env(:secrethub_core, :dynamic_postgresql_roles, updated_roles)
    :ok
  end

  defp delete_role_config(role_name) do
    # TODO: Implement role deletion
    roles = list_roles()
    updated_roles = Enum.reject(roles, fn role -> role.name == role_name end)
    Application.put_env(:secrethub_core, :dynamic_postgresql_roles, updated_roles)
    :ok
  end

  defp test_database_connection(config) do
    # Test connection using Postgrex
    case Postgrex.start_link(
           hostname: config.host,
           port: config.port,
           database: config.database,
           username: config.username,
           password: config.password,
           ssl: config.ssl,
           pool_size: 1
         ) do
      {:ok, pid} ->
        # Run a simple query to verify connection
        case Postgrex.query(pid, "SELECT 1", []) do
          {:ok, _result} ->
            GenServer.stop(pid)
            :ok

          {:error, reason} ->
            GenServer.stop(pid)
            {:error, reason}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end
end
