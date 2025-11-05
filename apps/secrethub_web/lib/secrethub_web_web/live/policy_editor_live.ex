defmodule SecretHub.WebWeb.PolicyEditorLive do
  @moduledoc """
  Advanced policy creation and editing interface with tab-based navigation.

  Features:
  - Tab-based interface for policy configuration
  - Real-time JSON preview
  - Validation feedback
  - Template-based creation
  """

  use SecretHub.WebWeb, :live_view
  require Logger

  alias SecretHub.Core.{Agents, Policies, PolicyTemplates}

  @impl true
  def mount(_params, _session, socket) do
    agents = list_agents()

    socket =
      socket
      |> assign(:agents, agents)
      |> assign(:active_tab, "basic")
      |> assign(:validation_errors, [])
      |> assign(:page_title, "Create Policy")

    {:ok, socket}
  end

  @impl true
  def handle_params(%{"id" => policy_id}, _url, socket) do
    case Policies.get_policy(policy_id) do
      {:ok, policy} ->
        form_data = %{
          "name" => policy.name,
          "description" => policy.description || "",
          "deny_policy" => policy.deny_policy || false,
          "allowed_secrets" => get_in(policy.policy_document, ["allowed_secrets"]) || [],
          "allowed_operations" => get_in(policy.policy_document, ["allowed_operations"]) || ["read"],
          "conditions" => get_in(policy.policy_document, ["conditions"]) || %{},
          "entity_bindings" => policy.entity_bindings || []
        }

        socket =
          socket
          |> assign(:form_mode, :edit)
          |> assign(:policy, policy)
          |> assign(:form_data, form_data)
          |> assign(:page_title, "Edit Policy: #{policy.name}")

        {:noreply, socket}

      {:error, _reason} ->
        socket =
          socket
          |> put_flash(:error, "Policy not found")
          |> redirect(to: "/admin/policies")

        {:noreply, socket}
    end
  end

  def handle_params(%{"template" => template_name}, _url, socket) do
    case PolicyTemplates.get_template(template_name) do
      nil ->
        socket =
          socket
          |> put_flash(:error, "Template not found")
          |> redirect(to: "/admin/policies/templates")

        {:noreply, socket}

      template ->
        form_data = %{
          "name" => "",
          "description" => template.description,
          "deny_policy" => false,
          "allowed_secrets" => template.policy_document["allowed_secrets"] || [],
          "allowed_operations" => template.policy_document["allowed_operations"] || ["read"],
          "conditions" => template.policy_document["conditions"] || %{},
          "entity_bindings" => []
        }

        socket =
          socket
          |> assign(:form_mode, :create)
          |> assign(:policy, nil)
          |> assign(:form_data, form_data)
          |> assign(:page_title, "Create Policy from Template: #{template.display_name}")
          |> put_flash(:info, "Policy pre-filled from template: #{template.display_name}")

        {:noreply, socket}
    end
  end

  def handle_params(_params, _url, socket) do
    form_data = %{
      "name" => "",
      "description" => "",
      "deny_policy" => false,
      "allowed_secrets" => [],
      "allowed_operations" => ["read"],
      "conditions" => %{},
      "entity_bindings" => []
    }

    socket =
      socket
      |> assign(:form_mode, :create)
      |> assign(:policy, nil)
      |> assign(:form_data, form_data)

    {:noreply, socket}
  end

  @impl true
  def handle_event("switch_tab", %{"tab" => tab}, socket) do
    socket = assign(socket, :active_tab, tab)
    {:noreply, socket}
  end

  @impl true
  def handle_event("update_field", %{"field" => field, "value" => value}, socket) do
    form_data = Map.put(socket.assigns.form_data, field, value)
    socket = assign(socket, :form_data, form_data)
    {:noreply, socket}
  end

  @impl true
  def handle_event("toggle_deny_policy", _params, socket) do
    current = socket.assigns.form_data["deny_policy"]
    form_data = Map.put(socket.assigns.form_data, "deny_policy", !current)
    socket = assign(socket, :form_data, form_data)
    {:noreply, socket}
  end

  @impl true
  def handle_event("add_secret_pattern", %{"pattern" => pattern}, socket) do
    if pattern != "" do
      current_patterns = socket.assigns.form_data["allowed_secrets"]
      new_patterns = [pattern | current_patterns] |> Enum.uniq()
      form_data = Map.put(socket.assigns.form_data, "allowed_secrets", new_patterns)

      {:noreply, assign(socket, :form_data, form_data)}
    else
      {:noreply, socket}
    end
  end

  @impl true
  def handle_event("remove_secret_pattern", %{"pattern" => pattern}, socket) do
    current_patterns = socket.assigns.form_data["allowed_secrets"]
    new_patterns = Enum.reject(current_patterns, &(&1 == pattern))
    form_data = Map.put(socket.assigns.form_data, "allowed_secrets", new_patterns)

    {:noreply, assign(socket, :form_data, form_data)}
  end

  @impl true
  def handle_event("toggle_operation", %{"operation" => operation}, socket) do
    current_ops = socket.assigns.form_data["allowed_operations"]

    new_ops =
      if operation in current_ops do
        Enum.reject(current_ops, &(&1 == operation))
      else
        [operation | current_ops]
      end

    form_data = Map.put(socket.assigns.form_data, "allowed_operations", new_ops)
    {:noreply, assign(socket, :form_data, form_data)}
  end

  @impl true
  def handle_event("update_condition", %{"condition" => condition, "value" => value}, socket) do
    conditions = socket.assigns.form_data["conditions"]

    conditions =
      if value == "" do
        Map.delete(conditions, condition)
      else
        Map.put(conditions, condition, value)
      end

    form_data = Map.put(socket.assigns.form_data, "conditions", conditions)
    {:noreply, assign(socket, :form_data, form_data)}
  end

  @impl true
  def handle_event("toggle_day", %{"day" => day}, socket) do
    conditions = socket.assigns.form_data["conditions"]
    current_days = Map.get(conditions, "days_of_week", [])

    new_days =
      if day in current_days do
        Enum.reject(current_days, &(&1 == day))
      else
        [day | current_days]
      end

    conditions = Map.put(conditions, "days_of_week", new_days)
    form_data = Map.put(socket.assigns.form_data, "conditions", conditions)
    {:noreply, assign(socket, :form_data, form_data)}
  end

  @impl true
  def handle_event("bind_entity", %{"entity_id" => entity_id}, socket) do
    if entity_id != "" do
      current_bindings = socket.assigns.form_data["entity_bindings"]
      new_bindings = [entity_id | current_bindings] |> Enum.uniq()
      form_data = Map.put(socket.assigns.form_data, "entity_bindings", new_bindings)

      {:noreply, assign(socket, :form_data, form_data)}
    else
      {:noreply, socket}
    end
  end

  @impl true
  def handle_event("unbind_entity", %{"entity_id" => entity_id}, socket) do
    current_bindings = socket.assigns.form_data["entity_bindings"]
    new_bindings = Enum.reject(current_bindings, &(&1 == entity_id))
    form_data = Map.put(socket.assigns.form_data, "entity_bindings", new_bindings)

    {:noreply, assign(socket, :form_data, form_data)}
  end

  @impl true
  def handle_event("save_policy", _params, socket) do
    errors = validate_policy_form(socket.assigns.form_data)

    if Enum.empty?(errors) do
      save_policy(socket)
    else
      socket =
        socket
        |> assign(:validation_errors, errors)
        |> put_flash(:error, "Please fix validation errors")

      {:noreply, socket}
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div class="mb-8">
        <div class="flex items-center justify-between">
          <div>
            <h1 class="text-3xl font-bold text-gray-900">
              {if @form_mode == :create, do: "Create Policy", else: "Edit Policy"}
            </h1>
            <p class="mt-2 text-sm text-gray-600">
              Configure policy rules and conditions
            </p>
          </div>
          <.link
            navigate="/admin/policies"
            class="inline-flex items-center px-4 py-2 border border-gray-300 shadow-sm text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50"
          >
            Cancel
          </.link>
        </div>
      </div>
      <!-- Validation Errors -->
      <%= if !Enum.empty?(@validation_errors) do %>
        <div class="mb-6 bg-red-50 border-l-4 border-red-400 p-4">
          <div class="flex">
            <div class="flex-shrink-0">
              <svg
                class="h-5 w-5 text-red-400"
                xmlns="http://www.w3.org/2000/svg"
                viewBox="0 0 20 20"
                fill="currentColor"
              >
                <path
                  fill-rule="evenodd"
                  d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z"
                  clip-rule="evenodd"
                />
              </svg>
            </div>
            <div class="ml-3">
              <h3 class="text-sm font-medium text-red-800">Validation errors:</h3>
              <ul class="mt-2 text-sm text-red-700 list-disc list-inside">
                <%= for error <- @validation_errors do %>
                  <li>{error}</li>
                <% end %>
              </ul>
            </div>
          </div>
        </div>
      <% end %>

      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <!-- Tab Navigation and Form -->
        <div class="lg:col-span-2">
          <div class="bg-white shadow rounded-lg overflow-hidden">
            <!-- Tabs -->
            <div class="border-b border-gray-200">
              <nav class="-mb-px flex space-x-8 px-6" aria-label="Tabs">
                <%= for {tab_id, tab_name} <- [
                  {"basic", "Basic Info"},
                  {"secrets", "Allowed Secrets"},
                  {"operations", "Operations"},
                  {"conditions", "Conditions"},
                  {"entities", "Entity Bindings"}
                ] do %>
                  <button
                    type="button"
                    phx-click="switch_tab"
                    phx-value-tab={tab_id}
                    class={"whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm #{if @active_tab == tab_id, do: "border-blue-500 text-blue-600", else: "border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300"}"}
                  >
                    {tab_name}
                  </button>
                <% end %>
              </nav>
            </div>
            <!-- Tab Content -->
            <div class="p-6">
              <%= case @active_tab do %>
                <% "basic" -> %>
                  <%= render_basic_tab(assigns) %>
                <% "secrets" -> %>
                  <%= render_secrets_tab(assigns) %>
                <% "operations" -> %>
                  <%= render_operations_tab(assigns) %>
                <% "conditions" -> %>
                  <%= render_conditions_tab(assigns) %>
                <% "entities" -> %>
                  <%= render_entities_tab(assigns) %>
              <% end %>
            </div>
          </div>

          <div class="mt-6 flex justify-end gap-3">
            <.link
              navigate="/admin/policies"
              class="inline-flex items-center px-4 py-2 border border-gray-300 shadow-sm text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50"
            >
              Cancel
            </.link>
            <button
              type="button"
              phx-click="save_policy"
              class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700"
            >
              {if @form_mode == :create, do: "Create Policy", else: "Update Policy"}
            </button>
          </div>
        </div>
        <!-- JSON Preview Panel -->
        <div class="lg:col-span-1">
          <div class="bg-white shadow rounded-lg p-6 sticky top-6">
            <h3 class="text-lg font-medium text-gray-900 mb-4">Policy Document Preview</h3>
            <div class="bg-gray-50 rounded-md p-3 overflow-x-auto">
              <pre class="text-xs text-gray-800">{Jason.encode!(build_policy_document(@form_data), pretty: true)}</pre>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
  end

  # Tab render functions

  defp render_basic_tab(assigns) do
    ~H"""
    <div class="space-y-6">
      <div>
        <label class="block text-sm font-medium text-gray-700">
          Policy Name
          <span class="text-red-500">*</span>
        </label>
        <input
          type="text"
          phx-blur="update_field"
          phx-value-field="name"
          value={@form_data["name"]}
          class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
          placeholder="e.g., database-readonly"
          required
        />
        <p class="mt-1 text-xs text-gray-500">
          A unique identifier for this policy
        </p>
      </div>

      <div>
        <label class="block text-sm font-medium text-gray-700">Description</label>
        <textarea
          phx-blur="update_field"
          phx-value-field="description"
          rows="3"
          class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
          placeholder="Describe what this policy controls..."
        >{@form_data["description"]}</textarea>
        <p class="mt-1 text-xs text-gray-500">
          Optional description to explain the policy's purpose
        </p>
      </div>

      <div class="flex items-start">
        <div class="flex items-center h-5">
          <input
            type="checkbox"
            id="deny_policy"
            phx-click="toggle_deny_policy"
            checked={@form_data["deny_policy"]}
            class="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
          />
        </div>
        <div class="ml-3">
          <label for="deny_policy" class="font-medium text-gray-700">Deny Policy</label>
          <p class="text-sm text-gray-500">
            If enabled, this policy will block matching requests instead of allowing them.
            Deny policies take precedence over allow policies.
          </p>
        </div>
      </div>
    </div>
    """
  end

  defp render_secrets_tab(assigns) do
    ~H"""
    <div class="space-y-6">
      <div>
        <label class="block text-sm font-medium text-gray-700 mb-2">
          Allowed Secret Patterns
          <span class="text-red-500">*</span>
        </label>
        <p class="text-sm text-gray-500 mb-4">
          Define which secrets this policy applies to using glob patterns.
          Use <code class="px-1 py-0.5 bg-gray-100 rounded text-xs">*</code>
          to match any segment.
        </p>

        <div class="flex gap-2 mb-3">
          <input
            type="text"
            id="new-pattern-input"
            class="flex-1 border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
            placeholder="e.g., prod.db.*, *.password"
          />
          <button
            type="button"
            phx-click="add_secret_pattern"
            phx-value-pattern={get_input_value("new-pattern-input")}
            class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700"
          >
            Add Pattern
          </button>
        </div>

        <div class="mb-4">
          <h4 class="text-xs font-medium text-gray-700 mb-2">Example Patterns:</h4>
          <ul class="text-xs text-gray-600 space-y-1">
            <li>
              <code class="px-1 py-0.5 bg-gray-100 rounded">prod.db.*</code>
              - Matches all database secrets in production
            </li>
            <li>
              <code class="px-1 py-0.5 bg-gray-100 rounded">*.password</code>
              - Matches all password secrets
            </li>
            <li>
              <code class="px-1 py-0.5 bg-gray-100 rounded">dev.*</code>
              - Matches all development environment secrets
            </li>
          </ul>
        </div>

        <div class="flex flex-wrap gap-2">
          <%= if Enum.empty?(@form_data["allowed_secrets"]) do %>
            <p class="text-sm text-gray-400 italic">No patterns added yet</p>
          <% else %>
            <%= for pattern <- @form_data["allowed_secrets"] do %>
              <span class="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-blue-100 text-blue-800">
                <code class="text-xs">{pattern}</code>
                <button
                  type="button"
                  phx-click="remove_secret_pattern"
                  phx-value-pattern={pattern}
                  class="ml-2 text-blue-600 hover:text-blue-800 font-bold"
                >
                  &times;
                </button>
              </span>
            <% end %>
          <% end %>
        </div>
      </div>
    </div>
    """
  end

  defp render_operations_tab(assigns) do
    ~H"""
    <div class="space-y-6">
      <div>
        <label class="block text-sm font-medium text-gray-700 mb-2">
          Allowed Operations
          <span class="text-red-500">*</span>
        </label>
        <p class="text-sm text-gray-500 mb-4">
          Select which operations are permitted by this policy.
        </p>

        <div class="space-y-3">
          <%= for {op, description} <- [
            {"read", "Allow reading secrets"},
            {"write", "Allow creating and updating secrets"},
            {"delete", "Allow deleting secrets"},
            {"rotate", "Allow rotating secret values"},
            {"renew", "Allow renewing dynamic secret leases"}
          ] do %>
            <label class="flex items-start">
              <div class="flex items-center h-5">
                <input
                  type="checkbox"
                  phx-click="toggle_operation"
                  phx-value-operation={op}
                  checked={op in @form_data["allowed_operations"]}
                  class="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                />
              </div>
              <div class="ml-3">
                <span class="font-medium text-gray-700">{String.capitalize(op)}</span>
                <p class="text-sm text-gray-500">{description}</p>
              </div>
            </label>
          <% end %>
        </div>
      </div>
    </div>
    """
  end

  defp render_conditions_tab(assigns) do
    ~H"""
    <div class="space-y-6">
      <p class="text-sm text-gray-500 mb-4">
        Add optional conditions to restrict when this policy is active.
        Leave fields empty to skip that restriction.
      </p>
      <!-- Time of Day -->
      <div>
        <label class="block text-sm font-medium text-gray-700 mb-2">Time of Day</label>
        <div class="grid grid-cols-2 gap-3">
          <div>
            <label class="block text-xs text-gray-500 mb-1">Start Time</label>
            <input
              type="time"
              id="start-time"
              value={extract_time_range(@form_data["conditions"], :start)}
              class="block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
            />
          </div>
          <div>
            <label class="block text-xs text-gray-500 mb-1">End Time</label>
            <input
              type="time"
              id="end-time"
              value={extract_time_range(@form_data["conditions"], :end)}
              phx-blur="update_condition"
              phx-value-condition="time_of_day"
              phx-value-value={build_time_range("start-time", "end-time")}
              class="block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
            />
          </div>
        </div>
        <p class="mt-1 text-xs text-gray-500">Restrict access to specific hours (UTC)</p>
      </div>
      <!-- Days of Week -->
      <div>
        <label class="block text-sm font-medium text-gray-700 mb-2">Days of Week</label>
        <div class="grid grid-cols-4 gap-2">
          <%= for day <- ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"] do %>
            <label class="flex items-center">
              <input
                type="checkbox"
                phx-click="toggle_day"
                phx-value-day={day}
                checked={day in (Map.get(@form_data["conditions"], "days_of_week") || [])}
                class="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
              />
              <span class="ml-2 text-sm text-gray-700">{String.capitalize(day)}</span>
            </label>
          <% end %>
        </div>
      </div>
      <!-- Date Range -->
      <div>
        <label class="block text-sm font-medium text-gray-700 mb-2">Date Range</label>
        <div class="grid grid-cols-2 gap-3">
          <div>
            <label class="block text-xs text-gray-500 mb-1">Start Date</label>
            <input
              type="date"
              id="start-date"
              class="block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
            />
          </div>
          <div>
            <label class="block text-xs text-gray-500 mb-1">End Date</label>
            <input
              type="date"
              id="end-date"
              phx-blur="update_condition"
              phx-value-condition="date_range"
              phx-value-value={build_date_range("start-date", "end-date")}
              class="block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
            />
          </div>
        </div>
        <p class="mt-1 text-xs text-gray-500">
          Policy only active within this date range
        </p>
      </div>
      <!-- IP Ranges -->
      <div>
        <label class="block text-sm font-medium text-gray-700 mb-2">IP Ranges (CIDR)</label>
        <textarea
          id="ip-ranges"
          phx-blur="update_condition"
          phx-value-condition="ip_ranges"
          phx-value-value={get_textarea_value("ip-ranges")}
          rows="3"
          class="block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm font-mono text-xs"
          placeholder={"10.0.0.0/8\n192.168.1.0/24"}
        >{format_ip_ranges(@form_data["conditions"])}</textarea>
        <p class="mt-1 text-xs text-gray-500">One CIDR block per line</p>
      </div>
      <!-- Max TTL -->
      <div>
        <label class="block text-sm font-medium text-gray-700 mb-2">Maximum TTL (seconds)</label>
        <input
          type="number"
          phx-blur="update_condition"
          phx-value-condition="max_ttl_seconds"
          value={Map.get(@form_data["conditions"], "max_ttl_seconds", "")}
          class="block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
          placeholder="3600"
        />
        <p class="mt-1 text-xs text-gray-500">
          Maximum TTL for dynamic secrets (e.g., 3600 = 1 hour)
        </p>
      </div>
    </div>
    """
  end

  defp render_entities_tab(assigns) do
    ~H"""
    <div class="space-y-6">
      <div>
        <label class="block text-sm font-medium text-gray-700 mb-2">Entity Bindings</label>
        <p class="text-sm text-gray-500 mb-4">
          Bind this policy to specific agents or applications. Leave empty to apply to all entities.
        </p>

        <div class="flex gap-2 mb-3">
          <select
            id="entity-select"
            class="flex-1 border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
          >
            <option value="">Select an agent...</option>
            <%= for agent <- @agents do %>
              <option value={agent.agent_id}>{agent.name} ({agent.agent_id})</option>
            <% end %>
          </select>
          <button
            type="button"
            phx-click="bind_entity"
            phx-value-entity_id={get_select_value("entity-select")}
            class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700"
          >
            Bind Agent
          </button>
        </div>

        <div class="flex flex-wrap gap-2">
          <%= if Enum.empty?(@form_data["entity_bindings"]) do %>
            <p class="text-sm text-gray-400 italic">
              No entities bound. Policy will apply to all entities.
            </p>
          <% else %>
            <%= for entity_id <- @form_data["entity_bindings"] do %>
              <span class="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-green-100 text-green-800">
                {entity_id}
                <button
                  type="button"
                  phx-click="unbind_entity"
                  phx-value-entity_id={entity_id}
                  class="ml-2 text-green-600 hover:text-green-800 font-bold"
                >
                  &times;
                </button>
              </span>
            <% end %>
          <% end %>
        </div>
      </div>
    </div>
    """
  end

  # Private functions

  defp save_policy(socket) do
    attrs = %{
      "name" => socket.assigns.form_data["name"],
      "description" => socket.assigns.form_data["description"],
      "deny_policy" => socket.assigns.form_data["deny_policy"],
      "policy_document" => build_policy_document(socket.assigns.form_data),
      "entity_bindings" => socket.assigns.form_data["entity_bindings"]
    }

    case socket.assigns.form_mode do
      :create ->
        case Policies.create_policy(attrs) do
          {:ok, _policy} ->
            socket =
              socket
              |> put_flash(:info, "Policy created successfully")
              |> redirect(to: "/admin/policies")

            {:noreply, socket}

          {:error, changeset} ->
            errors = extract_changeset_errors(changeset)

            socket =
              socket
              |> assign(:validation_errors, errors)
              |> put_flash(:error, "Failed to create policy")

            {:noreply, socket}
        end

      :edit ->
        case Policies.update_policy(socket.assigns.policy.id, attrs) do
          {:ok, _policy} ->
            socket =
              socket
              |> put_flash(:info, "Policy updated successfully")
              |> redirect(to: "/admin/policies")

            {:noreply, socket}

          {:error, changeset} ->
            errors = extract_changeset_errors(changeset)

            socket =
              socket
              |> assign(:validation_errors, errors)
              |> put_flash(:error, "Failed to update policy")

            {:noreply, socket}
        end
    end
  end

  defp build_policy_document(form_data) do
    %{
      "version" => "1.0",
      "allowed_secrets" => form_data["allowed_secrets"],
      "allowed_operations" => form_data["allowed_operations"],
      "conditions" => form_data["conditions"]
    }
  end

  defp validate_policy_form(form_data) do
    errors = []

    errors =
      if form_data["name"] == "" || is_nil(form_data["name"]) do
        ["Policy name is required" | errors]
      else
        errors
      end

    errors =
      if Enum.empty?(form_data["allowed_secrets"]) do
        ["At least one secret pattern is required" | errors]
      else
        errors
      end

    errors =
      if Enum.empty?(form_data["allowed_operations"]) do
        ["At least one operation must be allowed" | errors]
      else
        errors
      end

    errors
  end

  defp extract_changeset_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
    |> Enum.map(fn {field, errors} -> "#{field}: #{Enum.join(errors, ", ")}" end)
  end

  defp list_agents do
    Agents.list_agents()
  end

  # Helper functions for form values (would need JS hooks in production)
  defp get_input_value(_id), do: ""
  defp get_select_value(_id), do: ""
  defp get_textarea_value(_id), do: ""
  defp build_time_range(_start_id, _end_id), do: ""
  defp build_date_range(_start_id, _end_id), do: ""

  defp extract_time_range(conditions, :start) do
    case Map.get(conditions, "time_of_day") do
      nil -> ""
      range -> String.split(range, "-") |> List.first() || ""
    end
  end

  defp extract_time_range(conditions, :end) do
    case Map.get(conditions, "time_of_day") do
      nil -> ""
      range -> String.split(range, "-") |> List.last() || ""
    end
  end

  defp format_ip_ranges(conditions) do
    case Map.get(conditions, "ip_ranges") do
      nil -> ""
      ranges when is_list(ranges) -> Enum.join(ranges, "\n")
      _ -> ""
    end
  end
end
