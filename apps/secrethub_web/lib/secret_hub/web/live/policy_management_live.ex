defmodule SecretHub.Web.PolicyManagementLive do
  @moduledoc """
  LiveView for comprehensive policy management.

  Features:
  - Create, read, update, delete policies
  - Policy document JSON editor with validation
  - Entity binding management
  - Policy testing and preview
  - Wildcard pattern testing
  """

  use SecretHub.Web, :live_view
  require Logger

  alias SecretHub.Core.{Agents, Policies}

  @impl true
  def mount(_params, _session, socket) do
    policies = list_policies()
    agents = list_agents()

    socket =
      socket
      |> assign(:policies, policies)
      |> assign(:agents, agents)
      |> assign(:selected_policy, nil)
      |> assign(:show_form, false)
      |> assign(:form_mode, :create)
      |> assign(:form_data, %{
        "name" => "",
        "description" => "",
        "deny_policy" => false,
        "policy_document" => %{
          "version" => "1.0",
          "allowed_secrets" => [],
          "allowed_operations" => ["read"],
          "conditions" => %{}
        },
        "entity_bindings" => []
      })
      |> assign(:validation_errors, [])
      |> assign(:test_mode, false)
      |> assign(:test_entity_id, "")
      |> assign(:test_secret_path, "")
      |> assign(:test_operation, "read")
      |> assign(:test_result, nil)
      |> assign(:page_title, "Policy Management")

    {:ok, socket}
  end

  @impl true
  def handle_event("new_policy", _params, socket) do
    socket =
      socket
      |> assign(:show_form, true)
      |> assign(:form_mode, :create)
      |> assign(:selected_policy, nil)
      |> assign(:form_data, %{
        "name" => "",
        "description" => "",
        "deny_policy" => false,
        "policy_document" => %{
          "version" => "1.0",
          "allowed_secrets" => [],
          "allowed_operations" => ["read"],
          "conditions" => %{}
        },
        "entity_bindings" => []
      })
      |> assign(:validation_errors, [])

    {:noreply, socket}
  end

  @impl true
  def handle_event("edit_policy", %{"policy_id" => policy_id}, socket) do
    case Policies.get_policy(policy_id) do
      {:ok, policy} ->
        form_data = %{
          "name" => policy.name,
          "description" => policy.description || "",
          "deny_policy" => policy.deny_policy || false,
          "policy_document" => policy.policy_document || default_policy_document(),
          "entity_bindings" => policy.entity_bindings || []
        }

        socket =
          socket
          |> assign(:show_form, true)
          |> assign(:form_mode, :edit)
          |> assign(:selected_policy, policy)
          |> assign(:form_data, form_data)
          |> assign(:validation_errors, [])

        {:noreply, socket}

      {:error, reason} ->
        socket =
          socket
          |> put_flash(:error, "Failed to load policy: #{inspect(reason)}")

        {:noreply, socket}
    end
  end

  @impl true
  def handle_event("delete_policy", %{"policy_id" => policy_id}, socket) do
    case Policies.delete_policy(policy_id) do
      {:ok, _deleted} ->
        policies = list_policies()

        socket =
          socket
          |> assign(:policies, policies)
          |> put_flash(:info, "Policy deleted successfully")

        {:noreply, socket}

      {:error, reason} ->
        socket =
          socket
          |> put_flash(:error, "Failed to delete policy: #{inspect(reason)}")

        {:noreply, socket}
    end
  end

  @impl true
  def handle_event("update_form", %{"field" => field, "value" => value}, socket) do
    form_data = Map.put(socket.assigns.form_data, field, value)
    socket = assign(socket, :form_data, form_data)
    {:noreply, socket}
  end

  @impl true
  def handle_event("update_policy_document", %{"document" => doc_json}, socket) do
    case Jason.decode(doc_json) do
      {:ok, document} ->
        errors = validate_policy_document(document)

        form_data = put_in(socket.assigns.form_data, ["policy_document"], document)

        socket =
          socket
          |> assign(:form_data, form_data)
          |> assign(:validation_errors, errors)

        {:noreply, socket}

      {:error, %Jason.DecodeError{} = error} ->
        socket =
          socket
          |> assign(:validation_errors, ["Invalid JSON: #{Exception.message(error)}"])

        {:noreply, socket}
    end
  end

  @impl true
  def handle_event("add_secret_pattern", %{"pattern" => pattern}, socket) do
    if pattern != "" do
      current_patterns =
        get_in(socket.assigns.form_data, ["policy_document", "allowed_secrets"]) || []

      new_patterns = [pattern | current_patterns] |> Enum.uniq()

      form_data =
        put_in(socket.assigns.form_data, ["policy_document", "allowed_secrets"], new_patterns)

      {:noreply, assign(socket, :form_data, form_data)}
    else
      {:noreply, socket}
    end
  end

  @impl true
  def handle_event("remove_secret_pattern", %{"pattern" => pattern}, socket) do
    current_patterns =
      get_in(socket.assigns.form_data, ["policy_document", "allowed_secrets"]) || []

    new_patterns = Enum.reject(current_patterns, &(&1 == pattern))

    form_data =
      put_in(socket.assigns.form_data, ["policy_document", "allowed_secrets"], new_patterns)

    {:noreply, assign(socket, :form_data, form_data)}
  end

  @impl true
  def handle_event("toggle_operation", %{"operation" => operation}, socket) do
    current_ops =
      get_in(socket.assigns.form_data, ["policy_document", "allowed_operations"]) || []

    new_ops =
      if operation in current_ops do
        Enum.reject(current_ops, &(&1 == operation))
      else
        [operation | current_ops]
      end

    form_data =
      put_in(socket.assigns.form_data, ["policy_document", "allowed_operations"], new_ops)

    {:noreply, assign(socket, :form_data, form_data)}
  end

  @impl true
  def handle_event("bind_entity", %{"entity_id" => entity_id}, socket) do
    if entity_id != "" do
      current_bindings = socket.assigns.form_data["entity_bindings"] || []
      new_bindings = [entity_id | current_bindings] |> Enum.uniq()

      form_data = Map.put(socket.assigns.form_data, "entity_bindings", new_bindings)

      {:noreply, assign(socket, :form_data, form_data)}
    else
      {:noreply, socket}
    end
  end

  @impl true
  def handle_event("unbind_entity", %{"entity_id" => entity_id}, socket) do
    current_bindings = socket.assigns.form_data["entity_bindings"] || []
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
  def handle_event("cancel_form", _params, socket) do
    socket =
      socket
      |> assign(:show_form, false)
      |> assign(:validation_errors, [])

    {:noreply, socket}
  end

  @impl true
  def handle_event("toggle_test_mode", _params, socket) do
    {:noreply, assign(socket, :test_mode, !socket.assigns.test_mode)}
  end

  @impl true
  def handle_event(
        "test_policy",
        %{"entity_id" => entity_id, "secret_path" => secret_path, "operation" => operation},
        socket
      ) do
    if socket.assigns.selected_policy do
      result =
        Policies.evaluate_access(entity_id, secret_path, operation, %{})

      socket =
        socket
        |> assign(:test_result, %{
          success: match?({:ok, _}, result),
          message:
            case result do
              {:ok, policy} -> "Access granted by policy: #{policy.name}"
              {:error, reason} -> "Access denied: #{reason}"
            end
        })

      {:noreply, socket}
    else
      {:noreply, socket}
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div class="mb-8">
        <h1 class="text-3xl font-bold text-on-surface">Policy Management</h1>
        <p class="mt-2 text-sm text-on-surface-variant">
          Create and manage access control policies for secrets.
        </p>
      </div>
      
    <!-- Create New Policy Button -->
      <div class="mb-6 flex justify-between items-center">
        <div class="flex gap-3">
          <.link
            navigate="/admin/policies/new"
            class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-primary-content bg-primary hover:bg-primary focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary"
          >
            <svg
              class="-ml-1 mr-2 h-5 w-5"
              xmlns="http://www.w3.org/2000/svg"
              viewBox="0 0 20 20"
              fill="currentColor"
            >
              <path
                fill-rule="evenodd"
                d="M10 3a1 1 0 011 1v5h5a1 1 0 110 2h-5v5a1 1 0 11-2 0v-5H4a1 1 0 110-2h5V4a1 1 0 011-1z"
                clip-rule="evenodd"
              />
            </svg>
            Create New Policy
          </.link>
          <.link
            navigate="/admin/policies/templates"
            class="inline-flex items-center px-4 py-2 border border-primary shadow-sm text-sm font-medium rounded-md text-primary bg-surface-container hover:bg-primary/5"
          >
            <svg
              class="-ml-1 mr-2 h-5 w-5"
              xmlns="http://www.w3.org/2000/svg"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path
                stroke-linecap="round"
                stroke-linejoin="round"
                stroke-width="2"
                d="M4 5a1 1 0 011-1h14a1 1 0 011 1v2a1 1 0 01-1 1H5a1 1 0 01-1-1V5zM4 13a1 1 0 011-1h6a1 1 0 011 1v6a1 1 0 01-1 1H5a1 1 0 01-1-1v-6zM16 13a1 1 0 011-1h2a1 1 0 011 1v6a1 1 0 01-1 1h-2a1 1 0 01-1-1v-6z"
              />
            </svg>
            From Template
          </.link>
        </div>
      </div>
      
    <!-- Policy Form Modal -->
      <%= if @show_form do %>
        <div class="fixed inset-0 bg-surface-container-low0 bg-opacity-75 z-40 flex items-center justify-center p-4">
          <div class="bg-surface-container rounded-lg shadow-xl max-w-4xl w-full max-h-[90vh] overflow-y-auto">
            <div class="px-6 py-4 border-b border-outline-variant">
              <h3 class="text-lg font-medium text-on-surface">
                {if @form_mode == :create, do: "Create New Policy", else: "Edit Policy"}
              </h3>
            </div>

            <div class="px-6 py-4 space-y-6">
              <!-- Validation Errors -->
              <%= if !Enum.empty?(@validation_errors) do %>
                <div class="bg-error/5 border-l-4 border-error p-4">
                  <div class="flex">
                    <div class="flex-shrink-0">
                      <svg
                        class="h-5 w-5 text-error"
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
                      <h3 class="text-sm font-medium text-error">Validation errors:</h3>
                      <ul class="mt-2 text-sm text-error list-disc list-inside">
                        <%= for error <- @validation_errors do %>
                          <li>{error}</li>
                        <% end %>
                      </ul>
                    </div>
                  </div>
                </div>
              <% end %>
              
    <!-- Basic Information -->
              <div>
                <label class="block text-sm font-medium text-on-surface">Policy Name</label>
                <input
                  type="text"
                  phx-blur="update_form"
                  phx-value-field="name"
                  value={@form_data["name"]}
                  class="mt-1 block w-full border border-outline-variant rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-primary focus:border-primary sm:text-sm"
                  placeholder="e.g., database-readonly"
                  required
                />
              </div>

              <div>
                <label class="block text-sm font-medium text-on-surface">Description</label>
                <textarea
                  phx-blur="update_form"
                  phx-value-field="description"
                  rows="3"
                  class="mt-1 block w-full border border-outline-variant rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-primary focus:border-primary sm:text-sm"
                  placeholder="Describe what this policy controls..."
                >{@form_data["description"]}</textarea>
              </div>

              <div class="flex items-center">
                <input
                  type="checkbox"
                  id="deny_policy"
                  phx-click="update_form"
                  phx-value-field="deny_policy"
                  phx-value-value={to_string(!@form_data["deny_policy"])}
                  checked={@form_data["deny_policy"]}
                  class="h-4 w-4 text-primary focus:ring-primary border-outline-variant rounded"
                />
                <label for="deny_policy" class="ml-2 block text-sm text-on-surface">
                  Deny Policy (blocks matching requests instead of allowing them)
                </label>
              </div>
              
    <!-- Secret Patterns -->
              <div>
                <label class="block text-sm font-medium text-on-surface mb-2">
                  Allowed Secret Patterns
                </label>
                <div class="flex gap-2 mb-2">
                  <input
                    type="text"
                    id="new-pattern"
                    class="flex-1 border border-outline-variant rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-primary focus:border-primary sm:text-sm"
                    placeholder="e.g., prod.db.*, *.password"
                  />
                  <button
                    phx-click="add_secret_pattern"
                    phx-value-pattern={Phoenix.HTML.Form.input_value(assigns, :new_pattern) || ""}
                    type="button"
                    class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-primary-content bg-primary hover:bg-primary"
                  >
                    Add
                  </button>
                </div>
                <div class="flex flex-wrap gap-2">
                  <%= for pattern <- get_in(@form_data, ["policy_document", "allowed_secrets"]) || [] do %>
                    <span class="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-primary/10 text-primary">
                      <code class="text-xs">{pattern}</code>
                      <button
                        type="button"
                        phx-click="remove_secret_pattern"
                        phx-value-pattern={pattern}
                        class="ml-2 text-primary hover:text-primary"
                      >
                        &times;
                      </button>
                    </span>
                  <% end %>
                </div>
              </div>
              
    <!-- Allowed Operations -->
              <div>
                <label class="block text-sm font-medium text-on-surface mb-2">
                  Allowed Operations
                </label>
                <div class="space-y-2">
                  <%= for op <- ["read", "write", "delete", "renew"] do %>
                    <label class="inline-flex items-center mr-4">
                      <input
                        type="checkbox"
                        phx-click="toggle_operation"
                        phx-value-operation={op}
                        checked={
                          op in (get_in(@form_data, ["policy_document", "allowed_operations"]) || [])
                        }
                        class="h-4 w-4 text-primary focus:ring-primary border-outline-variant rounded"
                      />
                      <span class="ml-2 text-sm text-on-surface">{String.capitalize(op)}</span>
                    </label>
                  <% end %>
                </div>
              </div>
              
    <!-- Entity Bindings -->
              <div>
                <label class="block text-sm font-medium text-on-surface mb-2">Entity Bindings</label>
                <div class="flex gap-2 mb-2">
                  <select
                    id="entity-select"
                    class="flex-1 border border-outline-variant rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-primary focus:border-primary sm:text-sm"
                  >
                    <option value="">Select an agent...</option>
                    <%= for agent <- @agents do %>
                      <option value={agent.agent_id}>{agent.name} ({agent.agent_id})</option>
                    <% end %>
                  </select>
                  <button
                    type="button"
                    phx-click="bind_entity"
                    phx-value-entity_id=""
                    class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-primary-content bg-primary hover:bg-primary"
                  >
                    Bind
                  </button>
                </div>
                <div class="flex flex-wrap gap-2">
                  <%= for entity_id <- @form_data["entity_bindings"] || [] do %>
                    <span class="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-success/10 text-success">
                      {entity_id}
                      <button
                        type="button"
                        phx-click="unbind_entity"
                        phx-value-entity_id={entity_id}
                        class="ml-2 text-success hover:text-success"
                      >
                        &times;
                      </button>
                    </span>
                  <% end %>
                </div>
              </div>
              
    <!-- Policy Document JSON -->
              <div>
                <label class="block text-sm font-medium text-on-surface mb-2">
                  Policy Document (JSON)
                </label>
                <textarea
                  phx-blur="update_policy_document"
                  name="document"
                  rows="10"
                  class="font-mono text-xs block w-full border border-outline-variant rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-primary focus:border-primary"
                >{Jason.encode!(@form_data["policy_document"], pretty: true)}</textarea>
                <p class="mt-1 text-sm text-on-surface-variant">
                  Advanced: Edit the raw JSON policy document. Changes above are reflected here.
                </p>
              </div>
            </div>

            <div class="px-6 py-4 border-t border-outline-variant flex justify-end space-x-3">
              <button
                type="button"
                phx-click="cancel_form"
                class="inline-flex items-center px-4 py-2 border border-outline-variant shadow-sm text-sm font-medium rounded-md text-on-surface bg-surface-container hover:bg-surface-container-low"
              >
                Cancel
              </button>
              <button
                type="button"
                phx-click="save_policy"
                class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-primary-content bg-primary hover:bg-primary"
              >
                {if @form_mode == :create, do: "Create Policy", else: "Update Policy"}
              </button>
            </div>
          </div>
        </div>
      <% end %>
      
    <!-- Test Mode Panel -->
      <%= if @test_mode && @selected_policy do %>
        <div class="bg-warning/5 border-l-4 border-warning p-4 mb-6">
          <div class="flex">
            <div class="flex-shrink-0">
              <svg
                class="h-5 w-5 text-warning"
                xmlns="http://www.w3.org/2000/svg"
                viewBox="0 0 20 20"
                fill="currentColor"
              >
                <path
                  fill-rule="evenodd"
                  d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z"
                  clip-rule="evenodd"
                />
              </svg>
            </div>
            <div class="ml-3 flex-1">
              <h3 class="text-sm font-medium text-warning">
                Test Policy: {@selected_policy.name}
              </h3>
              <form phx-submit="test_policy" class="mt-4 grid grid-cols-3 gap-4">
                <div>
                  <label class="block text-xs font-medium text-warning">Entity ID</label>
                  <input
                    type="text"
                    name="entity_id"
                    value={@test_entity_id}
                    class="mt-1 block w-full border border-warning rounded-md shadow-sm py-1 px-2 text-sm"
                    placeholder="agent-001"
                  />
                </div>
                <div>
                  <label class="block text-xs font-medium text-warning">Secret Path</label>
                  <input
                    type="text"
                    name="secret_path"
                    value={@test_secret_path}
                    class="mt-1 block w-full border border-warning rounded-md shadow-sm py-1 px-2 text-sm"
                    placeholder="prod.db.postgres"
                  />
                </div>
                <div>
                  <label class="block text-xs font-medium text-warning">Operation</label>
                  <select
                    name="operation"
                    value={@test_operation}
                    class="mt-1 block w-full border border-warning rounded-md shadow-sm py-1 px-2 text-sm"
                  >
                    <option value="read">Read</option>
                    <option value="write">Write</option>
                    <option value="delete">Delete</option>
                    <option value="renew">Renew</option>
                  </select>
                </div>
                <div class="col-span-3">
                  <button
                    type="submit"
                    class="inline-flex items-center px-3 py-1 border border-transparent text-sm font-medium rounded-md text-warning bg-warning/10 hover:bg-warning/20"
                  >
                    Test Access
                  </button>
                </div>
              </form>
              <%= if @test_result do %>
                <div class={"mt-4 p-3 rounded-md #{if @test_result.success, do: "bg-success/10", else: "bg-error/10"}"}>
                  <p class={"text-sm font-medium #{if @test_result.success, do: "text-success", else: "text-error"}"}>
                    {@test_result.message}
                  </p>
                </div>
              <% end %>
            </div>
          </div>
        </div>
      <% end %>
      
    <!-- Policies List -->
      <div class="bg-surface-container shadow overflow-hidden sm:rounded-md">
        <ul role="list" class="divide-y divide-outline-variant">
          <%= if Enum.empty?(@policies) do %>
            <li class="px-6 py-12 text-center">
              <p class="text-on-surface-variant">
                No policies created yet. Create your first policy to get started.
              </p>
            </li>
          <% else %>
            <%= for policy <- @policies do %>
              <li class="px-6 py-4 hover:bg-surface-container-low">
                <div class="flex items-center justify-between">
                  <div class="flex-1">
                    <div class="flex items-center">
                      <div class="flex-shrink-0">
                        <div class={"h-10 w-10 rounded-full flex items-center justify-center #{if policy.deny_policy, do: "bg-error/10", else: "bg-success/10"}"}>
                          <%= if policy.deny_policy do %>
                            <svg
                              class="h-6 w-6 text-error"
                              xmlns="http://www.w3.org/2000/svg"
                              fill="none"
                              viewBox="0 0 24 24"
                              stroke="currentColor"
                            >
                              <path
                                stroke-linecap="round"
                                stroke-linejoin="round"
                                stroke-width="2"
                                d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636"
                              />
                            </svg>
                          <% else %>
                            <svg
                              class="h-6 w-6 text-success"
                              xmlns="http://www.w3.org/2000/svg"
                              fill="none"
                              viewBox="0 0 24 24"
                              stroke="currentColor"
                            >
                              <path
                                stroke-linecap="round"
                                stroke-linejoin="round"
                                stroke-width="2"
                                d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                              />
                            </svg>
                          <% end %>
                        </div>
                      </div>
                      <div class="ml-4">
                        <div class="text-sm font-medium text-on-surface">{policy.name}</div>
                        <div class="text-sm text-on-surface-variant">{policy.description}</div>
                        <div class="mt-1 flex items-center gap-2 flex-wrap">
                          <span class={"inline-flex items-center px-2 py-0.5 rounded text-xs font-medium #{if policy.deny_policy, do: "bg-error/10 text-error", else: "bg-success/10 text-success"}"}>
                            {if policy.deny_policy, do: "DENY", else: "ALLOW"}
                          </span>
                          <%= if policy.entity_bindings && length(policy.entity_bindings) > 0 do %>
                            <span class="text-xs text-on-surface-variant">
                              {length(policy.entity_bindings)} entity binding(s)
                            </span>
                          <% else %>
                            <span class="text-xs text-on-surface-variant">No bindings</span>
                          <% end %>
                          {render_conditions_summary(policy)}
                        </div>
                      </div>
                    </div>
                  </div>
                  <div class="ml-4 flex-shrink-0 flex space-x-2">
                    <.link
                      navigate={"/admin/policies/#{policy.id}/simulate"}
                      class="inline-flex items-center px-3 py-1.5 border border-primary shadow-sm text-xs font-medium rounded text-primary bg-surface-container hover:bg-primary/5"
                    >
                      <svg
                        class="-ml-0.5 mr-1 h-4 w-4"
                        xmlns="http://www.w3.org/2000/svg"
                        fill="none"
                        viewBox="0 0 24 24"
                        stroke="currentColor"
                      >
                        <path
                          stroke-linecap="round"
                          stroke-linejoin="round"
                          stroke-width="2"
                          d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"
                        />
                        <path
                          stroke-linecap="round"
                          stroke-linejoin="round"
                          stroke-width="2"
                          d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
                        />
                      </svg>
                      Simulate
                    </.link>
                    <.link
                      navigate={"/admin/policies/#{policy.id}/edit"}
                      class="inline-flex items-center px-3 py-1.5 border border-outline-variant shadow-sm text-xs font-medium rounded text-on-surface bg-surface-container hover:bg-surface-container-low"
                    >
                      Edit
                    </.link>
                    <button
                      phx-click="delete_policy"
                      phx-value-policy_id={policy.id}
                      data-confirm="Are you sure you want to delete this policy?"
                      class="inline-flex items-center px-3 py-1.5 border border-error shadow-sm text-xs font-medium rounded text-error bg-surface-container hover:bg-error/5"
                    >
                      Delete
                    </button>
                  </div>
                </div>
              </li>
            <% end %>
          <% end %>
        </ul>
      </div>
    </div>
    """
  end

  # Private functions

  defp save_policy(socket) do
    attrs =
      socket.assigns.form_data
      |> Map.put("entity_bindings", socket.assigns.form_data["entity_bindings"] || [])

    case socket.assigns.form_mode do
      :create -> create_new_policy(socket, attrs)
      :edit -> update_existing_policy(socket, attrs)
    end
  end

  defp create_new_policy(socket, attrs) do
    case Policies.create_policy(attrs) do
      {:ok, policy} ->
        bind_entities_to_policy(policy, attrs["entity_bindings"] || [])
        handle_policy_save_success(socket, "Policy created successfully")

      {:error, changeset} ->
        handle_policy_save_error(socket, changeset, "Failed to create policy")
    end
  end

  defp update_existing_policy(socket, attrs) do
    case Policies.update_policy(socket.assigns.selected_policy.id, attrs) do
      {:ok, policy} ->
        update_policy_bindings(socket, policy, attrs)
        handle_policy_save_success(socket, "Policy updated successfully")

      {:error, changeset} ->
        handle_policy_save_error(socket, changeset, "Failed to update policy")
    end
  end

  defp bind_entities_to_policy(policy, entity_ids) do
    Enum.each(entity_ids, fn entity_id ->
      Policies.bind_policy_to_entity(policy.id, entity_id)
    end)
  end

  defp update_policy_bindings(socket, policy, attrs) do
    current_bindings = socket.assigns.selected_policy.entity_bindings || []
    new_bindings = attrs["entity_bindings"] || []

    Enum.each(current_bindings -- new_bindings, fn entity_id ->
      Policies.unbind_policy_from_entity(policy.id, entity_id)
    end)

    Enum.each(new_bindings -- current_bindings, fn entity_id ->
      Policies.bind_policy_to_entity(policy.id, entity_id)
    end)
  end

  defp handle_policy_save_success(socket, message) do
    policies = list_policies()

    socket =
      socket
      |> assign(:policies, policies)
      |> assign(:show_form, false)
      |> put_flash(:info, message)

    {:noreply, socket}
  end

  defp handle_policy_save_error(socket, changeset, message) do
    errors = extract_changeset_errors(changeset)

    socket =
      socket
      |> assign(:validation_errors, errors)
      |> put_flash(:error, message)

    {:noreply, socket}
  end

  defp list_policies do
    Policies.list_policies()
  end

  defp list_agents do
    Agents.list_agents()
  end

  defp validate_policy_form(form_data) do
    errors = []

    errors =
      if form_data["name"] == "" || is_nil(form_data["name"]) do
        ["Policy name is required" | errors]
      else
        errors
      end

    errors = errors ++ validate_policy_document(form_data["policy_document"])

    errors
  end

  defp validate_policy_document(document) when is_map(document) do
    errors = []

    errors =
      if is_nil(document["allowed_secrets"]) || Enum.empty?(document["allowed_secrets"]) do
        ["At least one secret pattern is required" | errors]
      else
        errors
      end

    errors =
      if is_nil(document["allowed_operations"]) || Enum.empty?(document["allowed_operations"]) do
        ["At least one operation must be allowed" | errors]
      else
        errors
      end

    errors
  end

  defp validate_policy_document(_), do: ["Policy document must be a valid JSON object"]

  defp extract_changeset_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
    |> Enum.map(fn {field, errors} -> "#{field}: #{Enum.join(errors, ", ")}" end)
  end

  defp default_policy_document do
    %{
      "version" => "1.0",
      "allowed_secrets" => [],
      "allowed_operations" => ["read"],
      "conditions" => %{}
    }
  end

  defp render_conditions_summary(policy) do
    conditions = get_in(policy.policy_document, ["conditions"]) || %{}
    assigns = %{conditions: conditions}

    if map_size(conditions) == 0 do
      ~H""
    else
      ~H"""
      <%= if Map.has_key?(@conditions, "time_of_day") do %>
        <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-warning/10 text-warning">
          Time: {@conditions["time_of_day"]}
        </span>
      <% end %>
      <%= if Map.has_key?(@conditions, "days_of_week") do %>
        <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-warning/10 text-warning">
          Days: {length(@conditions["days_of_week"])}
        </span>
      <% end %>
      <%= if Map.has_key?(@conditions, "ip_ranges") do %>
        <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-tertiary/10 text-tertiary">
          IP Restricted
        </span>
      <% end %>
      <%= if Map.has_key?(@conditions, "max_ttl_seconds") do %>
        <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-primary/10 text-primary">
          Max TTL: {@conditions["max_ttl_seconds"]}s
        </span>
      <% end %>
      """
    end
  end
end
