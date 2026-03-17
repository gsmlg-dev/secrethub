defmodule SecretHub.Web.AppRoleManagementLive do
  @moduledoc """
  LiveView for managing AppRoles.

  Allows administrators to:
  - Create new AppRoles for agent authentication
  - View existing AppRoles
  - Generate new SecretIDs
  - View RoleID/SecretID pairs (one-time display)
  - Delete AppRoles
  """

  use SecretHub.Web, :live_view
  import Ecto.Query

  alias SecretHub.Core.Auth.AppRole
  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.Role

  @impl true
  def mount(_params, _session, socket) do
    roles = list_approles()

    socket =
      socket
      |> assign(:roles, roles)
      |> assign(:creating_role, false)
      |> assign(:new_role_name, "")
      |> assign(:new_role_policies, "")
      |> assign(:new_role_result, nil)
      |> assign(:selected_role, nil)
      |> assign(:page_title, "AppRole Management")

    {:ok, socket}
  end

  @impl true
  def handle_event("toggle_create_form", _params, socket) do
    {:noreply, assign(socket, :creating_role, !socket.assigns.creating_role)}
  end

  @impl true
  def handle_event("create_role", %{"role_name" => role_name, "policies" => policies_str}, socket) do
    # Parse policies from comma-separated string
    policies =
      policies_str
      |> String.split(",")
      |> Enum.map(&String.trim/1)
      |> Enum.reject(&(&1 == ""))

    case AppRole.create_role(role_name, policies: policies) do
      {:ok, result} ->
        # Show the RoleID and SecretID to the user (one-time display)
        socket =
          socket
          |> assign(:new_role_result, result)
          |> assign(:creating_role, false)
          |> assign(:new_role_name, "")
          |> assign(:new_role_policies, "")
          |> assign(:roles, list_approles())
          |> put_flash(
            :info,
            "AppRole created successfully! Save the RoleID and SecretID - they will only be shown once."
          )

        {:noreply, socket}

      {:error, reason} ->
        socket = put_flash(socket, :error, "Failed to create AppRole: #{inspect(reason)}")
        {:noreply, socket}
    end
  end

  @impl true
  def handle_event("close_credentials", _params, socket) do
    {:noreply, assign(socket, :new_role_result, nil)}
  end

  @impl true
  def handle_event("generate_secret_id", %{"role_id" => role_id}, socket) do
    case AppRole.generate_secret_id(role_id) do
      {:ok, secret_id} ->
        socket =
          socket
          |> put_flash(:info, "New SecretID generated successfully!")
          |> assign(:new_secret_id, %{role_id: role_id, secret_id: secret_id})

        {:noreply, socket}

      {:error, reason} ->
        socket = put_flash(socket, :error, "Failed to generate SecretID: #{inspect(reason)}")
        {:noreply, socket}
    end
  end

  @impl true
  def handle_event("delete_role", %{"role_id" => role_id}, socket) do
    case AppRole.delete_role(role_id) do
      :ok ->
        socket =
          socket
          |> assign(:roles, list_approles())
          |> put_flash(:info, "AppRole deleted successfully")

        {:noreply, socket}

      {:error, reason} ->
        socket = put_flash(socket, :error, "Failed to delete AppRole: #{inspect(reason)}")
        {:noreply, socket}
    end
  end

  @impl true
  def handle_event("view_role", %{"role_id" => role_id}, socket) do
    case AppRole.get_role(role_id) do
      {:ok, role_info} ->
        {:noreply, assign(socket, :selected_role, role_info)}

      {:error, _reason} ->
        {:noreply, put_flash(socket, :error, "Failed to load role details")}
    end
  end

  @impl true
  def handle_event("close_role_details", _params, socket) do
    {:noreply, assign(socket, :selected_role, nil)}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div class="mb-8">
        <h1 class="text-3xl font-bold text-on-surface">AppRole Management</h1>
        <p class="mt-2 text-sm text-on-surface-variant">
          Manage AppRoles for agent authentication. Each AppRole has a RoleID and one or more SecretIDs.
        </p>
      </div>
      
    <!-- Create New AppRole Button -->
      <div class="mb-6">
        <button
          phx-click="toggle_create_form"
          class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-on-primary bg-primary hover:bg-primary focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary"
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
          Create New AppRole
        </button>
      </div>
      
    <!-- Create Role Form -->
      <%= if @creating_role do %>
        <div class="bg-surface-container shadow sm:rounded-lg mb-6">
          <div class="px-4 py-5 sm:p-6">
            <h3 class="text-lg leading-6 font-medium text-on-surface">Create New AppRole</h3>
            <div class="mt-4">
              <form phx-submit="create_role" class="space-y-4">
                <div>
                  <label for="role_name" class="block text-sm font-medium text-on-surface">
                    Role Name
                  </label>
                  <input
                    type="text"
                    name="role_name"
                    id="role_name"
                    required
                    value={@new_role_name}
                    class="mt-1 block w-full border border-outline-variant rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-primary focus:border-primary sm:text-sm"
                    placeholder="e.g., production-app, staging-agent"
                  />
                </div>

                <div>
                  <label for="policies" class="block text-sm font-medium text-on-surface">
                    Policies (comma-separated)
                  </label>
                  <input
                    type="text"
                    name="policies"
                    id="policies"
                    value={@new_role_policies}
                    class="mt-1 block w-full border border-outline-variant rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-primary focus:border-primary sm:text-sm"
                    placeholder="e.g., secret-read, secret-write"
                  />
                  <p class="mt-1 text-sm text-on-surface-variant">
                    Enter policy names separated by commas
                  </p>
                </div>

                <div class="flex justify-end space-x-3">
                  <button
                    type="button"
                    phx-click="toggle_create_form"
                    class="inline-flex items-center px-4 py-2 border border-outline-variant shadow-sm text-sm font-medium rounded-md text-on-surface bg-surface-container hover:bg-surface-container-low focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-on-primary bg-primary hover:bg-primary focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary"
                  >
                    Create AppRole
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      <% end %>
      
    <!-- New Role Credentials Modal -->
      <%= if @new_role_result do %>
        <div
          class="fixed z-10 inset-0 overflow-y-auto"
          aria-labelledby="modal-title"
          role="dialog"
          aria-modal="true"
        >
          <div class="flex items-end justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
            <div
              class="fixed inset-0 bg-surface-container-low0 bg-opacity-75 transition-opacity"
              aria-hidden="true"
            >
            </div>
            <span class="hidden sm:inline-block sm:align-middle sm:h-screen" aria-hidden="true">
              &#8203;
            </span>
            <div class="inline-block align-bottom bg-surface-container rounded-lg px-4 pt-5 pb-4 text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-lg sm:w-full sm:p-6">
              <div>
                <div class="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-success/10">
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
                      d="M5 13l4 4L19 7"
                    />
                  </svg>
                </div>
                <div class="mt-3 text-center sm:mt-5">
                  <h3 class="text-lg leading-6 font-medium text-on-surface" id="modal-title">
                    AppRole Created Successfully
                  </h3>
                  <div class="mt-4">
                    <p class="text-sm text-error font-semibold mb-4">
                      ⚠️ Save these credentials now! They will only be shown once.
                    </p>

                    <div class="bg-surface-container-low p-4 rounded-md text-left space-y-3">
                      <div>
                        <label class="block text-xs font-medium text-on-surface-variant uppercase">
                          Role Name
                        </label>
                        <div class="mt-1 font-mono text-sm bg-surface-container p-2 rounded border border-outline-variant">
                          {@new_role_result.role_name}
                        </div>
                      </div>

                      <div>
                        <label class="block text-xs font-medium text-on-surface-variant uppercase">
                          Role ID
                        </label>
                        <div class="mt-1 font-mono text-sm bg-surface-container p-2 rounded border border-outline-variant break-all">
                          {@new_role_result.role_id}
                        </div>
                      </div>

                      <div>
                        <label class="block text-xs font-medium text-on-surface-variant uppercase">
                          Secret ID
                        </label>
                        <div class="mt-1 font-mono text-sm bg-surface-container p-2 rounded border border-outline-variant break-all">
                          {@new_role_result.secret_id}
                        </div>
                      </div>
                    </div>

                    <p class="mt-4 text-xs text-on-surface-variant">
                      Use these credentials to configure your agent. The RoleID is reusable, but the SecretID should be single-use.
                    </p>
                  </div>
                </div>
              </div>
              <div class="mt-5 sm:mt-6">
                <button
                  type="button"
                  phx-click="close_credentials"
                  class="inline-flex justify-center w-full rounded-md border border-transparent shadow-sm px-4 py-2 bg-primary text-base font-medium text-on-primary hover:bg-primary focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary sm:text-sm"
                >
                  I've Saved These Credentials
                </button>
              </div>
            </div>
          </div>
        </div>
      <% end %>
      
    <!-- AppRoles List -->
      <div class="bg-surface-container shadow overflow-hidden sm:rounded-md">
        <ul role="list" class="divide-y divide-outline-variant">
          <%= if Enum.empty?(@roles) do %>
            <li class="px-6 py-12 text-center">
              <p class="text-on-surface-variant">
                No AppRoles created yet. Create your first AppRole to get started.
              </p>
            </li>
          <% else %>
            <%= for role <- @roles do %>
              <li class="px-6 py-4 hover:bg-surface-container-low">
                <div class="flex items-center justify-between">
                  <div class="flex-1">
                    <div class="flex items-center">
                      <div class="flex-shrink-0">
                        <div class="h-10 w-10 rounded-full bg-primary/10 flex items-center justify-center">
                          <svg
                            class="h-6 w-6 text-primary"
                            xmlns="http://www.w3.org/2000/svg"
                            fill="none"
                            viewBox="0 0 24 24"
                            stroke="currentColor"
                          >
                            <path
                              stroke-linecap="round"
                              stroke-linejoin="round"
                              stroke-width="2"
                              d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"
                            />
                          </svg>
                        </div>
                      </div>
                      <div class="ml-4">
                        <div class="text-sm font-medium text-on-surface">
                          {role.role_name}
                        </div>
                        <div class="text-sm text-on-surface-variant">
                          Role ID:
                          <span class="font-mono text-xs">{String.slice(role.role_id, 0..7)}...</span>
                        </div>
                        <div class="mt-1">
                          <%= if role.metadata["policies"] && length(role.metadata["policies"]) > 0 do %>
                            <div class="flex flex-wrap gap-1">
                              <%= for policy <- role.metadata["policies"] do %>
                                <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-primary/10 text-primary">
                                  {policy}
                                </span>
                              <% end %>
                            </div>
                          <% else %>
                            <span class="text-xs text-on-surface-variant">No policies</span>
                          <% end %>
                        </div>
                      </div>
                    </div>
                  </div>
                  <div class="ml-4 flex-shrink-0 flex space-x-2">
                    <button
                      phx-click="view_role"
                      phx-value-role_id={role.role_id}
                      class="inline-flex items-center px-3 py-1.5 border border-outline-variant shadow-sm text-xs font-medium rounded text-on-surface bg-surface-container hover:bg-surface-container-low focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary"
                    >
                      View Details
                    </button>
                    <button
                      phx-click="generate_secret_id"
                      phx-value-role_id={role.role_id}
                      class="inline-flex items-center px-3 py-1.5 border border-outline-variant shadow-sm text-xs font-medium rounded text-on-surface bg-surface-container hover:bg-surface-container-low focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary"
                    >
                      Generate SecretID
                    </button>
                    <button
                      phx-click="delete_role"
                      phx-value-role_id={role.role_id}
                      data-confirm="Are you sure you want to delete this AppRole? This action cannot be undone."
                      class="inline-flex items-center px-3 py-1.5 border border-red-300 shadow-sm text-xs font-medium rounded text-error bg-surface-container hover:bg-error/5 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-error"
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

  ## Private Functions

  defp list_approles do
    # Query all AppRole roles - the roles table is specifically for AppRoles
    query =
      from(r in Role,
        order_by: [desc: r.inserted_at]
      )

    Repo.all(query)
  end
end
