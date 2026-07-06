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
  alias SecretHub.Shared.Schemas.{Policy, Role}

  @impl true
  def mount(_params, _session, socket) do
    socket =
      socket
      |> assign(:roles, [])
      |> assign(:available_policies, [])
      |> assign(:creating_role, false)
      |> assign(:new_role_name, "")
      |> assign(:new_role_policies, [])
      |> assign(:new_role_result, nil)
      |> assign(:new_secret_id, nil)
      |> assign(:selected_role, nil)
      |> assign(:delete_role_target, nil)
      |> assign(:editing_role_policies, nil)
      |> assign(:page_title, "AppRole Management")

    {:ok, socket}
  end

  @impl true
  def handle_params(_params, _url, socket) do
    socket =
      socket
      |> assign(:roles, list_approles())
      |> assign(:available_policies, list_available_policies())

    {:noreply, socket}
  end

  @impl true
  def handle_event("open_create_form", _params, socket) do
    {:noreply, assign(socket, :creating_role, true)}
  end

  @impl true
  def handle_event("close_create_form", _params, socket) do
    {:noreply, close_create_form(socket)}
  end

  @impl true
  def handle_event("toggle_create_form", _params, socket) do
    {:noreply, assign(socket, :creating_role, !socket.assigns.creating_role)}
  end

  @impl true
  def handle_event("create_role", %{"role_name" => role_name} = params, socket) do
    policies = normalize_selected_policies(Map.get(params, "policies", []))

    case AppRole.create_role(role_name, policies: policies) do
      {:ok, result} ->
        # Show the RoleID and SecretID to the user (one-time display)
        socket =
          socket
          |> assign(:new_role_result, result)
          |> assign(:creating_role, false)
          |> assign(:new_role_name, "")
          |> assign(:new_role_policies, [])
          |> assign(:new_secret_id, nil)
          |> assign(:delete_role_target, nil)
          |> assign(:editing_role_policies, nil)
          |> assign(:roles, list_approles())
          |> put_flash(
            :info,
            "AppRole created successfully! Save the RoleID and SecretID - they will only be shown once."
          )

        {:noreply, socket}

      {:error, reason} ->
        socket =
          socket
          |> assign(:creating_role, true)
          |> assign(:new_role_name, role_name)
          |> assign(:new_role_policies, policies)
          |> put_flash(:error, "Failed to create AppRole: #{inspect(reason)}")

        {:noreply, socket}
    end
  end

  @impl true
  def handle_event("close_credentials", _params, socket) do
    {:noreply, assign(socket, :new_role_result, nil)}
  end

  @impl true
  def handle_event("close_generated_secret_id", _params, socket) do
    {:noreply, assign(socket, :new_secret_id, nil)}
  end

  @impl true
  def handle_event("generate_secret_id", %{"role_id" => role_id}, socket) do
    case AppRole.generate_secret_id(role_id) do
      {:ok, secret_id} ->
        socket =
          socket
          |> put_flash(:info, "New SecretID generated successfully!")
          |> assign(:new_secret_id, %{
            role_name: role_name_for(socket.assigns.roles, role_id),
            role_id: role_id,
            secret_id: secret_id
          })

        {:noreply, socket}

      {:error, reason} ->
        socket = put_flash(socket, :error, "Failed to generate SecretID: #{inspect(reason)}")
        {:noreply, socket}
    end
  end

  @impl true
  def handle_event("show_delete_role_modal", %{"role_id" => role_id}, socket) do
    case delete_role_target(socket.assigns.roles, role_id) do
      nil ->
        {:noreply, put_flash(socket, :error, "Failed to load AppRole for deletion")}

      target ->
        {:noreply, assign(socket, :delete_role_target, target)}
    end
  end

  @impl true
  def handle_event("cancel_delete_role", _params, socket) do
    {:noreply, assign(socket, :delete_role_target, nil)}
  end

  @impl true
  def handle_event("confirm_delete_role", %{"role_id" => role_id}, socket) do
    case AppRole.delete_role(role_id) do
      :ok ->
        socket =
          socket
          |> assign(:roles, list_approles())
          |> assign(:delete_role_target, nil)
          |> clear_selected_role(role_id)
          |> put_flash(:info, "AppRole deleted successfully")

        {:noreply, socket}

      {:error, reason} ->
        socket =
          socket
          |> assign(:delete_role_target, nil)
          |> put_flash(:error, "Failed to delete AppRole: #{inspect(reason)}")

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
  def handle_event("edit_role_policies", %{"role_id" => role_id}, socket) do
    case edit_role_policies_target(socket.assigns.roles, role_id) do
      nil ->
        {:noreply, put_flash(socket, :error, "Failed to load AppRole policies")}

      target ->
        {:noreply, assign(socket, :editing_role_policies, target)}
    end
  end

  @impl true
  def handle_event("cancel_edit_role_policies", _params, socket) do
    {:noreply, assign(socket, :editing_role_policies, nil)}
  end

  @impl true
  def handle_event("update_role_policies", %{"role_id" => role_id} = params, socket) do
    policies = normalize_selected_policies(Map.get(params, "policies", []))

    case AppRole.update_role_policies(role_id, policies) do
      {:ok, updated_role} ->
        socket =
          socket
          |> assign(:roles, list_approles())
          |> assign(:editing_role_policies, nil)
          |> update_selected_role_policies(updated_role)
          |> put_flash(:info, "AppRole policies updated successfully")

        {:noreply, socket}

      {:error, reason} ->
        socket =
          socket
          |> assign(:editing_role_policies, nil)
          |> put_flash(:error, "Failed to update AppRole policies: #{inspect(reason)}")

        {:noreply, socket}
    end
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
          phx-click="open_create_form"
          class="inline-flex cursor-pointer items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-primary-content bg-primary hover:bg-primary focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary"
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

      <!-- Create Role Modal -->
      <%= if @creating_role do %>
        <div
          class="fixed inset-0 z-50 overflow-y-auto"
          aria-labelledby="create-approle-title"
          role="dialog"
          aria-modal="true"
        >
          <div
            class="fixed inset-0 bg-surface-container-low/80 transition-opacity"
            aria-hidden="true"
            phx-click="close_create_form"
          >
          </div>
          <div class="relative z-10 flex min-h-screen items-center justify-center p-4">
            <div
              data-create-role-modal-panel
              class="w-full max-w-lg bg-surface-container rounded-lg px-4 pt-5 pb-4 text-left overflow-hidden shadow-xl transform transition-all sm:p-6"
            >
              <div class="flex items-start justify-between gap-4">
                <div>
                  <h3 class="text-lg leading-6 font-medium text-on-surface" id="create-approle-title">
                    Create New AppRole
                  </h3>
                  <p class="mt-1 text-sm text-on-surface-variant">
                    Assign policies before showing the one-time RoleID and SecretID.
                  </p>
                </div>
                <button
                  type="button"
                  phx-click="close_create_form"
                  class="inline-flex h-9 w-9 cursor-pointer items-center justify-center rounded-md text-on-surface-variant hover:bg-surface-container-high hover:text-on-surface focus:outline-none focus:ring-2 focus:ring-primary"
                  aria-label="Close create AppRole modal"
                >
                  <.dm_mdi name="close" class="size-5" />
                </button>
              </div>

              <form phx-submit="create_role" class="mt-5 space-y-4">
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
                    class="input mt-1 block w-full border border-outline-variant rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-primary focus:border-primary sm:text-sm"
                    placeholder="e.g., production-app, staging-agent"
                  />
                </div>

                <div>
                  <label for="policies" class="block text-sm font-medium text-on-surface">
                    Policies
                  </label>
                  <select
                    name="policies[]"
                    id="policies"
                    multiple
                    size={policy_select_size(@available_policies)}
                    disabled={Enum.empty?(@available_policies)}
                    class="mt-1 block w-full overflow-y-auto rounded-md border border-outline-variant bg-surface-container px-3 py-2 text-sm text-on-surface shadow-sm focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    <%= for policy <- @available_policies do %>
                      <option
                        value={policy.name}
                        selected={policy.name in @new_role_policies}
                        title={policy.description}
                      >
                        {policy.name}
                      </option>
                    <% end %>
                  </select>
                  <p class="mt-1 text-sm text-on-surface-variant">
                    <%= if Enum.empty?(@available_policies) do %>
                      No policies are available yet.
                    <% else %>
                      Select one or more policies for this AppRole.
                    <% end %>
                  </p>
                </div>

                <div class="flex justify-end space-x-3 pt-2">
                  <button
                    type="button"
                    phx-click="close_create_form"
                    class="inline-flex cursor-pointer items-center px-4 py-2 border border-outline-variant shadow-sm text-sm font-medium rounded-md text-on-surface bg-surface-container hover:bg-surface-container-low focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    class="inline-flex cursor-pointer items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-primary-content bg-primary hover:bg-primary focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary"
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
          class="fixed inset-0 z-50 overflow-y-auto"
          aria-labelledby="modal-title"
          role="dialog"
          aria-modal="true"
        >
          <div
            class="fixed inset-0 bg-surface-container-low/80 transition-opacity"
            aria-hidden="true"
          >
          </div>
          <div class="relative z-10 flex min-h-screen items-center justify-center p-4">
            <div
              data-credential-modal-panel
              class="w-full max-w-lg bg-surface-container rounded-lg px-4 pt-5 pb-4 text-left overflow-hidden shadow-xl transform transition-all sm:p-6"
            >
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
                    <div class="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                      <p class="text-sm text-error font-semibold">
                        ⚠️ Save these credentials now! They will only be shown once.
                      </p>
                      <button
                        type="button"
                        id="copy-new-approle-credentials"
                        phx-hook="CopyToClipboard"
                        data-copy-value={approle_credentials_text(@new_role_result)}
                        class="btn btn-outline btn-sm shrink-0 cursor-pointer"
                        title="Copy all credentials"
                        aria-label="Copy all credentials"
                      >
                        <.dm_mdi name="content-copy" class="size-4" /> Copy all
                      </button>
                    </div>

                    <dl class="bg-surface-container-low p-4 rounded-md text-left space-y-3">
                      <%= for {label, field, value} <- approle_credential_fields(@new_role_result) do %>
                        <div>
                          <dt class="block text-xs font-medium text-on-surface-variant uppercase">
                            {label}
                          </dt>
                          <div class="mt-1 flex min-w-0 rounded border border-outline-variant bg-surface-container focus-within:ring-2 focus-within:ring-primary">
                            <dd
                              data-copyable-credential={field}
                              tabindex="0"
                              class={[
                                "block min-w-0 flex-1 cursor-text overflow-x-auto whitespace-nowrap bg-transparent px-2 py-2 font-mono text-sm text-on-surface outline-none focus:ring-2 focus:ring-primary",
                                field == "role-name" && "select-text",
                                field != "role-name" && "select-all"
                              ]}
                            >
                              {value}
                            </dd>
                            <button
                              type="button"
                              id={"copy-new-approle-#{field}"}
                              phx-hook="CopyToClipboard"
                              data-copy-value={value}
                              class="inline-flex h-10 w-10 shrink-0 cursor-pointer items-center justify-center border-l border-outline-variant text-on-surface-variant hover:bg-surface-container-high hover:text-on-surface focus:outline-none focus:ring-2 focus:ring-primary"
                              title={"Copy #{label}"}
                              aria-label={"Copy #{label}"}
                            >
                              <.dm_mdi name="content-copy" class="size-4" />
                            </button>
                          </div>
                        </div>
                      <% end %>
                    </dl>

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
                  class="inline-flex w-full cursor-pointer justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-primary text-base font-medium text-primary-content hover:bg-primary focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary sm:text-sm"
                >
                  I've Saved These Credentials
                </button>
              </div>
            </div>
          </div>
        </div>
      <% end %>

      <!-- Generated SecretID Modal -->
      <%= if @new_secret_id do %>
        <div
          class="fixed inset-0 z-50 overflow-y-auto"
          aria-labelledby="generated-secret-id-title"
          role="dialog"
          aria-modal="true"
        >
          <div
            class="fixed inset-0 bg-surface-container-low/80 transition-opacity"
            aria-hidden="true"
          >
          </div>
          <div class="relative z-10 flex min-h-screen items-center justify-center p-4">
            <div
              data-generated-secret-id-modal-panel
              class="w-full max-w-lg bg-surface-container rounded-lg px-4 pt-5 pb-4 text-left overflow-hidden shadow-xl transform transition-all sm:p-6"
            >
              <div>
                <div class="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-success/10">
                  <.dm_mdi name="key-plus" class="size-6 text-success" />
                </div>
                <div class="mt-3 text-center sm:mt-5">
                  <h3
                    class="text-lg leading-6 font-medium text-on-surface"
                    id="generated-secret-id-title"
                  >
                    SecretID Generated
                  </h3>
                  <div class="mt-4">
                    <div class="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                      <p class="text-sm text-error font-semibold">
                        Save this SecretID now. It will only be shown once.
                      </p>
                      <button
                        type="button"
                        id="copy-generated-approle-secret-id-details"
                        phx-hook="CopyToClipboard"
                        data-copy-value={generated_secret_id_text(@new_secret_id)}
                        class="btn btn-outline btn-sm shrink-0 cursor-pointer"
                        title="Copy generated SecretID details"
                        aria-label="Copy generated SecretID details"
                      >
                        <.dm_mdi name="content-copy" class="size-4" /> Copy all
                      </button>
                    </div>

                    <dl class="bg-surface-container-low p-4 rounded-md text-left space-y-3">
                      <%= for {label, field, value} <- generated_secret_id_fields(@new_secret_id) do %>
                        <div>
                          <dt class="block text-xs font-medium text-on-surface-variant uppercase">
                            {label}
                          </dt>
                          <div class="mt-1 flex min-w-0 rounded border border-outline-variant bg-surface-container focus-within:ring-2 focus-within:ring-primary">
                            <dd
                              data-copyable-credential={field}
                              tabindex="0"
                              class={[
                                "block min-w-0 flex-1 cursor-text overflow-x-auto whitespace-nowrap bg-transparent px-2 py-2 font-mono text-sm text-on-surface outline-none focus:ring-2 focus:ring-primary",
                                field == "generated-role-name" && "select-text",
                                field != "generated-role-name" && "select-all"
                              ]}
                            >
                              {value}
                            </dd>
                            <button
                              type="button"
                              id={"copy-generated-approle-#{field}"}
                              phx-hook="CopyToClipboard"
                              data-copy-value={value}
                              class="inline-flex h-10 w-10 shrink-0 cursor-pointer items-center justify-center border-l border-outline-variant text-on-surface-variant hover:bg-surface-container-high hover:text-on-surface focus:outline-none focus:ring-2 focus:ring-primary"
                              title={"Copy #{label}"}
                              aria-label={"Copy #{label}"}
                            >
                              <.dm_mdi name="content-copy" class="size-4" />
                            </button>
                          </div>
                        </div>
                      <% end %>
                    </dl>
                  </div>
                </div>
              </div>
              <div class="mt-5 sm:mt-6">
                <button
                  type="button"
                  phx-click="close_generated_secret_id"
                  class="inline-flex w-full cursor-pointer justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-primary text-base font-medium text-primary-content hover:bg-primary focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary sm:text-sm"
                >
                  I've Saved This SecretID
                </button>
              </div>
            </div>
          </div>
        </div>
      <% end %>

      <!-- Role Details Modal -->
      <%= if @selected_role do %>
        <div
          class="fixed inset-0 z-50 overflow-y-auto"
          aria-labelledby="role-details-title"
          role="dialog"
          aria-modal="true"
        >
          <div
            class="fixed inset-0 bg-surface-container-low/80 transition-opacity"
            aria-hidden="true"
            phx-click="close_role_details"
          >
          </div>
          <div class="relative z-10 flex min-h-screen items-center justify-center p-4">
            <div
              data-role-details-modal-panel
              class="w-full max-w-2xl bg-surface-container rounded-lg px-4 pt-5 pb-4 text-left overflow-hidden shadow-xl transform transition-all select-text sm:p-6"
            >
              <div class="flex items-start justify-between gap-4">
                <div>
                  <h3 class="text-lg leading-6 font-medium text-on-surface" id="role-details-title">
                    AppRole Details
                  </h3>
                  <p class="mt-1 text-sm text-on-surface-variant">
                    {@selected_role.role_name}
                  </p>
                </div>
                <button
                  type="button"
                  phx-click="close_role_details"
                  class="inline-flex h-9 w-9 cursor-pointer items-center justify-center rounded-md text-on-surface-variant hover:bg-surface-container-high hover:text-on-surface focus:outline-none focus:ring-2 focus:ring-primary"
                  aria-label="Close role details"
                >
                  <.dm_mdi name="close" class="size-5" />
                </button>
              </div>

              <div class="mt-6 space-y-5">
                <div>
                  <span class="block text-xs font-medium text-on-surface-variant uppercase">
                    Role ID
                  </span>
                  <div class="mt-1 flex min-w-0 rounded border border-outline-variant bg-surface-container-low focus-within:ring-2 focus-within:ring-primary">
                    <span
                      data-copyable-credential="selected-role-id"
                      tabindex="0"
                      class="block min-w-0 flex-1 cursor-text overflow-x-auto whitespace-nowrap bg-transparent px-2 py-2 font-mono text-sm text-on-surface outline-none select-all focus:ring-2 focus:ring-primary"
                    >
                      {@selected_role.role_id}
                    </span>
                    <button
                      type="button"
                      id="copy-selected-approle-role-id"
                      phx-hook="CopyToClipboard"
                      data-copy-value={@selected_role.role_id}
                      class="inline-flex h-10 w-10 shrink-0 cursor-pointer items-center justify-center border-l border-outline-variant text-on-surface-variant hover:bg-surface-container-high hover:text-on-surface focus:outline-none focus:ring-2 focus:ring-primary"
                      title="Copy Role ID"
                      aria-label="Copy Role ID"
                    >
                      <.dm_mdi name="content-copy" class="size-4" />
                    </button>
                  </div>
                </div>

                <div class="grid gap-4 sm:grid-cols-2">
                  <div class="rounded-md border border-outline-variant bg-surface-container-low p-4">
                    <p class="text-xs font-medium uppercase text-on-surface-variant">
                      Secret ID TTL
                    </p>
                    <p class="mt-1 text-sm font-medium text-on-surface">
                      {format_seconds(@selected_role.secret_id_ttl)}
                    </p>
                  </div>
                  <div class="rounded-md border border-outline-variant bg-surface-container-low p-4">
                    <p class="text-xs font-medium uppercase text-on-surface-variant">
                      Secret ID Uses
                    </p>
                    <p class="mt-1 text-sm font-medium text-on-surface">
                      {@selected_role.secret_id_uses} / {format_use_limit(
                        @selected_role.secret_id_num_uses
                      )}
                    </p>
                  </div>
                  <div class="rounded-md border border-outline-variant bg-surface-container-low p-4">
                    <p class="text-xs font-medium uppercase text-on-surface-variant">
                      Created
                    </p>
                    <p class="mt-1 text-sm font-medium text-on-surface">
                      {format_datetime(@selected_role.created_at)}
                    </p>
                  </div>
                  <div class="rounded-md border border-outline-variant bg-surface-container-low p-4">
                    <p class="text-xs font-medium uppercase text-on-surface-variant">
                      Secret ID
                    </p>
                    <p class="mt-1 text-sm text-on-surface-variant">
                      Hidden after creation. Generate a new SecretID to view it once.
                    </p>
                  </div>
                </div>

                <div>
                  <p class="text-xs font-medium uppercase text-on-surface-variant">Policies</p>
                  <div class="mt-2 flex flex-wrap gap-2">
                    <%= if role_detail_list(@selected_role.policies) == [] do %>
                      <span class="text-sm text-on-surface-variant">No policies</span>
                    <% else %>
                      <%= for policy <- role_detail_list(@selected_role.policies) do %>
                        <span class="inline-flex items-center rounded bg-primary/10 px-2 py-1 text-xs font-medium text-primary">
                          {policy}
                        </span>
                      <% end %>
                    <% end %>
                  </div>
                </div>

                <div>
                  <p class="text-xs font-medium uppercase text-on-surface-variant">
                    Bound CIDR List
                  </p>
                  <div class="mt-2 flex flex-wrap gap-2">
                    <%= if role_detail_list(@selected_role.bound_cidr_list) == [] do %>
                      <span class="text-sm text-on-surface-variant">No CIDR restrictions</span>
                    <% else %>
                      <%= for cidr <- role_detail_list(@selected_role.bound_cidr_list) do %>
                        <span class="inline-flex items-center rounded bg-surface-container-high px-2 py-1 font-mono text-xs text-on-surface">
                          {cidr}
                        </span>
                      <% end %>
                    <% end %>
                  </div>
                </div>
              </div>

              <div class="mt-6 flex justify-end">
                <button
                  type="button"
                  phx-click="close_role_details"
                  class="inline-flex cursor-pointer items-center rounded-md border border-outline-variant bg-surface-container px-4 py-2 text-sm font-medium text-on-surface shadow-sm hover:bg-surface-container-low focus:outline-none focus:ring-2 focus:ring-primary"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      <% end %>

      <!-- Edit Policies Modal -->
      <%= if @editing_role_policies do %>
        <div
          class="fixed inset-0 z-50 overflow-y-auto"
          aria-labelledby="edit-approle-policies-title"
          role="dialog"
          aria-modal="true"
        >
          <div
            class="fixed inset-0 bg-surface-container-low/80 transition-opacity"
            aria-hidden="true"
            phx-click="cancel_edit_role_policies"
          >
          </div>
          <div class="relative z-10 flex min-h-screen items-center justify-center p-4">
            <div
              data-edit-policies-modal-panel
              class="w-full max-w-lg bg-surface-container rounded-lg px-4 pt-5 pb-4 text-left overflow-hidden shadow-xl transform transition-all sm:p-6"
            >
              <div class="flex items-start justify-between gap-4">
                <div>
                  <h3
                    class="text-lg leading-6 font-medium text-on-surface"
                    id="edit-approle-policies-title"
                  >
                    Edit AppRole Policies
                  </h3>
                  <p class="mt-1 text-sm text-on-surface-variant">
                    {@editing_role_policies.role_name}
                  </p>
                </div>
                <button
                  type="button"
                  phx-click="cancel_edit_role_policies"
                  class="inline-flex h-9 w-9 cursor-pointer items-center justify-center rounded-md text-on-surface-variant hover:bg-surface-container-high hover:text-on-surface focus:outline-none focus:ring-2 focus:ring-primary"
                  aria-label="Close edit policies modal"
                >
                  <.dm_mdi name="close" class="size-5" />
                </button>
              </div>

              <form phx-submit="update_role_policies" class="mt-5 space-y-4">
                <input type="hidden" name="role_id" value={@editing_role_policies.role_id} />

                <div>
                  <label for="edit_policies" class="block text-sm font-medium text-on-surface">
                    Policies
                  </label>
                  <select
                    name="policies[]"
                    id="edit_policies"
                    multiple
                    size={policy_select_size(@available_policies)}
                    disabled={Enum.empty?(@available_policies)}
                    class="mt-1 block w-full overflow-y-auto rounded-md border border-outline-variant bg-surface-container px-3 py-2 text-sm text-on-surface shadow-sm focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    <%= for policy <- @available_policies do %>
                      <option
                        value={policy.name}
                        selected={policy.name in @editing_role_policies.policies}
                        title={policy.description}
                      >
                        {policy.name}
                      </option>
                    <% end %>
                  </select>
                  <p class="mt-1 text-sm text-on-surface-variant">
                    <%= if Enum.empty?(@available_policies) do %>
                      No policies are available yet.
                    <% else %>
                      Select one or more policies for this AppRole.
                    <% end %>
                  </p>
                </div>

                <div class="flex justify-end gap-3 pt-2">
                  <button
                    type="button"
                    phx-click="cancel_edit_role_policies"
                    class="inline-flex cursor-pointer items-center px-4 py-2 border border-outline-variant shadow-sm text-sm font-medium rounded-md text-on-surface bg-surface-container hover:bg-surface-container-low focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    class="inline-flex cursor-pointer items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-primary-content bg-primary hover:bg-primary focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary"
                  >
                    Save Policies
                  </button>
                </div>
              </form>
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
                      class="inline-flex cursor-pointer items-center px-3 py-1.5 border border-outline-variant shadow-sm text-xs font-medium rounded text-on-surface bg-surface-container hover:bg-surface-container-low focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary"
                    >
                      View Details
                    </button>
                    <button
                      phx-click="edit_role_policies"
                      phx-value-role_id={role.role_id}
                      class="inline-flex cursor-pointer items-center px-3 py-1.5 border border-outline-variant shadow-sm text-xs font-medium rounded text-on-surface bg-surface-container hover:bg-surface-container-low focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary"
                    >
                      Edit Policies
                    </button>
                    <button
                      phx-click="generate_secret_id"
                      phx-value-role_id={role.role_id}
                      class="inline-flex cursor-pointer items-center px-3 py-1.5 border border-outline-variant shadow-sm text-xs font-medium rounded text-on-surface bg-surface-container hover:bg-surface-container-low focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary"
                    >
                      Generate SecretID
                    </button>
                    <button
                      phx-click="show_delete_role_modal"
                      phx-value-role_id={role.role_id}
                      class="inline-flex cursor-pointer items-center px-3 py-1.5 border border-error shadow-sm text-xs font-medium rounded text-error bg-surface-container hover:bg-error/5 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-error"
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

      <!-- Delete AppRole Modal -->
      <%= if @delete_role_target do %>
        <div
          class="fixed inset-0 z-50 overflow-y-auto"
          aria-labelledby="delete-approle-title"
          role="dialog"
          aria-modal="true"
        >
          <div
            class="fixed inset-0 bg-surface-container-low/80 transition-opacity"
            aria-hidden="true"
            phx-click="cancel_delete_role"
          >
          </div>
          <div class="relative z-10 flex min-h-screen items-center justify-center p-4">
            <div
              data-delete-role-modal-panel
              class="w-full max-w-lg bg-surface-container rounded-lg px-4 pt-5 pb-4 text-left overflow-hidden shadow-xl transform transition-all sm:p-6"
            >
              <div class="flex items-start gap-4">
                <div class="flex h-12 w-12 shrink-0 items-center justify-center rounded-full bg-error/10">
                  <.dm_mdi name="alert-circle" class="size-6 text-error" />
                </div>
                <div>
                  <h3 class="text-lg leading-6 font-medium text-on-surface" id="delete-approle-title">
                    Delete AppRole
                  </h3>
                  <p class="mt-2 text-sm text-on-surface-variant">
                    Delete <span class="font-medium text-on-surface">{@delete_role_target.role_name}</span>?
                    This action cannot be undone.
                  </p>
                  <p class="mt-2 font-mono text-xs text-on-surface-variant select-all">
                    {@delete_role_target.role_id}
                  </p>
                </div>
              </div>

              <div class="mt-6 flex justify-end gap-3">
                <button
                  type="button"
                  phx-click="cancel_delete_role"
                  class="inline-flex cursor-pointer items-center px-4 py-2 border border-outline-variant shadow-sm text-sm font-medium rounded-md text-on-surface bg-surface-container hover:bg-surface-container-low focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  phx-click="confirm_delete_role"
                  phx-value-role_id={@delete_role_target.role_id}
                  class="inline-flex cursor-pointer items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-error-content bg-error hover:bg-error focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-error"
                >
                  Delete AppRole
                </button>
              </div>
            </div>
          </div>
        </div>
      <% end %>
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

  defp list_available_policies do
    Policy
    |> order_by([p], asc: p.name)
    |> Repo.all()
  end

  defp close_create_form(socket) do
    socket
    |> assign(:creating_role, false)
    |> assign(:new_role_name, "")
    |> assign(:new_role_policies, [])
  end

  defp role_name_for(roles, role_id) do
    roles
    |> Enum.find(&(&1.role_id == role_id))
    |> case do
      nil -> nil
      role -> role.role_name
    end
  end

  defp delete_role_target(roles, role_id) do
    roles
    |> Enum.find(&(&1.role_id == role_id))
    |> case do
      nil -> nil
      role -> %{role_id: role.role_id, role_name: role.role_name}
    end
  end

  defp edit_role_policies_target(roles, role_id) do
    roles
    |> Enum.find(&(&1.role_id == role_id))
    |> case do
      nil ->
        nil

      role ->
        %{
          role_id: role.role_id,
          role_name: role.role_name,
          policies: role_policies(role)
        }
    end
  end

  defp clear_selected_role(socket, role_id) do
    case socket.assigns.selected_role do
      %{role_id: ^role_id} -> assign(socket, :selected_role, nil)
      _role -> socket
    end
  end

  defp update_selected_role_policies(socket, %{role_id: role_id} = updated_role) do
    case socket.assigns.selected_role do
      %{role_id: ^role_id} -> assign(socket, :selected_role, updated_role)
      _role -> socket
    end
  end

  defp role_policies(%{metadata: metadata, policies: policies}) do
    metadata_policies = Map.get(metadata || %{}, "policies")

    cond do
      is_list(metadata_policies) -> metadata_policies
      is_list(policies) -> policies
      true -> []
    end
  end

  defp normalize_selected_policies(policies) when is_list(policies) do
    policies
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
  end

  defp normalize_selected_policies(policy) when is_binary(policy) do
    policy
    |> String.split(",")
    |> normalize_selected_policies()
  end

  defp normalize_selected_policies(_policies), do: []

  defp policy_select_size([]), do: 3
  defp policy_select_size(policies), do: min(length(policies), 6)

  defp role_detail_list(values) when is_list(values), do: values
  defp role_detail_list(_values), do: []

  defp format_use_limit(nil), do: "unlimited"
  defp format_use_limit(0), do: "unlimited"
  defp format_use_limit(uses), do: uses

  defp format_seconds(nil), do: "Not configured"

  defp format_seconds(seconds) when is_integer(seconds) do
    cond do
      seconds < 60 -> "#{seconds}s"
      rem(seconds, 3600) == 0 -> "#{div(seconds, 3600)}h"
      rem(seconds, 60) == 0 -> "#{div(seconds, 60)}m"
      true -> "#{seconds}s"
    end
  end

  defp format_seconds(seconds), do: to_string(seconds)

  defp format_datetime(nil), do: "Not available"

  defp format_datetime(%DateTime{} = datetime) do
    Calendar.strftime(datetime, "%Y-%m-%d %H:%M:%S UTC")
  end

  defp format_datetime(datetime), do: to_string(datetime)

  defp approle_credential_fields(result) do
    [
      {"Role Name", "role-name", result.role_name},
      {"Role ID", "role-id", result.role_id},
      {"Secret ID", "secret-id", result.secret_id}
    ]
  end

  defp approle_credentials_text(result) do
    """
    Role Name: #{result.role_name}
    Role ID: #{result.role_id}
    Secret ID: #{result.secret_id}
    """
    |> String.trim()
  end

  defp generated_secret_id_fields(result) do
    [
      {"Role Name", "generated-role-name", result.role_name},
      {"Role ID", "generated-role-id", result.role_id},
      {"Secret ID", "generated-secret-id", result.secret_id}
    ]
    |> Enum.reject(fn {_label, _field, value} -> is_nil(value) or value == "" end)
  end

  defp generated_secret_id_text(result) do
    result
    |> generated_secret_id_fields()
    |> Enum.map_join("\n", fn {label, _field, value} -> "#{label}: #{value}" end)
  end
end
