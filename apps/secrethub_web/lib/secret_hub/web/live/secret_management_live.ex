defmodule SecretHub.Web.SecretManagementLive do
  @moduledoc """
  LiveView for secret management with CRUD operations and policy validation.
  """

  use SecretHub.Web, :live_view
  require Logger
  alias SecretHub.Core.{Policies, Secrets}
  alias SecretHub.Core.Vault.SealState
  alias SecretHub.Shared.Schemas.Secret

  @impl true
  def mount(_params, _session, socket) do
    secrets = fetch_secrets()
    rotators = fetch_rotators()
    policies = fetch_policies()

    socket =
      socket
      |> assign(:secrets, secrets)
      |> assign(:rotators, rotators)
      |> assign(:policies, policies)
      |> assign(:selected_secret, nil)
      |> assign(:show_form, false)
      |> assign(:form_mode, :create)
      |> assign(:filter_rotator, "all")
      |> assign(:search_query, "")
      |> assign(:loading, false)
      |> assign(:form_changeset, changeset_for_secret(%Secret{}, rotators))

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
    status = vault_status()

    if vault_sealed?(status) do
      {:noreply, vault_unavailable_socket(socket, status, :create)}
    else
      socket =
        socket
        |> assign(:vault_status, status)
        |> assign(:show_form, true)
        |> assign(:form_mode, :create)
        |> assign(:form_changeset, changeset_for_secret(%Secret{}, socket.assigns.rotators))

      {:noreply, socket}
    end
  end

  @impl true
  def handle_event("edit_secret", %{"id" => secret_id}, socket) do
    status = vault_status()

    if vault_sealed?(status) do
      {:noreply, vault_unavailable_socket(socket, status, :update)}
    else
      secret = Enum.find(socket.assigns.secrets, &(&1.id == secret_id))
      changeset = changeset_for_secret(secret, socket.assigns.rotators)

      socket =
        socket
        |> assign(:vault_status, status)
        |> assign(:show_form, true)
        |> assign(:form_mode, :edit)
        |> assign(:selected_secret, secret)
        |> assign(:form_changeset, changeset)

      {:noreply, socket}
    end
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
  def handle_event("filter_secrets", %{"rotator" => rotator_id}, socket) do
    socket = assign(socket, :filter_rotator, rotator_id)
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
      |> Secret.changeset(with_default_rotator(secret_params, socket.assigns.rotators))
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
    create_secret(socket, secret_params)
  end

  @impl true
  def handle_info({:update_secret, secret_id, secret_params}, socket) do
    update_secret(socket, secret_id, secret_params)
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
        <h2 class="text-2xl font-bold text-on-surface">Secret Management</h2>
        <.dm_btn
          id="new-secret-button"
          variant="primary"
          size="md"
          phx-click="new_secret"
        >
          <:prefix>
            <.dm_mdi name="plus" class="h-4 w-4" />
          </:prefix>
          New Secret
        </.dm_btn>
      </div>
      
    <!-- Filters and Search -->
      <div class="bg-surface-container p-4 rounded-lg shadow">
        <div class="flex flex-wrap gap-4 items-center">
          <.dm_select
            id="secret-rotator-filter"
            name="rotator"
            value={@filter_rotator}
            label="Rotator"
            options={rotator_filter_options(@rotators)}
            horizontal
            class="min-w-44"
            phx-change="filter_secrets"
          />

          <.dm_input
            id="secret-search-input"
            type="search"
            name="query"
            value={@search_query}
            label="Search"
            placeholder="Search secrets by name, description, or path..."
            horizontal
            field_class="min-w-0 flex-1"
            class="w-full"
            phx-change="search_secrets"
          />
        </div>
      </div>
      
    <!-- Secret Form Modal -->
      <%= if @show_form do %>
        <.live_component
          module={SecretHub.Web.SecretFormComponent}
          id="secret-form"
          changeset={@form_changeset}
          mode={@form_mode}
          secret={@selected_secret}
          rotators={@rotators}
          policies={@policies}
          return_to="/admin/secrets"
        />
      <% end %>
      
    <!-- Secret List -->
      <div class="bg-surface-container rounded-lg shadow">
        <div class="overflow-x-auto">
          <table class="min-w-full divide-y divide-outline-variant">
            <thead class="bg-surface-container-low">
              <tr>
                <th class="px-6 py-3 text-left text-xs font-medium text-on-surface-variant uppercase tracking-wider">
                  Name
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-on-surface-variant uppercase tracking-wider">
                  Path
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-on-surface-variant uppercase tracking-wider">
                  TTL
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-on-surface-variant uppercase tracking-wider">
                  Rotator
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-on-surface-variant uppercase tracking-wider">
                  Access Policies
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-on-surface-variant uppercase tracking-wider">
                  Created
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-on-surface-variant uppercase tracking-wider">
                  Updated
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-on-surface-variant uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody class="bg-surface-container divide-y divide-outline-variant">
              <%= for secret <- filtered_secrets(@secrets, @filter_rotator, @search_query) do %>
                <tr class="hover:bg-surface-container-low transition-colors">
                  <td class="px-6 py-4 whitespace-nowrap">
                    <div class="text-sm font-medium text-on-surface">{secret.name}</div>
                    <div class="text-sm text-on-surface-variant">{secret.description}</div>
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap">
                    <code class="text-sm bg-surface-container px-1 py-0.5 rounded">
                      {secret.path}
                    </code>
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm text-on-surface">
                    {format_ttl(secret.ttl_seconds)}
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap">
                    <div class="text-sm text-on-surface">{secret.rotator_name}</div>
                    <div class="text-xs text-on-surface-variant">
                      {format_rotator_type(secret.rotator_type)}
                    </div>
                  </td>
                  <td class="px-6 py-4 text-sm text-on-surface-variant">
                    <div class="flex flex-wrap gap-1">
                      <%= if Enum.empty?(secret.policies) do %>
                        <span>No policies</span>
                      <% else %>
                        <%= for policy <- secret.policies do %>
                          <span class="rounded bg-surface-container-high px-2 py-0.5 text-xs text-on-surface">
                            {policy}
                          </span>
                        <% end %>
                      <% end %>
                    </div>
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm text-on-surface-variant">
                    {format_datetime(secret.inserted_at)}
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm text-on-surface-variant">
                    {format_datetime(secret.updated_at)}
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
                    <div class="flex space-x-2">
                      <button
                        class="text-secondary hover:text-secondary"
                        phx-click="edit_secret"
                        phx-value-id={secret.id}
                      >
                        Edit
                      </button>

                      <button
                        class="text-error hover:text-error"
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
        <div class="fixed inset-0 bg-surface-container-highest/75 bg-opacity-50 flex items-center justify-center z-50">
          <div class="bg-surface-container rounded-lg p-6 shadow-xl">
            <div class="flex items-center">
              <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
              <span class="ml-2 text-on-surface-variant">Processing...</span>
            </div>
          </div>
        </div>
      <% end %>
    </div>
    """
  end

  # Private functions
  defp create_secret(socket, secret_params) do
    status = vault_status()

    if vault_sealed?(status) do
      {:noreply, vault_unavailable_socket(socket, status, :create)}
    else
      create_secret_when_unsealed(socket, secret_params, status)
    end
  end

  defp create_secret_when_unsealed(socket, secret_params, status) do
    secret_params = normalize_secret_form_params(secret_params, socket.assigns.rotators)
    policy_ids = selected_policy_ids(secret_params)

    with {:ok, secret} <-
           Secrets.create_secret(Map.put(secret_params, "created_by", "admin-web")),
         {:ok, _secret_with_policies} <- Secrets.set_secret_policies(secret.id, policy_ids) do
      Logger.info("Created secret: #{secret.id}")
      secrets = fetch_secrets()

      socket =
        socket
        |> assign(:vault_status, status)
        |> assign(:secrets, secrets)
        |> assign(:show_form, false)
        |> put_flash(:info, "Secret created successfully")
        |> push_patch(to: "/admin/secrets")

      {:noreply, socket}
    else
      {:error, %Ecto.Changeset{} = changeset} ->
        socket =
          socket
          |> assign(:form_changeset, Map.put(changeset, :action, :insert))
          |> put_flash(:error, "Failed to create secret: validation error")

        {:noreply, socket}

      {:error, :sealed} ->
        {:noreply,
         socket
         |> assign(:vault_status, vault_status())
         |> put_flash(:error, vault_unavailable_message(:create))}

      {:error, :not_initialized} ->
        {:noreply,
         socket
         |> assign(:vault_status, vault_status())
         |> put_flash(
           :error,
           "Vault is not initialized. Initialize and unseal the vault before creating secrets."
         )}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to create secret: #{inspect(reason)}")}
    end
  end

  defp update_secret(socket, secret_id, secret_params) do
    status = vault_status()

    if vault_sealed?(status) do
      {:noreply, vault_unavailable_socket(socket, status, :update)}
    else
      update_secret_when_unsealed(socket, secret_id, secret_params, status)
    end
  end

  defp update_secret_when_unsealed(socket, secret_id, secret_params, status) do
    secret_params = normalize_secret_form_params(secret_params, socket.assigns.rotators)
    policy_ids = selected_policy_ids(secret_params)

    with {:ok, updated_secret} <-
           Secrets.update_secret(secret_id, secret_params,
             created_by: "admin-web",
             change_description: "Updated manually in web UI",
             via_rotator_id: selected_rotator_id(secret_params, socket.assigns.rotators)
           ),
         {:ok, _secret_with_policies} <-
           Secrets.set_secret_policies(updated_secret.id, policy_ids) do
      Logger.info("Updated secret: #{updated_secret.id}")
      secrets = fetch_secrets()

      socket =
        socket
        |> assign(:vault_status, status)
        |> assign(:secrets, secrets)
        |> assign(:show_form, false)
        |> put_flash(:info, "Secret updated successfully")
        |> push_patch(to: "/admin/secrets")

      {:noreply, socket}
    else
      {:error, "Secret not found"} ->
        {:noreply, put_flash(socket, :error, "Secret not found")}

      {:error, %Ecto.Changeset{} = changeset} ->
        socket =
          socket
          |> assign(:form_changeset, Map.put(changeset, :action, :update))
          |> put_flash(:error, "Failed to update secret: validation error")

        {:noreply, socket}

      {:error, :sealed} ->
        {:noreply,
         socket
         |> assign(:vault_status, vault_status())
         |> put_flash(:error, vault_unavailable_message(:update))}

      {:error, :not_initialized} ->
        {:noreply,
         socket
         |> assign(:vault_status, vault_status())
         |> put_flash(
           :error,
           "Vault is not initialized. Initialize and unseal the vault before updating secrets."
         )}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to update secret: #{inspect(reason)}")}
    end
  end

  defp fetch_secrets do
    Secrets.list_secrets()
    |> Enum.map(&format_secret_for_display/1)
  end

  defp format_secret_for_display(secret) do
    rotator = secret.rotator

    %{
      id: secret.id,
      name: secret.name,
      description: secret.description,
      path: secret.secret_path,
      ttl_seconds: ttl_seconds(secret),
      rotator_id: secret.rotator_id,
      rotator_name: if(rotator, do: rotator.name, else: "Unknown"),
      rotator_type: if(rotator, do: rotator.rotator_type, else: nil),
      policy_ids: Enum.map(secret.policies || [], & &1.id),
      policies: Enum.map(secret.policies || [], & &1.name),
      inserted_at: secret.inserted_at,
      updated_at: secret.updated_at
    }
  end

  defp fetch_rotators do
    Secrets.list_rotators()
    |> Enum.map(&%{id: &1.id, slug: &1.slug, name: &1.name, rotator_type: &1.rotator_type})
  end

  defp fetch_policies do
    Policies.list_policies()
    |> Enum.map(&%{id: &1.id, name: &1.name})
  end

  defp rotator_filter_options(rotators) do
    [{"all", "All"} | Enum.map(rotators, &{&1.id, &1.name})]
  end

  defp filtered_secrets(secrets, "all", ""), do: secrets

  defp filtered_secrets(secrets, rotator_id, "") do
    Enum.filter(secrets, &(&1.rotator_id == rotator_id))
  end

  defp filtered_secrets(secrets, "all", query) do
    query = String.downcase(query)

    Enum.filter(secrets, fn secret ->
      String.contains?(String.downcase(secret.name || ""), query) or
        String.contains?(String.downcase(secret.path || ""), query) or
        String.contains?(String.downcase(secret.description || ""), query)
    end)
  end

  defp filtered_secrets(secrets, rotator_id, query) do
    secrets
    |> Enum.filter(&(&1.rotator_id == rotator_id))
    |> filtered_secrets("all", query)
  end

  defp changeset_for_secret(secret, rotators) do
    Secret.changeset(%Secret{}, extract_secret_attrs(secret, rotators))
  end

  defp normalize_secret_form_params(secret_params, rotators) do
    secret_params
    |> Map.put_new("rotator_id", default_rotator_id(rotators))
    |> Map.put_new("ttl_seconds", 0)
    |> Map.put_new("secret_type", "static")
    |> Map.put_new("engine_type", "static")
  end

  defp with_default_rotator(secret_params, rotators) do
    Map.put_new(secret_params, "rotator_id", default_rotator_id(rotators))
  end

  defp selected_policy_ids(secret_params) do
    secret_params
    |> Map.get("policies", [])
    |> List.wrap()
    |> Enum.reject(&(&1 in [nil, ""]))
  end

  defp selected_rotator_id(secret_params, rotators) do
    case Map.get(secret_params, "rotator_id") do
      rotator_id when is_binary(rotator_id) and rotator_id != "" -> rotator_id
      _ -> default_rotator_id(rotators)
    end
  end

  defp extract_secret_attrs(secret, rotators) do
    %{
      name: get_field(secret, :name, ""),
      description: get_field(secret, :description, ""),
      secret_path: extract_secret_path(secret),
      value: "",
      rotator_id: get_field(secret, :rotator_id, default_rotator_id(rotators)),
      ttl_seconds: get_field(secret, :ttl_seconds, 0),
      policies: get_field(secret, :policy_ids, []),
      engine_type: "static",
      secret_type: :static
    }
  end

  defp get_field(map, key, default), do: Map.get(map, key) || default

  defp extract_secret_path(secret) do
    get_field(secret, :secret_path, nil) || get_field(secret, :path, "")
  end

  defp default_rotator_id(rotators) do
    rotators
    |> Enum.find(&(&1.slug == "manual-web-ui"))
    |> case do
      nil -> rotators |> List.first() |> then(&(&1 && &1.id))
      rotator -> rotator.id
    end
  end

  defp ttl_seconds(%{ttl_seconds: seconds}) when is_integer(seconds), do: seconds
  defp ttl_seconds(%{ttl_hours: hours}) when is_integer(hours), do: hours * 3600
  defp ttl_seconds(_secret), do: 0

  defp format_ttl(0), do: "Always alive"
  defp format_ttl(seconds), do: "#{seconds}s"

  defp format_rotator_type(nil), do: ""

  defp format_rotator_type(type) do
    type
    |> to_string()
    |> String.replace("_", " ")
  end

  defp format_datetime(nil), do: "Never"

  defp format_datetime(datetime) do
    DateTime.to_string(datetime)
  end

  defp vault_status do
    case Process.whereis(SealState) do
      nil -> nil
      _pid -> SealState.status()
    end
  catch
    :exit, _reason -> nil
  end

  defp vault_sealed?(%{initialized: true, sealed: true}), do: true
  defp vault_sealed?(_status), do: false

  defp vault_unavailable_socket(socket, status, action) do
    socket
    |> assign(:vault_status, status)
    |> assign(:show_form, false)
    |> put_flash(:error, vault_unavailable_message(action))
  end

  defp vault_unavailable_message(:update),
    do: "Vault is sealed. Unseal the vault before updating secrets."

  defp vault_unavailable_message(_action),
    do: "Vault is sealed. Unseal the vault before creating secrets."
end
