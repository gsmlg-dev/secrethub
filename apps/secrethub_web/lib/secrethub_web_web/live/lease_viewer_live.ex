defmodule SecretHub.WebWeb.LeaseViewerLive do
  @moduledoc """
  LiveView for viewing and managing active dynamic secret leases.

  Features:
  - Real-time table of active leases with TTL countdown
  - Filtering by role, agent, and status
  - Manual lease revocation
  - Lease renewal
  - Statistics dashboard
  """
  use SecretHub.WebWeb, :live_view
  alias SecretHub.Core.LeaseManager
  require Logger

  @refresh_interval 1_000

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      # Schedule periodic refresh for TTL countdown
      Process.send_after(self(), :update_ttls, @refresh_interval)
    end

    socket =
      socket
      |> assign(:page_title, "Lease Viewer")
      |> assign(:leases, [])
      |> assign(:filtered_leases, [])
      |> assign(:stats, %{})
      |> assign(:filter_role, "")
      |> assign(:filter_agent, "")
      |> assign(:filter_status, "all")
      |> assign(:search_query, "")
      |> assign(:sort_by, :expires_at)
      |> assign(:sort_order, :asc)
      |> load_leases()

    {:ok, socket}
  end

  @impl true
  def handle_info(:update_ttls, socket) do
    # Schedule next update
    Process.send_after(self(), :update_ttls, @refresh_interval)

    socket =
      socket
      |> load_leases()
      |> apply_filters()

    {:noreply, socket}
  end

  @impl true
  def handle_event("filter_role", %{"value" => role}, socket) do
    socket =
      socket
      |> assign(:filter_role, role)
      |> apply_filters()

    {:noreply, socket}
  end

  @impl true
  def handle_event("filter_agent", %{"value" => agent}, socket) do
    socket =
      socket
      |> assign(:filter_agent, agent)
      |> apply_filters()

    {:noreply, socket}
  end

  @impl true
  def handle_event("filter_status", %{"value" => status}, socket) do
    socket =
      socket
      |> assign(:filter_status, status)
      |> apply_filters()

    {:noreply, socket}
  end

  @impl true
  def handle_event("search", %{"query" => query}, socket) do
    socket =
      socket
      |> assign(:search_query, query)
      |> apply_filters()

    {:noreply, socket}
  end

  @impl true
  def handle_event("sort", %{"field" => field}, socket) do
    field_atom = String.to_atom(field)

    sort_order =
      if socket.assigns.sort_by == field_atom do
        case socket.assigns.sort_order do
          :asc -> :desc
          :desc -> :asc
        end
      else
        :asc
      end

    socket =
      socket
      |> assign(:sort_by, field_atom)
      |> assign(:sort_order, sort_order)
      |> apply_filters()

    {:noreply, socket}
  end

  @impl true
  def handle_event("revoke_lease", %{"lease_id" => lease_id}, socket) do
    case LeaseManager.revoke_lease(lease_id) do
      :ok ->
        socket =
          socket
          |> put_flash(:info, "Lease #{lease_id} revoked successfully")
          |> load_leases()
          |> apply_filters()

        {:noreply, socket}

      {:error, :not_found} ->
        {:noreply, put_flash(socket, :error, "Lease not found: #{lease_id}")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to revoke lease: #{inspect(reason)}")}
    end
  end

  @impl true
  def handle_event("renew_lease", %{"lease_id" => lease_id}, socket) do
    case LeaseManager.renew_lease(lease_id) do
      {:ok, _lease} ->
        socket =
          socket
          |> put_flash(:info, "Lease #{lease_id} renewed successfully")
          |> load_leases()
          |> apply_filters()

        {:noreply, socket}

      {:error, :not_found} ->
        {:noreply, put_flash(socket, :error, "Lease not found: #{lease_id}")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to renew lease: #{inspect(reason)}")}
    end
  end

  @impl true
  def handle_event("clear_filters", _params, socket) do
    socket =
      socket
      |> assign(:filter_role, "")
      |> assign(:filter_agent, "")
      |> assign(:filter_status, "all")
      |> assign(:search_query, "")
      |> apply_filters()

    {:noreply, socket}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="container mx-auto px-4 py-8">
      <div class="mb-6">
        <h1 class="text-3xl font-bold text-gray-900">Dynamic Secret Leases</h1>
        <p class="mt-2 text-gray-600">
          View and manage active dynamic secret leases
        </p>
      </div>
      
    <!-- Statistics Cards -->
      <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <div class="bg-white shadow rounded-lg p-6">
          <div class="text-sm font-medium text-gray-500">Total Leases</div>
          <div class="mt-2 text-3xl font-bold text-gray-900">{@stats[:total] || 0}</div>
        </div>

        <div class="bg-white shadow rounded-lg p-6">
          <div class="text-sm font-medium text-gray-500">Active</div>
          <div class="mt-2 text-3xl font-bold text-green-600">{@stats[:active] || 0}</div>
        </div>

        <div class="bg-white shadow rounded-lg p-6">
          <div class="text-sm font-medium text-gray-500">Expiring Soon</div>
          <div class="mt-2 text-3xl font-bold text-yellow-600">{@stats[:expiring_soon] || 0}</div>
        </div>

        <div class="bg-white shadow rounded-lg p-6">
          <div class="text-sm font-medium text-gray-500">Expired</div>
          <div class="mt-2 text-3xl font-bold text-red-600">{@stats[:expired] || 0}</div>
        </div>
      </div>
      
    <!-- Filters -->
      <div class="bg-white shadow rounded-lg p-6 mb-6">
        <h2 class="text-lg font-semibold mb-4">Filters</h2>

        <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">Search</label>
            <input
              type="text"
              phx-change="search"
              phx-value-query={@search_query}
              phx-debounce="300"
              value={@search_query}
              placeholder="Lease ID, role, agent..."
              class="input input-bordered w-full"
            />
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">Role</label>
            <input
              type="text"
              phx-change="filter_role"
              phx-value-value={@filter_role}
              phx-debounce="300"
              value={@filter_role}
              placeholder="Filter by role..."
              class="input input-bordered w-full"
            />
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">Agent ID</label>
            <input
              type="text"
              phx-change="filter_agent"
              phx-value-value={@filter_agent}
              phx-debounce="300"
              value={@filter_agent}
              placeholder="Filter by agent..."
              class="input input-bordered w-full"
            />
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">Status</label>
            <select
              phx-change="filter_status"
              phx-value-value={@filter_status}
              class="select select-bordered w-full"
            >
              <option value="all" selected={@filter_status == "all"}>All</option>
              <option value="active" selected={@filter_status == "active"}>Active</option>
              <option value="expiring_soon" selected={@filter_status == "expiring_soon"}>
                Expiring Soon
              </option>
              <option value="expired" selected={@filter_status == "expired"}>Expired</option>
            </select>
          </div>
        </div>

        <div class="mt-4">
          <button
            phx-click="clear_filters"
            class="btn btn-ghost btn-sm"
          >
            Clear Filters
          </button>
        </div>
      </div>
      
    <!-- Leases Table -->
      <div class="bg-white shadow rounded-lg overflow-hidden">
        <table class="min-w-full divide-y divide-gray-200">
          <thead class="bg-gray-50">
            <tr>
              <th
                class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer hover:bg-gray-100"
                phx-click="sort"
                phx-value-field="id"
              >
                Lease ID
                <%= if @sort_by == :id do %>
                  <span class="ml-1">{if @sort_order == :asc, do: "↑", else: "↓"}</span>
                <% end %>
              </th>
              <th
                class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer hover:bg-gray-100"
                phx-click="sort"
                phx-value-field="role_name"
              >
                Role
                <%= if @sort_by == :role_name do %>
                  <span class="ml-1">{if @sort_order == :asc, do: "↑", else: "↓"}</span>
                <% end %>
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Agent ID
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Engine
              </th>
              <th
                class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer hover:bg-gray-100"
                phx-click="sort"
                phx-value-field="created_at"
              >
                Created
                <%= if @sort_by == :created_at do %>
                  <span class="ml-1">{if @sort_order == :asc, do: "↑", else: "↓"}</span>
                <% end %>
              </th>
              <th
                class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer hover:bg-gray-100"
                phx-click="sort"
                phx-value-field="expires_at"
              >
                Expires
                <%= if @sort_by == :expires_at do %>
                  <span class="ml-1">{if @sort_order == :asc, do: "↑", else: "↓"}</span>
                <% end %>
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                TTL
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Status
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Actions
              </th>
            </tr>
          </thead>
          <tbody class="bg-white divide-y divide-gray-200">
            <%= for lease <- @filtered_leases do %>
              <tr class={"#{ttl_row_class(lease)}"}>
                <td class="px-6 py-4 whitespace-nowrap text-sm font-mono text-gray-900">
                  {String.slice(lease.id, 0, 8)}...
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                  {lease.role_name}
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                  <%= if lease.agent_id do %>
                    {String.slice(lease.agent_id, 0, 8)}...
                  <% else %>
                    N/A
                  <% end %>
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                  {lease.engine_type}
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                  {format_datetime(lease.created_at)}
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                  {format_datetime(lease.expires_at)}
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm font-semibold">
                  <span class={ttl_class(lease)}>
                    {format_ttl(lease)}
                  </span>
                </td>
                <td class="px-6 py-4 whitespace-nowrap">
                  <span class={"px-2 inline-flex text-xs leading-5 font-semibold rounded-full #{status_badge_class(lease)}"}>
                    {status_text(lease)}
                  </span>
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
                  <%= if is_expired?(lease) do %>
                    <span class="text-gray-400">No actions</span>
                  <% else %>
                    <button
                      phx-click="renew_lease"
                      phx-value-lease_id={lease.id}
                      class="text-blue-600 hover:text-blue-900 mr-3"
                      title="Renew lease"
                    >
                      Renew
                    </button>
                    <button
                      phx-click="revoke_lease"
                      phx-value-lease_id={lease.id}
                      class="text-red-600 hover:text-red-900"
                      data-confirm="Are you sure you want to revoke this lease?"
                      title="Revoke lease"
                    >
                      Revoke
                    </button>
                  <% end %>
                </td>
              </tr>
            <% end %>
          </tbody>
        </table>

        <%= if @filtered_leases == [] do %>
          <div class="px-6 py-12 text-center text-gray-500">
            <%= if @leases == [] do %>
              No active leases found.
            <% else %>
              No leases match the current filters.
            <% end %>
          </div>
        <% end %>
      </div>
    </div>
    """
  end

  # Private helper functions

  defp load_leases(socket) do
    case LeaseManager.list_active_leases() do
      {:ok, leases} ->
        stats = calculate_stats(leases)

        socket
        |> assign(:leases, leases)
        |> assign(:stats, stats)

      {:error, _reason} ->
        # If LeaseManager is not started in test mode, use empty list
        socket
        |> assign(:leases, [])
        |> assign(:stats, %{total: 0, active: 0, expiring_soon: 0, expired: 0})
    end
  end

  defp apply_filters(socket) do
    leases = socket.assigns.leases
    filter_role = socket.assigns.filter_role
    filter_agent = socket.assigns.filter_agent
    filter_status = socket.assigns.filter_status
    search_query = socket.assigns.search_query

    filtered =
      leases
      |> filter_by_role(filter_role)
      |> filter_by_agent(filter_agent)
      |> filter_by_status(filter_status)
      |> filter_by_search(search_query)
      |> sort_leases(socket.assigns.sort_by, socket.assigns.sort_order)

    assign(socket, :filtered_leases, filtered)
  end

  defp filter_by_role(leases, ""), do: leases

  defp filter_by_role(leases, role) do
    Enum.filter(leases, fn lease ->
      String.contains?(String.downcase(lease.role_name), String.downcase(role))
    end)
  end

  defp filter_by_agent(leases, ""), do: leases

  defp filter_by_agent(leases, agent) do
    Enum.filter(leases, fn lease ->
      lease.agent_id && String.contains?(String.downcase(lease.agent_id), String.downcase(agent))
    end)
  end

  defp filter_by_status(leases, "all"), do: leases

  defp filter_by_status(leases, "active") do
    Enum.filter(leases, fn lease -> is_active?(lease) end)
  end

  defp filter_by_status(leases, "expiring_soon") do
    Enum.filter(leases, fn lease -> is_expiring_soon?(lease) end)
  end

  defp filter_by_status(leases, "expired") do
    Enum.filter(leases, fn lease -> is_expired?(lease) end)
  end

  defp filter_by_search(leases, ""), do: leases

  defp filter_by_search(leases, query) do
    query_lower = String.downcase(query)

    Enum.filter(leases, fn lease ->
      String.contains?(String.downcase(lease.id), query_lower) ||
        String.contains?(String.downcase(lease.role_name), query_lower) ||
        String.contains?(String.downcase(lease.engine_type), query_lower) ||
        (lease.agent_id && String.contains?(String.downcase(lease.agent_id), query_lower))
    end)
  end

  defp sort_leases(leases, sort_by, sort_order) do
    sorted =
      Enum.sort_by(leases, fn lease ->
        case sort_by do
          :id -> lease.id
          :role_name -> lease.role_name
          :created_at -> lease.created_at
          :expires_at -> lease.expires_at
          _ -> lease.expires_at
        end
      end)

    case sort_order do
      :asc -> sorted
      :desc -> Enum.reverse(sorted)
    end
  end

  defp calculate_stats(leases) do
    total = length(leases)
    active = Enum.count(leases, &is_active?/1)
    expiring_soon = Enum.count(leases, &is_expiring_soon?/1)
    expired = Enum.count(leases, &is_expired?/1)

    %{
      total: total,
      active: active,
      expiring_soon: expiring_soon,
      expired: expired
    }
  end

  defp is_expired?(lease) do
    DateTime.compare(lease.expires_at, DateTime.utc_now()) == :lt
  end

  defp is_expiring_soon?(lease) do
    now = DateTime.utc_now()
    remaining = DateTime.diff(lease.expires_at, now)
    threshold = lease.lease_duration * 0.2

    !is_expired?(lease) && remaining < threshold
  end

  defp is_active?(lease) do
    !is_expired?(lease) && !is_expiring_soon?(lease)
  end

  defp format_ttl(lease) do
    now = DateTime.utc_now()
    remaining = DateTime.diff(lease.expires_at, now)

    cond do
      remaining < 0 -> "Expired"
      remaining < 60 -> "#{remaining}s"
      remaining < 3600 -> "#{div(remaining, 60)}m #{rem(remaining, 60)}s"
      remaining < 86400 -> "#{div(remaining, 3600)}h #{div(rem(remaining, 3600), 60)}m"
      true -> "#{div(remaining, 86400)}d #{div(rem(remaining, 86400), 3600)}h"
    end
  end

  defp ttl_class(lease) do
    cond do
      is_expired?(lease) -> "text-red-600"
      is_expiring_soon?(lease) -> "text-yellow-600"
      true -> "text-green-600"
    end
  end

  defp ttl_row_class(lease) do
    cond do
      is_expired?(lease) -> "bg-red-50"
      is_expiring_soon?(lease) -> "bg-yellow-50"
      true -> ""
    end
  end

  defp status_text(lease) do
    cond do
      is_expired?(lease) -> "Expired"
      is_expiring_soon?(lease) -> "Expiring Soon"
      true -> "Active"
    end
  end

  defp status_badge_class(lease) do
    cond do
      is_expired?(lease) -> "bg-red-100 text-red-800"
      is_expiring_soon?(lease) -> "bg-yellow-100 text-yellow-800"
      true -> "bg-green-100 text-green-800"
    end
  end

  defp format_datetime(datetime) do
    Calendar.strftime(datetime, "%Y-%m-%d %H:%M:%S")
  end
end
