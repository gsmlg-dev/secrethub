defmodule SecretHub.Web.AuditLogLive do
  @moduledoc """
  LiveView for audit log viewing with advanced filtering and search capabilities.
  """

  use SecretHub.Web, :live_view
  require Logger

  alias SecretHub.Core.Audit

  @impl true
  def mount(_params, _session, socket) do
    audit_logs = fetch_audit_logs()
    event_types = fetch_event_types()

    socket =
      socket
      |> assign(:audit_logs, audit_logs)
      |> assign(:event_types, event_types)
      |> assign(:selected_event, nil)
      |> assign(:loading, false)
      |> assign(:filters, %{
        event_type: "all",
        agent_id: "",
        secret_path: "",
        date_from: "",
        date_to: "",
        access_granted: "all"
      })
      |> assign(:search_query, "")
      |> assign(:pagination, %{
        page: 1,
        per_page: 50,
        total_count: 0,
        total_pages: 0
      })

    {:ok, socket}
  end

  @impl true
  def handle_params(%{"id" => event_id}, _url, socket) do
    event = Enum.find(socket.assigns.audit_logs, &(&1.id == event_id))
    socket = assign(socket, :selected_event, event)
    {:noreply, socket}
  end

  def handle_params(_params, _url, socket) do
    socket = assign(socket, :selected_event, nil)
    {:noreply, socket}
  end

  @impl true
  def handle_event("filter_logs", %{"filters" => filter_params}, socket) do
    filters = Map.merge(socket.assigns.filters, filter_params)

    audit_logs = fetch_filtered_audit_logs(filters)
    pagination = calculate_pagination(audit_logs, socket.assigns.pagination.page)

    socket =
      socket
      |> assign(:audit_logs, audit_logs)
      |> assign(:filters, filters)
      |> assign(:pagination, pagination)

    {:noreply, socket}
  end

  @impl true
  def handle_event("search_logs", %{"query" => query}, socket) do
    socket = assign(socket, :search_query, query)
    {:noreply, socket}
  end

  @impl true
  def handle_event("export_logs", _params, socket) do
    Logger.info("Exporting audit logs with filters: #{inspect(socket.assigns.filters)}")

    filters = build_audit_filters(socket.assigns.filters)
    csv_content = Audit.export_to_csv(filters)

    # Return CSV as download
    socket =
      socket
      |> put_flash(:info, "Audit logs exported successfully")
      |> push_event("download", %{
        filename: "audit_logs_#{DateTime.utc_now() |> DateTime.to_unix()}.csv",
        content: csv_content
      })

    {:noreply, socket}
  end

  @impl true
  def handle_event("clear_filters", _params, socket) do
    filters = %{
      event_type: "all",
      agent_id: "",
      secret_path: "",
      date_from: "",
      date_to: "",
      access_granted: "all"
    }

    audit_logs = fetch_audit_logs()
    pagination = calculate_pagination(audit_logs, 1)

    socket =
      socket
      |> assign(:audit_logs, audit_logs)
      |> assign(:filters, filters)
      |> assign(:search_query, "")
      |> assign(:pagination, pagination)

    {:noreply, socket}
  end

  @impl true
  def handle_event("page_change", %{"page" => page}, socket) do
    page = String.to_integer(page)

    audit_logs = fetch_filtered_audit_logs(socket.assigns.filters)
    pagination = calculate_pagination(audit_logs, page)

    socket =
      socket
      |> assign(:pagination, pagination)

    {:noreply, socket}
  end

  @impl true
  def handle_event("select_event", %{"id" => event_id}, socket) do
    _event = Enum.find(socket.assigns.audit_logs, &(&1.id == event_id))
    socket = push_patch(socket, to: "/admin/audit/#{event_id}")
    {:noreply, socket}
  end

  @impl true
  def handle_info({:close_event_details}, socket) do
    socket =
      socket
      |> assign(:selected_event, nil)
      |> push_patch(to: "/admin/audit")

    {:noreply, socket}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="space-y-6">
      <!-- Header -->
      <div class="flex justify-between items-center">
        <div>
          <h2 class="text-2xl font-bold text-gray-900">Audit Logs</h2>
          <p class="text-sm text-gray-600">
            Monitor and analyze all secret access attempts and system events
          </p>
        </div>
        <div class="flex space-x-4">
          <button
            class="btn-secondary"
            phx-click="export_logs"
          >
            <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path
                stroke-linecap="round"
                stroke-linejoin="round"
                stroke-width="2"
                d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
              />
            </svg>
            Export Logs
          </button>
        </div>
      </div>
      
    <!-- Filters -->
      <div class="bg-white p-6 rounded-lg shadow">
        <div class="flex justify-between items-center mb-4">
          <h3 class="text-lg font-medium text-gray-900">Filters</h3>
          <button
            class="text-sm text-blue-600 hover:text-blue-800"
            phx-click="clear_filters"
          >
            Clear all filters
          </button>
        </div>

        <form phx-change="filter_logs" class="space-y-4">
          <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">Event Type</label>
              <select name="filters[event_type]" class="form-select w-full">
                <option value="all" selected={@filters.event_type == "all"}>All Events</option>
                <%= for type <- @event_types do %>
                  <option
                    value={type}
                    selected={@filters.event_type == type}
                  >
                    {format_event_type(type)}
                  </option>
                <% end %>
              </select>
            </div>

            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">Access Status</label>
              <select name="filters[access_granted]" class="form-select w-full">
                <option value="all" selected={@filters.access_granted == "all"}>All Status</option>
                <option value="true" selected={@filters.access_granted == "true"}>Granted</option>
                <option value="false" selected={@filters.access_granted == "false"}>Denied</option>
              </select>
            </div>

            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">Agent ID</label>
              <input
                type="text"
                name="filters[agent_id]"
                value={@filters.agent_id}
                class="form-input w-full"
                placeholder="agent-prod-01"
              />
            </div>

            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">Secret Path</label>
              <input
                type="text"
                name="filters[secret_path]"
                value={@filters.secret_path}
                class="form-input w-full"
                placeholder="prod/db/postgres"
              />
            </div>

            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">Date From</label>
              <input
                type="datetime-local"
                name="filters[date_from]"
                value={@filters.date_from}
                class="form-input w-full"
              />
            </div>

            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">Date To</label>
              <input
                type="datetime-local"
                name="filters[date_to]"
                value={@filters.date_to}
                class="form-input w-full"
              />
            </div>
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1">Search</label>
            <input
              type="text"
              name="query"
              value={@search_query}
              class="form-input w-full"
              placeholder="Search by IP address, policy, or correlation ID..."
              phx-change="search_logs"
            />
          </div>
        </form>
      </div>
      
    <!-- Results Summary -->
      <div class="bg-blue-50 border border-blue-200 rounded-lg p-4">
        <div class="flex items-center justify-between">
          <div>
            <span class="text-sm font-medium text-blue-800">
              Showing {length(current_page_logs(@audit_logs, @pagination.page, @pagination.per_page))} of {@pagination.total_count} audit events
            </span>
          </div>
          <%= if @pagination.total_pages > 1 do %>
            <div class="flex items-center space-x-2">
              <span class="text-sm text-blue-800">Page:</span>
              <div class="flex space-x-1">
                <%= for page <- 1..@pagination.total_pages do %>
                  <button
                    class={"px-3 py-1 text-sm rounded #{if page == @pagination.page, do: "bg-blue-600 text-white", else: "bg-white text-blue-600 border border-blue-300 hover:bg-blue-50"}"}
                    phx-click="page_change"
                    phx-value-page={page}
                  >
                    {page}
                  </button>
                <% end %>
              </div>
            </div>
          <% end %>
        </div>
      </div>
      
    <!-- Audit Log Table -->
      <div class="bg-white rounded-lg shadow">
        <div class="overflow-x-auto">
          <table class="min-w-full divide-y divide-gray-200">
            <thead class="bg-gray-50">
              <tr>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Timestamp
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Event Type
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Agent
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Secret Path
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Status
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Source IP
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Response Time
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody class="bg-white divide-y divide-gray-200">
              <%= for event <- current_page_logs(@audit_logs, @pagination.page, @pagination.per_page) do %>
                <tr
                  class="hover:bg-gray-50 transition-colors cursor-pointer"
                  phx-click="select_event"
                  phx-value-id={event.id}
                >
                  <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {format_timestamp(event.timestamp)}
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap">
                    <span class={"inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium #{event_type_badge_color(event.event_type)}"}>
                      {format_event_type(event.event_type)}
                    </span>
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {event.agent_id}
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap">
                    <code class="text-sm bg-gray-100 px-1 py-0.5 rounded">
                      {event.secret_path || "-"}
                    </code>
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap">
                    <div class="flex items-center">
                      <div class={"w-2 h-2 rounded-full mr-2 #{access_status_color(event.access_granted)}"}>
                      </div>
                      <span class="text-sm">
                        {if event.access_granted, do: "Granted", else: "Denied"}
                      </span>
                    </div>
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {event.source_ip}
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {event.response_time_ms}ms
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
                    <button class="text-indigo-600 hover:text-indigo-900">
                      View Details
                    </button>
                  </td>
                </tr>
              <% end %>
            </tbody>
          </table>
        </div>
      </div>
      
    <!-- Event Details Modal -->
      <%= if @selected_event do %>
        <.live_component
          module={SecretHub.Web.AuditEventDetailsComponent}
          id={"event-#{@selected_event.id}"}
          event={@selected_event}
        />
      <% end %>
    </div>
    """
  end

  # Helper functions
  defp fetch_audit_logs do
    # FIXME: Replace with actual SecretHub.Core.Audit.list_logs()
    [
      %{
        id: "1",
        timestamp: DateTime.utc_now() |> DateTime.add(-300, :second),
        event_type: "secret_access",
        agent_id: "agent-prod-01",
        secret_path: "prod/db/postgres",
        access_granted: true,
        policy_matched: "webapp-secrets",
        source_ip: "10.0.1.42",
        response_time_ms: 45,
        correlation_id: "550e8400-e29b-41d4-a5a0-c276e42c5ca",
        user_agent: "SecretHub-Agent/1.0.0",
        request_size: 245,
        response_size: 1024
      },
      %{
        id: "2",
        timestamp: DateTime.utc_now() |> DateTime.add(-600, :second),
        event_type: "secret_access_denied",
        agent_id: "agent-prod-02",
        secret_path: "prod/api/payment",
        access_granted: false,
        policy_matched: "production-secrets",
        denial_reason: "Agent not authorized for production secrets",
        source_ip: "10.0.1.45",
        response_time_ms: 23,
        correlation_id: "550e8400-e29b-41d4-a5a0-c276e42c5cb",
        user_agent: "SecretHub-Agent/1.0.1",
        request_size: 189,
        response_size: 156
      },
      %{
        id: "3",
        timestamp: DateTime.utc_now() |> DateTime.add(-1200, :second),
        event_type: "agent_connect",
        agent_id: "agent-dev-01",
        secret_path: nil,
        access_granted: true,
        policy_matched: "development-access",
        source_ip: "192.168.1.100",
        response_time_ms: 89,
        correlation_id: "550e8400-e29b-41d4-a5a0-c276e42c5cc",
        user_agent: "SecretHub-Agent/0.9.0",
        request_size: 412,
        response_size: 2048
      }
    ]
  end

  defp fetch_event_types do
    # FIXME: Replace with actual event types from audit system
    [
      "secret_access",
      "secret_access_denied",
      "agent_connect",
      "agent_disconnect",
      "secret_created",
      "secret_updated",
      "secret_deleted",
      "policy_created",
      "policy_updated"
    ]
  end

  defp fetch_filtered_audit_logs(_filters) do
    fetch_audit_logs()
    # FIXME: Apply actual filtering logic
  end

  defp current_page_logs(logs, page, per_page) do
    start_index = (page - 1) * per_page
    Enum.slice(logs, start_index, per_page)
  end

  defp calculate_pagination(logs, page) do
    per_page = 50
    total_count = length(logs)
    total_pages = ceil(total_count / per_page)

    %{
      page: page,
      per_page: per_page,
      total_count: total_count,
      total_pages: total_pages
    }
  end

  defp format_timestamp(datetime) do
    DateTime.to_string(datetime)
  end

  defp format_event_type("secret_access"), do: "Secret Access"
  defp format_event_type("secret_access_denied"), do: "Access Denied"
  defp format_event_type("agent_connect"), do: "Agent Connect"
  defp format_event_type("agent_disconnect"), do: "Agent Disconnect"
  defp format_event_type("secret_created"), do: "Secret Created"
  defp format_event_type("secret_updated"), do: "Secret Updated"
  defp format_event_type("secret_deleted"), do: "Secret Deleted"
  defp format_event_type("policy_created"), do: "Policy Created"
  defp format_event_type("policy_updated"), do: "Policy Updated"
  defp format_event_type(type), do: String.replace(String.capitalize(type), "_", " ")

  defp event_type_badge_color("secret_access"), do: "bg-green-100 text-green-800"
  defp event_type_badge_color("secret_access_denied"), do: "bg-red-100 text-red-800"
  defp event_type_badge_color("agent_connect"), do: "bg-blue-100 text-blue-800"
  defp event_type_badge_color("agent_disconnect"), do: "bg-yellow-100 text-yellow-800"
  defp event_type_badge_color(_), do: "bg-gray-100 text-gray-800"

  defp access_status_color(true), do: "bg-green-500"
  defp access_status_color(false), do: "bg-red-500"

  defp build_audit_filters(ui_filters) do
    %{}
    |> add_event_type_filter(ui_filters.event_type)
    |> add_agent_id_filter(ui_filters.agent_id)
    |> add_access_granted_filter(ui_filters.access_granted)
    |> add_date_from_filter(ui_filters.date_from)
    |> add_date_to_filter(ui_filters.date_to)
  end

  defp add_event_type_filter(filters, "all"), do: filters
  defp add_event_type_filter(filters, event_type), do: Map.put(filters, :event_type, event_type)

  defp add_agent_id_filter(filters, ""), do: filters
  defp add_agent_id_filter(filters, agent_id), do: Map.put(filters, :actor_id, agent_id)

  defp add_access_granted_filter(filters, "all"), do: filters

  defp add_access_granted_filter(filters, access_granted) do
    Map.put(filters, :access_granted, access_granted == "granted")
  end

  defp add_date_from_filter(filters, ""), do: filters

  defp add_date_from_filter(filters, date_from) do
    case DateTime.from_iso8601(date_from <> "T00:00:00Z") do
      {:ok, dt, _} -> Map.put(filters, :from_date, dt)
      _ -> filters
    end
  end

  defp add_date_to_filter(filters, ""), do: filters

  defp add_date_to_filter(filters, date_to) do
    case DateTime.from_iso8601(date_to <> "T23:59:59Z") do
      {:ok, dt, _} -> Map.put(filters, :to_date, dt)
      _ -> filters
    end
  end
end
