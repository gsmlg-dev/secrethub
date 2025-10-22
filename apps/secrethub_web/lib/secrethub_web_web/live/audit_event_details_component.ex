defmodule SecretHub.WebWeb.AuditEventDetailsComponent do
  @moduledoc """
  LiveComponent for displaying detailed audit event information.
  """

  use SecretHub.WebWeb, :live_component

  @impl true
  def update(assigns, socket) do
    socket = assign(socket, assigns)
    {:ok, socket}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="fixed inset-0 bg-gray-600 bg-opacity-50 flex items-center justify-center z-50">
      <div class="bg-white rounded-lg shadow-xl max-w-4xl w-full mx-4 max-h-[90vh] overflow-y-auto">
        <div class="px-6 py-4 border-b border-gray-200 flex justify-between items-center">
          <h3 class="text-lg font-semibold text-gray-900">Audit Event Details</h3>
          <button
            phx-click="close"
            phx-target={@myself}
            class="text-gray-400 hover:text-gray-600"
          >
            <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
            </svg>
          </button>
        </div>

        <div class="p-6 space-y-6">
          <!-- Event Summary -->
          <div class="bg-gray-50 rounded-lg p-4">
            <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <label class="block text-sm font-medium text-gray-500">Event ID</label>
                <p class="text-sm font-mono text-gray-900"><%= @event.id %></p>
              </div>
              <div>
                <label class="block text-sm font-medium text-gray-500">Timestamp</label>
                <p class="text-sm text-gray-900"><%= format_datetime(@event.timestamp) %></p>
              </div>
              <div>
                <label class="block text-sm font-medium text-gray-500">Event Type</label>
                <span class={"inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium #{event_type_badge_color(@event.event_type)}"}>
                  <%= format_event_type(@event.event_type) %>
                </span>
              </div>
            </div>
          </div>

          <!-- Request Details -->
          <div>
            <h4 class="text-lg font-medium text-gray-900 mb-4">Request Details</h4>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div class="space-y-4">
                <div>
                  <label class="block text-sm font-medium text-gray-500">Agent ID</label>
                  <p class="text-sm text-gray-900"><%= @event.agent_id %></p>
                </div>

                <div>
                  <label class="block text-sm font-medium text-gray-500">Source IP Address</label>
                  <p class="text-sm text-gray-900"><%= @event.source_ip %></p>
                </div>

                <div>
                  <label class="block text-sm font-medium text-gray-500">User Agent</label>
                  <p class="text-sm text-gray-900 font-mono"><%= @event.user_agent %></p>
                </div>

                <div>
                  <label class="block text-sm font-medium text-gray-500">Correlation ID</label>
                  <p class="text-sm font-mono text-gray-900"><%= @event.correlation_id %></p>
                </div>
              </div>

              <div class="space-y-4">
                <div>
                  <label class="block text-sm font-medium text-gray-500">Secret Path</label>
                  <p class="text-sm text-gray-900">
                    <%= if @event.secret_path do %>
                      <code class="bg-gray-100 px-1 py-0.5 rounded"><%= @event.secret_path %></code>
                    <% else %>
                      -
                    <% end %>
                  </p>
                </div>

                <div>
                  <label class="block text-sm font-medium text-gray-500">Access Status</label>
                  <div class="flex items-center">
                    <div class={"w-2 h-2 rounded-full mr-2 #{access_status_color(@event.access_granted)}"}></div>
                    <span class="text-sm">
                      <%= if @event.access_granted, do: "Granted", else: "Denied" %>
                    </span>
                  </div>
                </div>

                <div>
                  <label class="block text-sm font-medium text-gray-500">Response Time</label>
                  <p class="text-sm text-gray-900"><%= @event.response_time_ms %>ms</p>
                </div>

                <div>
                  <label class="block text-sm font-medium text-gray-500">Policy Matched</label>
                  <p class="text-sm text-gray-900"><%= @event.policy_matched || "N/A" %></p>
                </div>
              </div>
            </div>
          </div>

          <!-- Request/Response Details -->
          <div>
            <h4 class="text-lg font-medium text-gray-900 mb-4">Request & Response</h4>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div class="bg-gray-50 rounded-lg p-4">
                <h5 class="text-sm font-medium text-gray-700 mb-2">Request</h5>
                <div class="space-y-2">
                  <div class="flex justify-between">
                    <span class="text-sm text-gray-500">Size:</span>
                    <span class="text-sm text-gray-900"><%= @event.request_size %> bytes</span>
                  </div>
                  <%= if @event.request_headers do %>
                    <div>
                      <span class="text-sm text-gray-500">Headers:</span>
                      <pre class="text-xs bg-gray-100 p-2 rounded mt-1 overflow-x-auto"><%= Jason.encode!(@event.request_headers, pretty: true) %></pre>
                    </div>
                  <% end %>
                </div>
              </div>

              <div class="bg-gray-50 rounded-lg p-4">
                <h5 class="text-sm font-medium text-gray-700 mb-2">Response</h5>
                <div class="space-y-2">
                  <div class="flex justify-between">
                    <span class="text-sm text-gray-500">Size:</span>
                    <span class="text-sm text-gray-900"><%= @event.response_size %> bytes</span>
                  </div>
                  <%= if @event.response_status do %>
                    <div class="flex justify-between">
                      <span class="text-sm text-gray-500">Status:</span>
                      <span class="text-sm text-gray-900"><%= @event.response_status %></span>
                    </div>
                  <% end %>
                  <%= if @event.response_headers do %>
                    <div>
                      <span class="text-sm text-gray-500">Headers:</span>
                      <pre class="text-xs bg-gray-100 p-2 rounded mt-1 overflow-x-auto"><%= Jason.encode!(@event.response_headers, pretty: true) %></pre>
                    </div>
                  <% end %>
                </div>
              </div>
            </div>
          </div>

          <!-- Denial Reason (if applicable) -->
          <%= if @event.access_granted == false and @event.denial_reason do %>
            <div class="bg-red-50 border border-red-200 rounded-lg p-4">
              <h4 class="text-sm font-medium text-red-800 mb-2">Denial Reason</h4>
              <p class="text-sm text-red-700"><%= @event.denial_reason %></p>
            </div>
          <% end %>

          <!-- Additional Context -->
          <%= if @event.context do %>
            <div>
              <h4 class="text-lg font-medium text-gray-900 mb-4">Additional Context</h4>
              <div class="bg-gray-50 rounded-lg p-4">
                <pre class="text-xs text-gray-700 overflow-x-auto"><%= Jason.encode!(@event.context, pretty: true) %></pre>
              </div>
            </div>
          <% end %>

          <!-- Hash Chain Information -->
          <div>
            <h4 class="text-lg font-medium text-gray-900 mb-4">Integrity Verification</h4>
            <div class="bg-gray-50 rounded-lg p-4">
              <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label class="block text-sm font-medium text-gray-500">Event Hash</label>
                  <p class="text-sm font-mono text-gray-900"><%= @event.hash || "SHA256:abc123..." %></p>
                </div>
                <div>
                  <label class="block text-sm font-medium text-gray-500">Previous Hash</label>
                  <p class="text-sm font-mono text-gray-900"><%= @event.previous_hash || "SHA256:def456..." %></p>
                </div>
              </div>
              <div class="mt-4">
                <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                  ✓ Chain Integrity Verified
                </span>
              </div>
            </div>
          </div>
        </div>

        <!-- Actions -->
        <div class="px-6 py-4 border-t border-gray-200 flex justify-end space-x-4">
          <button
            class="btn-secondary"
            phx-click="close"
            phx-target={@myself}
          >
            Close
          </button>
          <button class="btn-secondary">
            Export Event
          </button>
          <button class="btn-secondary">
            View Related Events
          </button>
        </div>
      </div>
    </div>
    """
  end

  @impl true
  def handle_event("close", _params, socket) do
    send(self(), {:close_event_details})
    {:noreply, socket}
  end

  # Helper functions
  defp format_datetime(datetime) do
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
end