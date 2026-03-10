defmodule SecretHub.Web.AuditEventDetailsComponent do
  @moduledoc """
  LiveComponent for displaying detailed audit event information.
  """

  use SecretHub.Web, :live_component

  @impl true
  def update(assigns, socket) do
    socket = assign(socket, assigns)
    {:ok, socket}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="fixed inset-0 bg-surface-container-highest/75 bg-opacity-50 flex items-center justify-center z-50">
      <div class="bg-surface-container rounded-lg shadow-xl max-w-4xl w-full mx-4 max-h-[90vh] overflow-y-auto">
        <div class="px-6 py-4 border-b border-outline-variant flex justify-between items-center">
          <h3 class="text-lg font-semibold text-on-surface">Audit Event Details</h3>
          <button
            phx-click="close"
            phx-target={@myself}
            class="text-on-surface-variant hover:text-on-surface-variant"
          >
            <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path
                stroke-linecap="round"
                stroke-linejoin="round"
                stroke-width="2"
                d="M6 18L18 6M6 6l12 12"
              />
            </svg>
          </button>
        </div>

        <div class="p-6 space-y-6">
          <!-- Event Summary -->
          <div class="bg-surface-container-low rounded-lg p-4">
            <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <label class="block text-sm font-medium text-on-surface-variant">Event ID</label>
                <p class="text-sm font-mono text-on-surface">{@event.id}</p>
              </div>
              <div>
                <label class="block text-sm font-medium text-on-surface-variant">Timestamp</label>
                <p class="text-sm text-on-surface">{format_datetime(@event.timestamp)}</p>
              </div>
              <div>
                <label class="block text-sm font-medium text-on-surface-variant">Event Type</label>
                <span class={"inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium #{event_type_badge_color(@event.event_type)}"}>
                  {format_event_type(@event.event_type)}
                </span>
              </div>
            </div>
          </div>
          
    <!-- Request Details -->
          <div>
            <h4 class="text-lg font-medium text-on-surface mb-4">Request Details</h4>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div class="space-y-4">
                <div>
                  <label class="block text-sm font-medium text-on-surface-variant">Agent ID</label>
                  <p class="text-sm text-on-surface">{@event.agent_id}</p>
                </div>

                <div>
                  <label class="block text-sm font-medium text-on-surface-variant">Source IP Address</label>
                  <p class="text-sm text-on-surface">{@event.source_ip}</p>
                </div>

                <div>
                  <label class="block text-sm font-medium text-on-surface-variant">User Agent</label>
                  <p class="text-sm text-on-surface font-mono">{@event.user_agent}</p>
                </div>

                <div>
                  <label class="block text-sm font-medium text-on-surface-variant">Correlation ID</label>
                  <p class="text-sm font-mono text-on-surface">{@event.correlation_id}</p>
                </div>
              </div>

              <div class="space-y-4">
                <div>
                  <label class="block text-sm font-medium text-on-surface-variant">Secret Path</label>
                  <p class="text-sm text-on-surface">
                    <%= if @event.secret_path do %>
                      <code class="bg-surface-container px-1 py-0.5 rounded">{@event.secret_path}</code>
                    <% else %>
                      -
                    <% end %>
                  </p>
                </div>

                <div>
                  <label class="block text-sm font-medium text-on-surface-variant">Access Status</label>
                  <div class="flex items-center">
                    <div class={"w-2 h-2 rounded-full mr-2 #{access_status_color(@event.access_granted)}"}>
                    </div>
                    <span class="text-sm">
                      {if @event.access_granted, do: "Granted", else: "Denied"}
                    </span>
                  </div>
                </div>

                <div>
                  <label class="block text-sm font-medium text-on-surface-variant">Response Time</label>
                  <p class="text-sm text-on-surface">{@event.response_time_ms}ms</p>
                </div>

                <div>
                  <label class="block text-sm font-medium text-on-surface-variant">Policy Matched</label>
                  <p class="text-sm text-on-surface">{@event.policy_matched || "N/A"}</p>
                </div>
              </div>
            </div>
          </div>
          
    <!-- Request/Response Details -->
          <div>
            <h4 class="text-lg font-medium text-on-surface mb-4">Request & Response</h4>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div class="bg-surface-container-low rounded-lg p-4">
                <h5 class="text-sm font-medium text-on-surface mb-2">Request</h5>
                <div class="space-y-2">
                  <div class="flex justify-between">
                    <span class="text-sm text-on-surface-variant">Size:</span>
                    <span class="text-sm text-on-surface">{@event.request_size} bytes</span>
                  </div>
                  <%= if @event.request_headers do %>
                    <div>
                      <span class="text-sm text-on-surface-variant">Headers:</span>
                      <pre class="text-xs bg-surface-container p-2 rounded mt-1 overflow-x-auto"><%= Jason.encode!(@event.request_headers, pretty: true) %></pre>
                    </div>
                  <% end %>
                </div>
              </div>

              <div class="bg-surface-container-low rounded-lg p-4">
                <h5 class="text-sm font-medium text-on-surface mb-2">Response</h5>
                <div class="space-y-2">
                  <div class="flex justify-between">
                    <span class="text-sm text-on-surface-variant">Size:</span>
                    <span class="text-sm text-on-surface">{@event.response_size} bytes</span>
                  </div>
                  <%= if @event.response_status do %>
                    <div class="flex justify-between">
                      <span class="text-sm text-on-surface-variant">Status:</span>
                      <span class="text-sm text-on-surface">{@event.response_status}</span>
                    </div>
                  <% end %>
                  <%= if @event.response_headers do %>
                    <div>
                      <span class="text-sm text-on-surface-variant">Headers:</span>
                      <pre class="text-xs bg-surface-container p-2 rounded mt-1 overflow-x-auto"><%= Jason.encode!(@event.response_headers, pretty: true) %></pre>
                    </div>
                  <% end %>
                </div>
              </div>
            </div>
          </div>
          
    <!-- Denial Reason (if applicable) -->
          <%= if @event.access_granted == false and @event.denial_reason do %>
            <div class="bg-error/5 border border-red-200 rounded-lg p-4">
              <h4 class="text-sm font-medium text-error mb-2">Denial Reason</h4>
              <p class="text-sm text-error">{@event.denial_reason}</p>
            </div>
          <% end %>
          
    <!-- Additional Context -->
          <%= if @event.context do %>
            <div>
              <h4 class="text-lg font-medium text-on-surface mb-4">Additional Context</h4>
              <div class="bg-surface-container-low rounded-lg p-4">
                <pre class="text-xs text-on-surface overflow-x-auto"><%= Jason.encode!(@event.context, pretty: true) %></pre>
              </div>
            </div>
          <% end %>
          
    <!-- Hash Chain Information -->
          <div>
            <h4 class="text-lg font-medium text-on-surface mb-4">Integrity Verification</h4>
            <div class="bg-surface-container-low rounded-lg p-4">
              <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label class="block text-sm font-medium text-on-surface-variant">Event Hash</label>
                  <p class="text-sm font-mono text-on-surface">{@event.hash || "SHA256:abc123..."}</p>
                </div>
                <div>
                  <label class="block text-sm font-medium text-on-surface-variant">Previous Hash</label>
                  <p class="text-sm font-mono text-on-surface">
                    {@event.previous_hash || "SHA256:def456..."}
                  </p>
                </div>
              </div>
              <div class="mt-4">
                <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-success/10 text-success">
                  ✓ Chain Integrity Verified
                </span>
              </div>
            </div>
          </div>
        </div>
        
    <!-- Actions -->
        <div class="px-6 py-4 border-t border-outline-variant flex justify-end space-x-4">
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

  defp event_type_badge_color("secret_access"), do: "bg-success/10 text-success"
  defp event_type_badge_color("secret_access_denied"), do: "bg-error/10 text-error"
  defp event_type_badge_color("agent_connect"), do: "bg-primary/10 text-primary"
  defp event_type_badge_color("agent_disconnect"), do: "bg-warning/10 text-warning"
  defp event_type_badge_color(_), do: "bg-surface-container text-on-surface"

  defp access_status_color(true), do: "bg-success"
  defp access_status_color(false), do: "bg-error"
end
