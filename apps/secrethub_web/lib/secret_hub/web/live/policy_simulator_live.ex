defmodule SecretHub.Web.PolicySimulatorLive do
  @moduledoc """
  Interactive policy testing and simulation interface.

  Features:
  - Step-by-step policy evaluation
  - Color-coded results (pass/fail)
  - Custom timestamp simulation
  - Detailed failure explanations
  """

  use SecretHub.Web, :live_view
  require Logger

  alias SecretHub.Core.{Policies, PolicyEvaluator}

  @impl true
  def mount(%{"id" => policy_id}, _session, socket) do
    case Policies.get_policy(policy_id) do
      {:ok, policy} ->
        socket =
          socket
          |> assign(:policy, policy)
          |> assign(:entity_id, "")
          |> assign(:secret_path, "")
          |> assign(:operation, "read")
          |> assign(:ip_address, "")
          |> assign(:requested_ttl, "")
          |> assign(:use_custom_timestamp, false)
          |> assign(:custom_timestamp, "")
          |> assign(:simulation_result, nil)
          |> assign(:page_title, "Simulate Policy: #{policy.name}")

        {:ok, socket}

      {:error, _reason} ->
        socket =
          socket
          |> put_flash(:error, "Policy not found")
          |> redirect(to: "/admin/policies")

        {:ok, socket}
    end
  end

  @impl true
  def handle_event("update_field", %{"field" => field, "value" => value}, socket) do
    socket = assign(socket, String.to_atom(field), value)
    {:noreply, socket}
  end

  @impl true
  def handle_event("toggle_custom_timestamp", _params, socket) do
    socket = assign(socket, :use_custom_timestamp, !socket.assigns.use_custom_timestamp)
    {:noreply, socket}
  end

  @impl true
  def handle_event("run_simulation", _params, socket) do
    context = build_simulation_context(socket.assigns)

    result = PolicyEvaluator.simulate(socket.assigns.policy, context)

    socket = assign(socket, :simulation_result, result)
    {:noreply, socket}
  end

  @impl true
  def handle_event("clear_results", _params, socket) do
    socket = assign(socket, :simulation_result, nil)
    {:noreply, socket}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div class="mb-8">
        <div class="flex items-center justify-between">
          <div>
            <h1 class="text-3xl font-bold text-on-surface">Policy Simulator</h1>
            <p class="mt-2 text-sm text-on-surface-variant">
              Test policy: <span class="font-semibold">{@policy.name}</span>
            </p>
          </div>
          <.link
            navigate="/admin/policies"
            class="inline-flex items-center px-4 py-2 border border-outline-variant shadow-sm text-sm font-medium rounded-md text-on-surface bg-surface-container hover:bg-surface-container-low"
          >
            Back to Policies
          </.link>
        </div>
      </div>

      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <!-- Input Form -->
        <div class="bg-surface-container shadow rounded-lg p-6">
          <h2 class="text-lg font-medium text-on-surface mb-4">Simulation Context</h2>

          <form phx-submit="run_simulation" class="space-y-4">
            <div>
              <label class="block text-sm font-medium text-on-surface">
                Entity ID <span class="text-error">*</span>
              </label>
              <input
                type="text"
                phx-change="update_field"
                phx-value-field="entity_id"
                value={@entity_id}
                class="mt-1 block w-full border border-outline-variant rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-primary focus:border-primary sm:text-sm"
                placeholder="agent-001"
                required
              />
              <p class="mt-1 text-xs text-on-surface-variant">The entity requesting access</p>
            </div>

            <div>
              <label class="block text-sm font-medium text-on-surface">
                Secret Path <span class="text-error">*</span>
              </label>
              <input
                type="text"
                phx-change="update_field"
                phx-value-field="secret_path"
                value={@secret_path}
                class="mt-1 block w-full border border-outline-variant rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-primary focus:border-primary sm:text-sm"
                placeholder="prod.db.postgres"
                required
              />
              <p class="mt-1 text-xs text-on-surface-variant">Path of the secret being accessed</p>
            </div>

            <div>
              <label class="block text-sm font-medium text-on-surface">
                Operation <span class="text-error">*</span>
              </label>
              <select
                phx-change="update_field"
                phx-value-field="operation"
                value={@operation}
                class="mt-1 block w-full border border-outline-variant rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-primary focus:border-primary sm:text-sm"
              >
                <option value="read">Read</option>
                <option value="write">Write</option>
                <option value="delete">Delete</option>
                <option value="rotate">Rotate</option>
                <option value="renew">Renew</option>
              </select>
            </div>

            <div>
              <label class="block text-sm font-medium text-on-surface">IP Address (optional)</label>
              <input
                type="text"
                phx-change="update_field"
                phx-value-field="ip_address"
                value={@ip_address}
                class="mt-1 block w-full border border-outline-variant rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-primary focus:border-primary sm:text-sm"
                placeholder="192.168.1.100"
              />
              <p class="mt-1 text-xs text-on-surface-variant">For IP-based restrictions</p>
            </div>

            <div>
              <label class="block text-sm font-medium text-on-surface">
                Requested TTL (seconds, optional)
              </label>
              <input
                type="number"
                phx-change="update_field"
                phx-value-field="requested_ttl"
                value={@requested_ttl}
                class="mt-1 block w-full border border-outline-variant rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-primary focus:border-primary sm:text-sm"
                placeholder="3600"
              />
              <p class="mt-1 text-xs text-on-surface-variant">For TTL-based restrictions</p>
            </div>

            <div>
              <div class="flex items-center mb-2">
                <input
                  type="checkbox"
                  id="use_custom_timestamp"
                  phx-click="toggle_custom_timestamp"
                  checked={@use_custom_timestamp}
                  class="h-4 w-4 text-primary focus:ring-primary border-outline-variant rounded"
                />
                <label for="use_custom_timestamp" class="ml-2 block text-sm text-on-surface">
                  Use custom timestamp
                </label>
              </div>

              <%= if @use_custom_timestamp do %>
                <input
                  type="datetime-local"
                  phx-change="update_field"
                  phx-value-field="custom_timestamp"
                  value={@custom_timestamp}
                  class="mt-1 block w-full border border-outline-variant rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-primary focus:border-primary sm:text-sm"
                />
                <p class="mt-1 text-xs text-on-surface-variant">For testing time-based restrictions</p>
              <% end %>
            </div>

            <div class="pt-4 flex gap-3">
              <button
                type="submit"
                class="flex-1 inline-flex justify-center items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-on-primary bg-primary hover:bg-primary focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary"
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
                    d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"
                  />
                  <path
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    stroke-width="2"
                    d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
                  />
                </svg>
                Run Simulation
              </button>
              <%= if @simulation_result do %>
                <button
                  type="button"
                  phx-click="clear_results"
                  class="inline-flex items-center px-4 py-2 border border-outline-variant shadow-sm text-sm font-medium rounded-md text-on-surface bg-surface-container hover:bg-surface-container-low"
                >
                  Clear
                </button>
              <% end %>
            </div>
          </form>
        </div>
        <!-- Results Panel -->
        <div class="bg-surface-container shadow rounded-lg p-6">
          <h2 class="text-lg font-medium text-on-surface mb-4">Simulation Results</h2>

          <%= if @simulation_result do %>
            <!-- Final Result -->
            <div class={"mb-6 p-4 rounded-lg border-2 #{if @simulation_result.result == :allow, do: "bg-success/5 border-green-500", else: "bg-error/5 border-red-500"}"}>
              <div class="flex items-start">
                <div class="flex-shrink-0">
                  <%= if @simulation_result.result == :allow do %>
                    <svg
                      class="h-8 w-8 text-success"
                      xmlns="http://www.w3.org/2000/svg"
                      fill="none"
                      viewBox="0 0 24 24"
                      stroke="currentColor"
                    >
                      <path
                        stroke-linecap="round"
                        stroke-linejoin="round"
                        stroke-width="2"
                        d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
                      />
                    </svg>
                  <% else %>
                    <svg
                      class="h-8 w-8 text-error"
                      xmlns="http://www.w3.org/2000/svg"
                      fill="none"
                      viewBox="0 0 24 24"
                      stroke="currentColor"
                    >
                      <path
                        stroke-linecap="round"
                        stroke-linejoin="round"
                        stroke-width="2"
                        d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z"
                      />
                    </svg>
                  <% end %>
                </div>
                <div class="ml-3">
                  <h3 class={"text-lg font-medium #{if @simulation_result.result == :allow, do: "text-success", else: "text-error"}"}>
                    {if @simulation_result.result == :allow,
                      do: "ACCESS ALLOWED",
                      else: "ACCESS DENIED"}
                  </h3>
                  <p class={"mt-1 text-sm #{if @simulation_result.result == :allow, do: "text-success", else: "text-error"}"}>
                    {@simulation_result.reason}
                  </p>
                  <p class="mt-2 text-xs text-on-surface-variant">
                    Policy: {@simulation_result.policy_name}
                  </p>
                </div>
              </div>
            </div>
            <!-- Step-by-Step Evaluation -->
            <div>
              <h3 class="text-sm font-medium text-on-surface mb-3">Evaluation Steps</h3>
              <div class="space-y-2">
                <%= for step <- @simulation_result.steps do %>
                  <div class={"flex items-start p-3 rounded-md #{if step.result == :pass, do: "bg-success/5", else: "bg-error/5"}"}>
                    <div class="flex-shrink-0 mt-0.5">
                      <%= if step.result == :pass do %>
                        <svg
                          class="h-5 w-5 text-success"
                          xmlns="http://www.w3.org/2000/svg"
                          viewBox="0 0 20 20"
                          fill="currentColor"
                        >
                          <path
                            fill-rule="evenodd"
                            d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z"
                            clip-rule="evenodd"
                          />
                        </svg>
                      <% else %>
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
                      <% end %>
                    </div>
                    <div class="ml-3 flex-1">
                      <p class={"text-sm font-medium #{if step.result == :pass, do: "text-success", else: "text-error"}"}>
                        {step.step}
                      </p>
                      <p class={"text-xs mt-1 #{if step.result == :pass, do: "text-success", else: "text-error"}"}>
                        {step.message}
                      </p>
                    </div>
                  </div>
                <% end %>
              </div>
            </div>

            <div class="mt-6 pt-6 border-t border-outline-variant">
              <h3 class="text-sm font-medium text-on-surface mb-2">Policy Document</h3>
              <div class="bg-surface-container-low rounded-md p-3 overflow-x-auto">
                <pre class="text-xs text-on-surface">{Jason.encode!(@policy.policy_document, pretty: true)}</pre>
              </div>
            </div>
          <% else %>
            <div class="text-center py-12">
              <svg
                class="mx-auto h-12 w-12 text-on-surface-variant"
                xmlns="http://www.w3.org/2000/svg"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width="2"
                  d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"
                />
              </svg>
              <p class="mt-4 text-sm text-on-surface-variant">
                Fill in the simulation context and click "Run Simulation" to test the policy
              </p>
            </div>
          <% end %>
        </div>
      </div>
    </div>
    """
  end

  # Private functions

  defp build_simulation_context(assigns) do
    context = %{
      entity_id: assigns.entity_id,
      secret_path: assigns.secret_path,
      operation: assigns.operation
    }

    context =
      if assigns.ip_address != "" do
        Map.put(context, :ip_address, assigns.ip_address)
      else
        context
      end

    context =
      if assigns.requested_ttl != "" do
        case Integer.parse(assigns.requested_ttl) do
          {ttl, ""} -> Map.put(context, :requested_ttl, ttl)
          _ -> context
        end
      else
        context
      end

    context =
      if assigns.use_custom_timestamp && assigns.custom_timestamp != "" do
        case parse_custom_timestamp(assigns.custom_timestamp) do
          {:ok, timestamp} -> Map.put(context, :timestamp, timestamp)
          _ -> context
        end
      else
        context
      end

    context
  end

  defp parse_custom_timestamp(timestamp_str) do
    # Parse datetime-local format (YYYY-MM-DDTHH:MM)
    case NaiveDateTime.from_iso8601(timestamp_str <> ":00") do
      {:ok, naive_dt} -> {:ok, DateTime.from_naive!(naive_dt, "Etc/UTC")}
      {:error, _} -> {:error, :invalid_timestamp}
    end
  end
end
