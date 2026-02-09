defmodule SecretHub.Web.DeploymentStatusLive do
  @moduledoc """
  LiveView for monitoring Kubernetes deployment status.

  Displays:
  - Deployment overview (replicas, strategy, status)
  - Pod list with health status and metrics
  - Resource usage (CPU, memory per pod)
  - Scaling controls
  - Recent Kubernetes events
  - Real-time updates
  """

  use SecretHub.Web, :live_view
  require Logger
  alias SecretHub.Core.K8s

  @refresh_interval 10_000

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      schedule_refresh()
    end

    socket =
      socket
      |> assign(:loading, true)
      |> assign(:auto_refresh, true)
      |> assign(:scale_replicas, nil)
      |> load_data()

    {:ok, socket}
  end

  @impl true
  def handle_info(:refresh, socket) do
    if socket.assigns.auto_refresh do
      schedule_refresh()
    end

    {:noreply, load_data(socket)}
  end

  @impl true
  def handle_event("toggle_refresh", _params, socket) do
    new_auto_refresh = !socket.assigns.auto_refresh

    if new_auto_refresh do
      schedule_refresh()
    end

    {:noreply, assign(socket, :auto_refresh, new_auto_refresh)}
  end

  @impl true
  def handle_event("refresh_now", _params, socket) do
    {:noreply, load_data(socket)}
  end

  @impl true
  def handle_event("show_scale_dialog", _params, socket) do
    current_replicas =
      case socket.assigns.deployment do
        %{replicas: %{desired: desired}} -> desired
        _ -> 3
      end

    {:noreply, assign(socket, :scale_replicas, current_replicas)}
  end

  @impl true
  def handle_event("cancel_scale", _params, socket) do
    {:noreply, assign(socket, :scale_replicas, nil)}
  end

  @impl true
  def handle_event("scale_deployment", %{"replicas" => replicas_str}, socket) do
    case Integer.parse(replicas_str) do
      {replicas, ""} when replicas >= 1 and replicas <= 10 ->
        case K8s.scale_deployment(replicas) do
          :ok ->
            socket =
              socket
              |> put_flash(:info, "Scaling deployment to #{replicas} replicas")
              |> assign(:scale_replicas, nil)
              |> load_data()

            {:noreply, socket}

          {:error, reason} ->
            {:noreply, put_flash(socket, :error, "Failed to scale deployment: #{reason}")}
        end

      _ ->
        {:noreply, put_flash(socket, :error, "Invalid replica count")}
    end
  end

  # Private helpers

  defp schedule_refresh do
    Process.send_after(self(), :refresh, @refresh_interval)
  end

  defp load_data(socket) do
    # Get deployment status
    deployment =
      case K8s.get_deployment_status() do
        {:ok, deployment} -> deployment
        {:error, _} -> nil
      end

    # Get pods
    pods =
      case K8s.list_pods() do
        {:ok, pods} -> pods
        {:error, _} -> []
      end

    # Get metrics
    metrics =
      case K8s.get_pod_metrics() do
        {:ok, metrics} -> metrics
        {:error, _} -> []
      end

    # Get events
    events =
      case K8s.get_events() do
        {:ok, events} -> Enum.take(events, 10)
        {:error, _} -> []
      end

    # Check if in cluster
    in_cluster = K8s.in_cluster?()

    socket
    |> assign(:loading, false)
    |> assign(:deployment, deployment)
    |> assign(:pods, pods)
    |> assign(:metrics, metrics)
    |> assign(:events, events)
    |> assign(:in_cluster, in_cluster)
    |> assign(:error, nil)
  rescue
    e ->
      Logger.error("Failed to load deployment data: #{Exception.message(e)}")

      socket
      |> assign(:loading, false)
      |> assign(:error, "Failed to load deployment data")
  end

  defp pod_status_badge(status) do
    case status do
      "Running" -> {"bg-green-100 text-green-800", "Running"}
      "Pending" -> {"bg-yellow-100 text-yellow-800", "Pending"}
      "Failed" -> {"bg-red-100 text-red-800", "Failed"}
      "Succeeded" -> {"bg-blue-100 text-blue-800", "Succeeded"}
      "Unknown" -> {"bg-gray-100 text-gray-800", "Unknown"}
      _ -> {"bg-gray-100 text-gray-800", status}
    end
  end

  defp event_type_badge(type) do
    case type do
      "Normal" -> {"bg-blue-100 text-blue-800", "Normal"}
      "Warning" -> {"bg-yellow-100 text-yellow-800", "Warning"}
      "Error" -> {"bg-red-100 text-red-800", "Error"}
      _ -> {"bg-gray-100 text-gray-800", type}
    end
  end

  defp format_age(seconds) when is_integer(seconds) do
    cond do
      seconds < 60 -> "#{seconds}s"
      seconds < 3600 -> "#{div(seconds, 60)}m"
      seconds < 86400 -> "#{div(seconds, 3600)}h"
      true -> "#{div(seconds, 86400)}d"
    end
  end

  defp format_age(_), do: "N/A"

  defp format_timestamp(nil), do: "Never"

  defp format_timestamp(timestamp) do
    diff = DateTime.diff(DateTime.utc_now() |> DateTime.truncate(:second), timestamp, :second)

    cond do
      diff < 60 -> "#{diff}s ago"
      diff < 3600 -> "#{div(diff, 60)}m ago"
      diff < 86400 -> "#{div(diff, 3600)}h ago"
      true -> "#{div(diff, 86400)}d ago"
    end
  end

  defp get_pod_metrics(metrics, pod_name) do
    Enum.find(metrics, fn m -> m.pod_name == pod_name end)
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="container mx-auto p-6">
      <div class="flex justify-between items-center mb-6">
        <div>
          <h1 class="text-3xl font-bold">Deployment Status</h1>
          <p class="text-gray-600 mt-1">Monitor Kubernetes deployment and pod health</p>
        </div>

        <div class="flex gap-2">
          <.link navigate={~p"/admin/cluster"} class="btn btn-outline">
            <svg
              xmlns="http://www.w3.org/2000/svg"
              class="h-5 w-5"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path
                stroke-linecap="round"
                stroke-linejoin="round"
                stroke-width="2"
                d="M10 19l-7-7m0 0l7-7m-7 7h18"
              />
            </svg>
            Back to Cluster
          </.link>

          <button
            phx-click="toggle_refresh"
            class={"btn btn-outline #{if @auto_refresh, do: "btn-active", else: ""}"}
          >
            {if @auto_refresh, do: "Auto-refresh ON", else: "Auto-refresh OFF"}
          </button>

          <button phx-click="refresh_now" class="btn btn-primary">
            Refresh Now
          </button>
        </div>
      </div>

      <%= if @error do %>
        <div class="alert alert-error mb-6">
          <svg
            xmlns="http://www.w3.org/2000/svg"
            class="stroke-current shrink-0 h-6 w-6"
            fill="none"
            viewBox="0 0 24 24"
          >
            <path
              stroke-linecap="round"
              stroke-linejoin="round"
              stroke-width="2"
              d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z"
            />
          </svg>
          <span>{@error}</span>
        </div>
      <% end %>

      <%= if not @in_cluster do %>
        <div class="alert alert-warning mb-6">
          <svg
            xmlns="http://www.w3.org/2000/svg"
            class="stroke-current shrink-0 h-6 w-6"
            fill="none"
            viewBox="0 0 24 24"
          >
            <path
              stroke-linecap="round"
              stroke-linejoin="round"
              stroke-width="2"
              d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
            />
          </svg>
          <span>
            Not running in Kubernetes cluster. Displaying placeholder data for development.
          </span>
        </div>
      <% end %>
      
    <!-- Deployment Overview -->
      <%= if @deployment do %>
        <div class="card bg-base-100 shadow-xl mb-6">
          <div class="card-body">
            <h2 class="card-title">Deployment Overview</h2>

            <div class="grid grid-cols-1 md:grid-cols-5 gap-4 mt-4">
              <div class="stat bg-base-200 rounded-lg">
                <div class="stat-title">Desired</div>
                <div class="stat-value text-2xl">{@deployment.replicas.desired}</div>
                <div class="stat-desc">Replicas</div>
              </div>

              <div class="stat bg-base-200 rounded-lg">
                <div class="stat-title">Available</div>
                <div class="stat-value text-2xl text-green-600">
                  {@deployment.replicas.available}
                </div>
                <div class="stat-desc">Ready to serve</div>
              </div>

              <div class="stat bg-base-200 rounded-lg">
                <div class="stat-title">Ready</div>
                <div class="stat-value text-2xl text-blue-600">{@deployment.replicas.ready}</div>
                <div class="stat-desc">Passing health checks</div>
              </div>

              <div class="stat bg-base-200 rounded-lg">
                <div class="stat-title">Updated</div>
                <div class="stat-value text-2xl">{@deployment.replicas.updated}</div>
                <div class="stat-desc">Latest version</div>
              </div>

              <div class="stat bg-base-200 rounded-lg">
                <div class="stat-title">Strategy</div>
                <div class="stat-value text-lg">{@deployment.strategy}</div>
                <div class="stat-desc">{@deployment.max_surge} surge</div>
              </div>
            </div>

            <div class="card-actions justify-end mt-4">
              <button phx-click="show_scale_dialog" class="btn btn-primary">
                Scale Deployment
              </button>
            </div>
          </div>
        </div>
      <% end %>
      
    <!-- Pods Table -->
      <div class="card bg-base-100 shadow-xl mb-6">
        <div class="card-body">
          <h2 class="card-title">Pods</h2>

          <%= if Enum.any?(@pods) do %>
            <div class="overflow-x-auto mt-4">
              <table class="table table-zebra">
                <thead>
                  <tr>
                    <th>Pod Name</th>
                    <th>Status</th>
                    <th>Ready</th>
                    <th>Restarts</th>
                    <th>Age</th>
                    <th>Node</th>
                    <th>CPU</th>
                    <th>Memory</th>
                  </tr>
                </thead>
                <tbody>
                  <%= for pod <- @pods do %>
                    <% pod_metrics = get_pod_metrics(@metrics, pod.name) %>
                    <tr>
                      <td class="font-mono text-sm">{pod.name}</td>
                      <td>
                        <span class={
                          "px-2 py-1 text-xs font-semibold rounded-full #{elem(pod_status_badge(pod.status), 0)}"
                        }>
                          {elem(pod_status_badge(pod.status), 1)}
                        </span>
                      </td>
                      <td>{pod.ready}</td>
                      <td>
                        <%= if pod.restarts > 0 do %>
                          <span class="badge badge-warning">{pod.restarts}</span>
                        <% else %>
                          <span class="badge badge-ghost">{pod.restarts}</span>
                        <% end %>
                      </td>
                      <td>{format_age(pod.age_seconds)}</td>
                      <td class="text-sm">{pod.node}</td>
                      <td>
                        <%= if pod_metrics do %>
                          <div class="text-sm">
                            <div>{pod_metrics.cpu_usage}</div>
                            <div class="text-xs text-gray-500">
                              {Float.round(pod_metrics.cpu_percent, 1)}%
                            </div>
                          </div>
                        <% else %>
                          <span class="text-gray-400">N/A</span>
                        <% end %>
                      </td>
                      <td>
                        <%= if pod_metrics do %>
                          <div class="text-sm">
                            <div>{pod_metrics.memory_usage}</div>
                            <div class="text-xs text-gray-500">
                              {Float.round(pod_metrics.memory_percent, 1)}%
                            </div>
                          </div>
                        <% else %>
                          <span class="text-gray-400">N/A</span>
                        <% end %>
                      </td>
                    </tr>
                  <% end %>
                </tbody>
              </table>
            </div>
          <% else %>
            <div class="alert alert-info">
              <svg
                xmlns="http://www.w3.org/2000/svg"
                fill="none"
                viewBox="0 0 24 24"
                class="stroke-current shrink-0 w-6 h-6"
              >
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width="2"
                  d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
                />
              </svg>
              <span>No pods found</span>
            </div>
          <% end %>
        </div>
      </div>
      
    <!-- Recent Events -->
      <div class="card bg-base-100 shadow-xl">
        <div class="card-body">
          <h2 class="card-title">Recent Events</h2>

          <%= if Enum.any?(@events) do %>
            <div class="overflow-x-auto mt-4">
              <table class="table table-sm">
                <thead>
                  <tr>
                    <th>Type</th>
                    <th>Reason</th>
                    <th>Message</th>
                    <th>Count</th>
                    <th>Age</th>
                  </tr>
                </thead>
                <tbody>
                  <%= for event <- @events do %>
                    <tr>
                      <td>
                        <span class={
                          "px-2 py-1 text-xs font-semibold rounded-full #{elem(event_type_badge(event.type), 0)}"
                        }>
                          {elem(event_type_badge(event.type), 1)}
                        </span>
                      </td>
                      <td class="font-medium">{event.reason}</td>
                      <td class="text-sm">{event.message}</td>
                      <td>{event.count}</td>
                      <td>{format_timestamp(event.timestamp)}</td>
                    </tr>
                  <% end %>
                </tbody>
              </table>
            </div>
          <% else %>
            <div class="alert alert-info">
              <svg
                xmlns="http://www.w3.org/2000/svg"
                fill="none"
                viewBox="0 0 24 24"
                class="stroke-current shrink-0 w-6 h-6"
              >
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width="2"
                  d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
                />
              </svg>
              <span>No recent events</span>
            </div>
          <% end %>
        </div>
      </div>
      
    <!-- Scale Dialog Modal -->
      <%= if @scale_replicas do %>
        <div class="modal modal-open">
          <div class="modal-box">
            <h3 class="font-bold text-lg">Scale Deployment</h3>
            <p class="py-4">
              Enter the desired number of replicas for the SecretHub Core deployment.
            </p>

            <form phx-submit="scale_deployment">
              <div class="form-control">
                <label class="label">
                  <span class="label-text">Number of Replicas</span>
                </label>
                <input
                  type="number"
                  name="replicas"
                  value={@scale_replicas}
                  min="1"
                  max="10"
                  class="input input-bordered"
                  required
                />
                <label class="label">
                  <span class="label-text-alt">Must be between 1 and 10</span>
                </label>
              </div>

              <div class="modal-action">
                <button type="button" phx-click="cancel_scale" class="btn">Cancel</button>
                <button type="submit" class="btn btn-primary">Scale</button>
              </div>
            </form>
          </div>
        </div>
      <% end %>
    </div>
    """
  end
end
