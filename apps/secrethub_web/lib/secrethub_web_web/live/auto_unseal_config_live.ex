defmodule SecretHub.WebWeb.AutoUnsealConfigLive do
  @moduledoc """
  LiveView for managing auto-unseal configuration.

  Displays:
  - Current auto-unseal status and configuration
  - Unseal status across all cluster nodes
  - Enable/disable auto-unseal controls
  - KMS provider configuration details
  - Security information and best practices
  """

  use SecretHub.WebWeb, :live_view
  require Logger
  alias SecretHub.Core.{AutoUnseal, ClusterState}

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
  def handle_event("disable_auto_unseal", _params, socket) do
    case AutoUnseal.disable() do
      :ok ->
        socket =
          socket
          |> put_flash(:info, "Auto-unseal disabled successfully")
          |> load_data()

        {:noreply, socket}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to disable auto-unseal: #{inspect(reason)}")}
    end
  end

  @impl true
  def handle_event("trigger_unseal", _params, socket) do
    case AutoUnseal.trigger_unseal() do
      :ok ->
        socket =
          socket
          |> put_flash(:info, "Auto-unseal triggered successfully")
          |> load_data()

        {:noreply, socket}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to trigger auto-unseal: #{inspect(reason)}")}
    end
  end

  # Private helpers

  defp schedule_refresh do
    Process.send_after(self(), :refresh, @refresh_interval)
  end

  defp load_data(socket) do
    # Get auto-unseal status
    auto_unseal_status = AutoUnseal.status()

    # Get cluster info
    cluster_info =
      case ClusterState.cluster_info() do
        {:ok, info} -> info
        {:error, _} -> nil
      end

    socket
    |> assign(:loading, false)
    |> assign(:auto_unseal_status, auto_unseal_status)
    |> assign(:cluster_info, cluster_info)
    |> assign(:error, nil)
  rescue
    e ->
      Logger.error("Failed to load auto-unseal data: #{Exception.message(e)}")

      socket
      |> assign(:loading, false)
      |> assign(:error, "Failed to load auto-unseal data")
  end

  defp format_provider(provider) do
    case provider do
      :aws_kms -> "AWS KMS"
      :gcp_kms -> "Google Cloud KMS"
      :azure_kv -> "Azure Key Vault"
      :disabled -> "Disabled"
      _ -> to_string(provider)
    end
  end

  defp provider_badge(provider, assigns \\ %{}) do
    case provider do
      :aws_kms ->
        ~H"""
        <span class="badge badge-warning">AWS KMS</span>
        """

      :gcp_kms ->
        ~H"""
        <span class="badge badge-info">GCP KMS</span>
        """

      :azure_kv ->
        ~H"""
        <span class="badge badge-primary">Azure KV</span>
        """

      :disabled ->
        ~H"""
        <span class="badge badge-ghost">Disabled</span>
        """

      _ ->
        assigns = assign(assigns, :provider, provider)

        ~H"""
        <span class="badge badge-ghost">{to_string(@provider)}</span>
        """
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="container mx-auto p-6">
      <div class="flex justify-between items-center mb-6">
        <div>
          <h1 class="text-3xl font-bold">Auto-Unseal Configuration</h1>
          <p class="text-gray-600 mt-1">Manage automatic vault unsealing with cloud KMS providers</p>
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
      <!-- Auto-Unseal Status -->
      <div class="card bg-base-100 shadow-xl mb-6">
        <div class="card-body">
          <h2 class="card-title">Current Status</h2>

          <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mt-4">
            <div class="stat bg-base-200 rounded-lg">
              <div class="stat-title">Auto-Unseal</div>
              <div class="stat-value text-2xl">
                <%= if @auto_unseal_status.enabled do %>
                  <span class="badge badge-success badge-lg">Enabled</span>
                <% else %>
                  <span class="badge badge-ghost badge-lg">Disabled</span>
                <% end %>
              </div>
              <div class="stat-desc">Current configuration state</div>
            </div>

            <div class="stat bg-base-200 rounded-lg">
              <div class="stat-title">KMS Provider</div>
              <div class="stat-value text-2xl">
                {provider_badge(@auto_unseal_status.provider)}
              </div>
              <div class="stat-desc">{format_provider(@auto_unseal_status.provider)}</div>
            </div>

            <div class="stat bg-base-200 rounded-lg">
              <div class="stat-title">Configuration</div>
              <div class="stat-value text-2xl">
                <%= if @auto_unseal_status.configured do %>
                  <span class="badge badge-success badge-lg">Valid</span>
                <% else %>
                  <span class="badge badge-warning badge-lg">Not Configured</span>
                <% end %>
              </div>
              <div class="stat-desc">KMS configuration status</div>
            </div>
          </div>
          <!-- Actions -->
          <div class="card-actions justify-end mt-6">
            <%= if @auto_unseal_status.enabled do %>
              <button phx-click="trigger_unseal" class="btn btn-primary">
                Trigger Unseal Now
              </button>
              <button
                phx-click="disable_auto_unseal"
                class="btn btn-error"
                onclick="return confirm('Are you sure you want to disable auto-unseal? Nodes will require manual unsealing after restart.')"
              >
                Disable Auto-Unseal
              </button>
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
                <span>
                  Auto-unseal must be configured during vault initialization. Please refer to the documentation for setup instructions.
                </span>
              </div>
            <% end %>
          </div>
        </div>
      </div>
      <!-- Cluster Unseal Status -->
      <%= if @cluster_info do %>
        <div class="card bg-base-100 shadow-xl mb-6">
          <div class="card-body">
            <h2 class="card-title">Cluster Unseal Status</h2>

            <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mt-4">
              <div class="stat bg-base-200 rounded-lg">
                <div class="stat-title">Total Nodes</div>
                <div class="stat-value">{@cluster_info.node_count}</div>
              </div>

              <div class="stat bg-base-200 rounded-lg">
                <div class="stat-title">Unsealed</div>
                <div class="stat-value text-green-600">{@cluster_info.unsealed_count}</div>
              </div>

              <div class="stat bg-base-200 rounded-lg">
                <div class="stat-title">Sealed</div>
                <div class="stat-value text-yellow-600">{@cluster_info.sealed_count}</div>
              </div>

              <div class="stat bg-base-200 rounded-lg">
                <div class="stat-title">Initialized</div>
                <div class="stat-value">
                  {if @cluster_info.initialized, do: "Yes", else: "No"}
                </div>
              </div>
            </div>

            <%= if Enum.any?(@cluster_info.nodes) do %>
              <div class="overflow-x-auto mt-4">
                <table class="table table-zebra table-sm">
                  <thead>
                    <tr>
                      <th>Node ID</th>
                      <th>Hostname</th>
                      <th>Status</th>
                      <th>Seal State</th>
                    </tr>
                  </thead>
                  <tbody>
                    <%= for node <- @cluster_info.nodes do %>
                      <tr>
                        <td class="text-xs font-mono">{Map.get(node, :node_id, "N/A")}</td>
                        <td>{Map.get(node, :hostname, "Unknown")}</td>
                        <td>
                          <span class="badge badge-sm">{Map.get(node, :status, "unknown")}</span>
                        </td>
                        <td>
                          <%= if Map.get(node, :sealed, true) do %>
                            <span class="badge badge-warning badge-sm">Sealed</span>
                          <% else %>
                            <span class="badge badge-success badge-sm">Unsealed</span>
                          <% end %>
                        </td>
                      </tr>
                    <% end %>
                  </tbody>
                </table>
              </div>
            <% end %>
          </div>
        </div>
      <% end %>
      <!-- Information Card -->
      <div class="card bg-base-200 shadow-xl">
        <div class="card-body">
          <h2 class="card-title">About Auto-Unseal</h2>

          <div class="prose max-w-none">
            <p>
              Auto-unseal allows SecretHub to automatically unseal the vault on startup using cloud KMS providers (AWS KMS, Google Cloud KMS, or Azure Key Vault). This eliminates the need for manual unseal key entry while maintaining security.
            </p>

            <h3 class="text-lg font-semibold mt-4">How It Works</h3>
            <ol class="list-decimal list-inside space-y-2">
              <li>During initialization, unseal keys are encrypted with your KMS provider</li>
              <li>Encrypted keys are securely stored in the database</li>
              <li>On startup, each node retrieves and decrypts the keys using KMS</li>
              <li>The vault automatically unseals without manual intervention</li>
            </ol>

            <h3 class="text-lg font-semibold mt-4">Supported Providers</h3>
            <ul class="list-disc list-inside space-y-1">
              <li>
                <strong>AWS KMS:</strong>
                Uses AWS Key Management Service with IAM roles (IRSA recommended)
              </li>
              <li>
                <strong>Google Cloud KMS:</strong> Uses GCP KMS with service account authentication
              </li>
              <li><strong>Azure Key Vault:</strong> Uses Azure Key Vault with managed identities</li>
            </ul>

            <h3 class="text-lg font-semibold mt-4">Security Considerations</h3>
            <ul class="list-disc list-inside space-y-1">
              <li>Unseal keys are ALWAYS encrypted before storage</li>
              <li>Use IAM roles or managed identities (never long-lived credentials)</li>
              <li>KMS access is logged and audited by cloud providers</li>
              <li>Manual unseal is still available as a fallback</li>
              <li>Each node independently auto-unseals in HA deployments</li>
            </ul>

            <div class="alert alert-warning mt-4">
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
              <div>
                <h3 class="font-bold">Configuration Notice</h3>
                <div class="text-sm">
                  Auto-unseal must be configured during vault initialization. To enable auto-unseal, reinitialize the vault with the
                  <code>--auto-unseal</code>
                  flag and provide KMS configuration. Refer to the deployment documentation for detailed instructions.
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
  end
end
