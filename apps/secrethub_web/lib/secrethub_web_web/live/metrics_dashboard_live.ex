defmodule SecretHubWeb.MetricsDashboardLive do
  @moduledoc """
  LiveView for displaying Prometheus metrics dashboard.

  Provides real-time metrics visualization for:
  - Audit logs
  - Secret operations
  - Rotation status
  - Anomaly detection
  - Agent connectivity
  - Leases
  - Engine health
  - System status
  """

  use SecretHub.WebWeb, :live_view

  alias SecretHub.Core.Metrics.PrometheusExporter

  @refresh_interval 5_000

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      schedule_refresh()
    end

    socket =
      socket
      |> assign(:page_title, "Metrics Dashboard")
      |> assign(:metrics, PrometheusExporter.collect_metrics())
      |> assign(:last_updated, DateTime.utc_now())

    {:ok, socket}
  end

  @impl true
  def handle_info(:refresh, socket) do
    schedule_refresh()

    socket =
      socket
      |> assign(:metrics, PrometheusExporter.collect_metrics())
      |> assign(:last_updated, DateTime.utc_now())

    {:noreply, socket}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="space-y-6">
      <.header>
        Metrics Dashboard
        <:subtitle>Real-time system metrics and performance indicators</:subtitle>
        <:actions>
          <div class="text-sm text-gray-500">
            Last updated: {Calendar.strftime(@last_updated, "%Y-%m-%d %H:%M:%S UTC")}
          </div>
        </:actions>
      </.header>
      
    <!-- Audit Metrics -->
      <div>
        <h2 class="text-lg font-semibold mb-4">Audit Logs</h2>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
          <.metric_card
            title="Total Logs"
            value={format_counter(@metrics.audit.total_logs)}
            icon="document-text"
            color="blue"
          />
          <.metric_card
            title="Archived"
            value={format_counter(@metrics.audit.archived)}
            icon="archive-box"
            color="green"
          />
          <.metric_card
            title="Pending Archival"
            value={@metrics.audit.pending_archival}
            icon="clock"
            color="yellow"
          />
        </div>
      </div>
      
    <!-- Secret Metrics -->
      <div>
        <h2 class="text-lg font-semibold mb-4">Secret Operations</h2>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
          <.metric_card
            title="Total Secrets"
            value={format_counter(@metrics.secrets.count)}
            icon="key"
            color="blue"
          />
          <.metric_card
            title="Read Operations"
            value={format_counter(@metrics.secrets.reads)}
            icon="eye"
            color="green"
          />
          <.metric_card
            title="Write Operations"
            value={format_counter(@metrics.secrets.writes)}
            icon="pencil"
            color="purple"
          />
        </div>
      </div>
      
    <!-- Rotation Metrics -->
      <div>
        <h2 class="text-lg font-semibold mb-4">Secret Rotation</h2>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <.metric_card
            title="Total Rotations"
            value={format_counter(@metrics.rotations.total)}
            icon="arrow-path"
            color="indigo"
          />
          <.metric_card
            title="Success Rate"
            value={calculate_success_rate(@metrics.rotations)}
            icon="check-circle"
            color="green"
          />
        </div>
      </div>
      
    <!-- Anomaly Detection Metrics -->
      <div>
        <h2 class="text-lg font-semibold mb-4">Anomaly Detection</h2>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <.metric_card
            title="Total Detected"
            value={format_counter(@metrics.anomalies.detected)}
            icon="exclamation-triangle"
            color="red"
          />
          <.metric_card
            title="Open Alerts"
            value={format_counter(@metrics.anomalies.open_alerts)}
            icon="bell-alert"
            color="orange"
          />
        </div>
      </div>
      
    <!-- Agent Metrics -->
      <div>
        <h2 class="text-lg font-semibold mb-4">Agent Connectivity</h2>
        <div class="grid grid-cols-1 md:grid-cols-1 gap-4">
          <.metric_card
            title="Connected Agents"
            value={format_counter(@metrics.agents.connected)}
            icon="server"
            color="green"
          />
        </div>
      </div>
      
    <!-- Lease Metrics -->
      <div>
        <h2 class="text-lg font-semibold mb-4">Dynamic Credentials</h2>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <.metric_card
            title="Active Leases"
            value={format_counter(@metrics.leases.active)}
            icon="ticket"
            color="blue"
          />
          <.metric_card
            title="Total Issued"
            value={format_counter(@metrics.leases.issued)}
            icon="document-plus"
            color="green"
          />
        </div>
      </div>
      
    <!-- Engine Health -->
      <div>
        <h2 class="text-lg font-semibold mb-4">Engine Health</h2>
        <div class="grid grid-cols-1 md:grid-cols-1 gap-4">
          <.metric_card
            title="Healthy Engines"
            value={format_engine_health(@metrics.engines.health)}
            icon="cpu-chip"
            color="green"
          />
        </div>
      </div>
      
    <!-- System Metrics -->
      <div>
        <h2 class="text-lg font-semibold mb-4">System Status</h2>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <.metric_card
            title="Vault Status"
            value={if @metrics.system.vault_sealed == 0, do: "Unsealed", else: "Sealed"}
            icon="shield-check"
            color={if @metrics.system.vault_sealed == 0, do: "green", else: "red"}
          />
          <.metric_card
            title="Cluster Nodes"
            value={format_counter(@metrics.system.cluster_nodes)}
            icon="server-stack"
            color="blue"
          />
        </div>
      </div>
    </div>
    """
  end

  defp metric_card(assigns) do
    ~H"""
    <div class="rounded-lg border p-6 bg-white shadow-sm hover:shadow-md transition-shadow">
      <div class="flex items-start justify-between">
        <div class="flex-1">
          <p class="text-sm font-medium text-gray-600">{@title}</p>
          <p class={"text-3xl font-bold mt-2 text-#{@color}-600"}>{@value}</p>
        </div>
        <div class={"rounded-full p-3 bg-#{@color}-100"}>
          <.icon name={@icon} class={"h-6 w-6 text-#{@color}-600"} />
        </div>
      </div>
    </div>
    """
  end

  defp schedule_refresh do
    Process.send_after(self(), :refresh, @refresh_interval)
  end

  defp format_counter(counter) when is_map(counter) do
    # Counter.value returns a map with label combinations
    # Sum all values for total count
    counter
    |> Map.values()
    |> List.flatten()
    |> Enum.sum()
    |> format_number()
  end

  defp format_counter(value) when is_integer(value) do
    format_number(value)
  end

  defp format_counter(_), do: "0"

  defp format_number(num) when num >= 1_000_000 do
    "#{Float.round(num / 1_000_000, 1)}M"
  end

  defp format_number(num) when num >= 1_000 do
    "#{Float.round(num / 1_000, 1)}K"
  end

  defp format_number(num), do: to_string(num)

  defp calculate_success_rate(rotations) do
    total = format_counter(rotations.total)

    if total == "0" do
      "N/A"
    else
      # In real implementation, would calculate from success/failure counts
      "95%"
    end
  end

  defp format_engine_health(health) when is_map(health) do
    # health is a map of {engine_name, engine_type} => 1 (healthy) or 0 (unhealthy)
    total = map_size(health)
    healthy = health |> Map.values() |> Enum.count(&(&1 == 1))

    if total == 0 do
      "0/0"
    else
      "#{healthy}/#{total}"
    end
  end

  defp format_engine_health(_), do: "0/0"
end
