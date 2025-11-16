defmodule SecretHub.WebWeb.AnomalyDetectionLive do
  @moduledoc """
  LiveView for anomaly detection dashboard.

  Displays:
  - Active anomaly detection rules
  - Recent alerts
  - Alert statistics
  - Rule management (enable/disable, edit thresholds)
  """

  use SecretHub.WebWeb, :live_view

  alias SecretHub.Core.Alerting
  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.{AnomalyDetectionRule, AnomalyAlert}

  import Ecto.Query

  @refresh_interval 10_000

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      schedule_refresh()
    end

    socket =
      socket
      |> assign(:page_title, "Anomaly Detection")
      |> assign(:selected_severity, :all)
      |> assign(:rules, list_rules())
      |> assign(:alerts, list_recent_alerts(:all))
      |> assign(:stats, calculate_stats())

    {:ok, socket}
  end

  @impl true
  def handle_info(:refresh, socket) do
    schedule_refresh()

    socket =
      socket
      |> assign(:alerts, list_recent_alerts(socket.assigns.selected_severity))
      |> assign(:stats, calculate_stats())

    {:noreply, socket}
  end

  @impl true
  def handle_event("toggle_rule", %{"id" => id}, socket) do
    rule = Repo.get!(AnomalyDetectionRule, id)

    case AnomalyDetectionRule.toggle(rule) |> Repo.update() do
      {:ok, _rule} ->
        socket =
          socket
          |> assign(:rules, list_rules())
          |> put_flash(:info, "Rule #{if rule.enabled, do: "disabled", else: "enabled"}")

        {:noreply, socket}

      {:error, _changeset} ->
        {:noreply, put_flash(socket, :error, "Failed to toggle rule")}
    end
  end

  @impl true
  def handle_event("filter_severity", %{"severity" => severity}, socket) do
    severity_atom = if severity == "all", do: :all, else: String.to_existing_atom(severity)

    socket =
      socket
      |> assign(:selected_severity, severity_atom)
      |> assign(:alerts, list_recent_alerts(severity_atom))

    {:noreply, socket}
  end

  @impl true
  def handle_event("acknowledge_alert", %{"id" => id}, socket) do
    case Alerting.acknowledge_alert(id, "web_admin") do
      {:ok, _alert} ->
        socket =
          socket
          |> assign(:alerts, list_recent_alerts(socket.assigns.selected_severity))
          |> put_flash(:info, "Alert acknowledged")

        {:noreply, socket}

      {:error, _reason} ->
        {:noreply, put_flash(socket, :error, "Failed to acknowledge alert")}
    end
  end

  @impl true
  def handle_event("resolve_alert", %{"id" => id}, socket) do
    case Alerting.resolve_alert(id, :resolved, "Resolved from dashboard", "web_admin") do
      {:ok, _alert} ->
        socket =
          socket
          |> assign(:alerts, list_recent_alerts(socket.assigns.selected_severity))
          |> put_flash(:info, "Alert resolved")

        {:noreply, socket}

      {:error, _reason} ->
        {:noreply, put_flash(socket, :error, "Failed to resolve alert")}
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="space-y-6">
      <.header>
        Anomaly Detection
        <:subtitle>Real-time anomaly detection and alerting</:subtitle>
      </.header>
      
    <!-- Statistics Cards -->
      <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
        <.stat_card
          title="Total Alerts"
          value={@stats.total_alerts}
          icon="bell"
          color="blue"
        />
        <.stat_card
          title="Open Alerts"
          value={@stats.open_alerts}
          icon="exclamation-circle"
          color="yellow"
        />
        <.stat_card
          title="Critical Alerts"
          value={@stats.critical_alerts}
          icon="exclamation-triangle"
          color="red"
        />
        <.stat_card
          title="Active Rules"
          value={@stats.active_rules}
          icon="shield-check"
          color="green"
        />
      </div>
      
    <!-- Detection Rules -->
      <div class="bg-white rounded-lg border shadow-sm">
        <div class="px-6 py-4 border-b">
          <h2 class="text-lg font-semibold">Detection Rules</h2>
        </div>
        <div class="divide-y">
          <%= for rule <- @rules do %>
            <div class="px-6 py-4 hover:bg-gray-50">
              <div class="flex items-start justify-between">
                <div class="flex-1">
                  <div class="flex items-center gap-3">
                    <h3 class="text-sm font-medium text-gray-900">{rule.name}</h3>
                    <.rule_type_badge type={rule.rule_type} />
                    <.severity_badge severity={rule.severity} />
                    <%= if rule.enabled do %>
                      <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800">
                        Enabled
                      </span>
                    <% else %>
                      <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-800">
                        Disabled
                      </span>
                    <% end %>
                  </div>
                  <p class="mt-1 text-sm text-gray-500">{rule.description}</p>
                  <div class="mt-2 flex items-center gap-4 text-xs text-gray-500">
                    <span>Triggered: {rule.trigger_count} times</span>
                    <%= if rule.last_triggered_at do %>
                      <span>
                        Last: {Calendar.strftime(rule.last_triggered_at, "%Y-%m-%d %H:%M")}
                      </span>
                    <% end %>
                  </div>
                </div>
                <button
                  phx-click="toggle_rule"
                  phx-value-id={rule.id}
                  class="ml-4 text-sm text-indigo-600 hover:text-indigo-900"
                >
                  {if rule.enabled, do: "Disable", else: "Enable"}
                </button>
              </div>
            </div>
          <% end %>
        </div>
      </div>
      
    <!-- Recent Alerts -->
      <div class="bg-white rounded-lg border shadow-sm">
        <div class="px-6 py-4 border-b flex items-center justify-between">
          <h2 class="text-lg font-semibold">Recent Alerts</h2>
          <div class="flex gap-2">
            <.severity_filter_button
              severity="all"
              selected={@selected_severity}
              label="All"
            />
            <.severity_filter_button
              severity="critical"
              selected={@selected_severity}
              label="Critical"
            />
            <.severity_filter_button
              severity="high"
              selected={@selected_severity}
              label="High"
            />
            <.severity_filter_button
              severity="medium"
              selected={@selected_severity}
              label="Medium"
            />
          </div>
        </div>
        <div class="divide-y">
          <%= for alert <- @alerts do %>
            <div class="px-6 py-4 hover:bg-gray-50">
              <div class="flex items-start justify-between">
                <div class="flex-1">
                  <div class="flex items-center gap-3">
                    <.severity_badge severity={alert.severity} />
                    <.status_badge status={alert.status} />
                    <span class="text-xs text-gray-500">
                      {Calendar.strftime(alert.triggered_at, "%Y-%m-%d %H:%M:%S")}
                    </span>
                  </div>
                  <p class="mt-2 text-sm text-gray-900">{alert.description}</p>
                  <%= if alert.context do %>
                    <div class="mt-2 text-xs text-gray-500 font-mono bg-gray-50 p-2 rounded">
                      {Jason.encode!(alert.context, pretty: true)}
                    </div>
                  <% end %>
                </div>
                <div class="ml-4 flex gap-2">
                  <%= if alert.status == :open do %>
                    <button
                      phx-click="acknowledge_alert"
                      phx-value-id={alert.id}
                      class="text-sm text-blue-600 hover:text-blue-900"
                    >
                      Acknowledge
                    </button>
                    <button
                      phx-click="resolve_alert"
                      phx-value-id={alert.id}
                      class="text-sm text-green-600 hover:text-green-900"
                    >
                      Resolve
                    </button>
                  <% end %>
                </div>
              </div>
            </div>
          <% end %>

          <%= if @alerts == [] do %>
            <div class="px-6 py-12 text-center">
              <.icon name="check-circle" class="mx-auto h-12 w-12 text-green-500" />
              <h3 class="mt-2 text-sm font-medium text-gray-900">No alerts</h3>
              <p class="mt-1 text-sm text-gray-500">
                <%= if @selected_severity == :all do %>
                  All systems operating normally
                <% else %>
                  No {@selected_severity} severity alerts
                <% end %>
              </p>
            </div>
          <% end %>
        </div>
      </div>
    </div>
    """
  end

  defp stat_card(assigns) do
    ~H"""
    <div class="bg-white rounded-lg border p-6 shadow-sm">
      <div class="flex items-start justify-between">
        <div>
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

  defp rule_type_badge(assigns) do
    ~H"""
    <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-blue-100 text-blue-800">
      {format_rule_type(@type)}
    </span>
    """
  end

  defp severity_badge(assigns) do
    color =
      case assigns.severity do
        :critical -> "red"
        :high -> "orange"
        :medium -> "yellow"
        :low -> "blue"
        :info -> "gray"
        _ -> "gray"
      end

    assigns = assign(assigns, :color, color)

    ~H"""
    <span class={"inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-#{@color}-100 text-#{@color}-800"}>
      {String.upcase(to_string(@severity))}
    </span>
    """
  end

  defp status_badge(assigns) do
    {color, label} =
      case assigns.status do
        :open -> {"red", "Open"}
        :acknowledged -> {"yellow", "Acknowledged"}
        :investigating -> {"blue", "Investigating"}
        :resolved -> {"green", "Resolved"}
        :false_positive -> {"gray", "False Positive"}
        _ -> {"gray", to_string(assigns.status)}
      end

    assigns = assigns |> assign(:color, color) |> assign(:label, label)

    ~H"""
    <span class={"inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-#{@color}-100 text-#{@color}-800"}>
      {@label}
    </span>
    """
  end

  defp severity_filter_button(assigns) do
    selected? =
      to_string(assigns.severity) == to_string(assigns.selected)

    assigns = assign(assigns, :selected?, selected?)

    ~H"""
    <button
      phx-click="filter_severity"
      phx-value-severity={@severity}
      class={[
        "px-3 py-1 text-sm rounded-md",
        if(@selected?,
          do: "bg-indigo-600 text-white",
          else: "bg-gray-100 text-gray-700 hover:bg-gray-200"
        )
      ]}
    >
      {@label}
    </button>
    """
  end

  defp schedule_refresh do
    Process.send_after(self(), :refresh, @refresh_interval)
  end

  defp list_rules do
    AnomalyDetectionRule
    |> order_by([r], desc: r.enabled, desc: r.severity, asc: r.name)
    |> Repo.all()
  end

  defp list_recent_alerts(:all) do
    AnomalyAlert
    |> order_by([a], desc: a.triggered_at)
    |> limit(50)
    |> Repo.all()
  end

  defp list_recent_alerts(severity) do
    AnomalyAlert
    |> where([a], a.severity == ^severity)
    |> order_by([a], desc: a.triggered_at)
    |> limit(50)
    |> Repo.all()
  end

  defp calculate_stats do
    total_alerts = Repo.aggregate(AnomalyAlert, :count)

    open_alerts =
      AnomalyAlert
      |> where([a], a.status in [:open, :acknowledged, :investigating])
      |> Repo.aggregate(:count)

    critical_alerts =
      AnomalyAlert
      |> where([a], a.severity == :critical)
      |> where([a], a.status in [:open, :acknowledged, :investigating])
      |> Repo.aggregate(:count)

    active_rules =
      AnomalyDetectionRule
      |> where([r], r.enabled == true)
      |> Repo.aggregate(:count)

    %{
      total_alerts: total_alerts,
      open_alerts: open_alerts,
      critical_alerts: critical_alerts,
      active_rules: active_rules
    }
  end

  defp format_rule_type(type) do
    type
    |> to_string()
    |> String.split("_")
    |> Enum.map(&String.capitalize/1)
    |> Enum.join(" ")
  end
end
