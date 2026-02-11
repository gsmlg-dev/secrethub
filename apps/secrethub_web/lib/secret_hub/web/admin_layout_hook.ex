defmodule SecretHub.Web.AdminLayoutHook do
  @moduledoc """
  LiveView hook that sets up the admin layout for all admin pages.
  Uses attach_hook to update navigation on every page navigation.
  """

  import Phoenix.Component
  import Phoenix.LiveView

  def on_mount(:default, _params, _session, socket) do
    # Set default values and attach hook for navigation updates
    socket =
      socket
      |> assign(:active_nav, :dashboard)
      |> assign(:page_title, "Dashboard")
      |> attach_hook(:admin_nav, :handle_params, &update_nav/3)

    {:cont, socket}
  end

  # This callback runs on every navigation, receiving the full URI
  defp update_nav(_params, uri, socket) do
    path = URI.parse(uri).path || ""
    active_nav = determine_active_nav(path)

    socket =
      socket
      |> assign(:active_nav, active_nav)
      |> assign(:page_title, page_title_for(active_nav))

    {:cont, socket}
  end

  # Data-driven mapping from URL path segments to nav keys
  @nav_segments %{
    "secrets" => :secrets,
    "engines" => :engines,
    "rotations" => :rotations,
    "leases" => :leases,
    "policies" => :policies,
    "approles" => :approles,
    "agents" => :agents,
    "pki" => :pki,
    "certificates" => :certificates,
    "audit" => :audit,
    "cluster" => :cluster,
    "templates" => :templates,
    "alerts" => :alerts,
    "performance" => :performance,
    "dashboard" => :dashboard
  }

  # Data-driven mapping from nav keys to page titles
  @nav_titles %{
    dashboard: "Dashboard",
    secrets: "Secret Management",
    engines: "Secret Engines",
    rotations: "Rotation Schedule",
    leases: "Lease Management",
    policies: "Policy Management",
    approles: "AppRole Management",
    agents: "Agent Monitoring",
    pki: "PKI Management",
    certificates: "Certificates",
    audit: "Audit Log",
    cluster: "Cluster Status",
    templates: "Template Management",
    alerts: "Alerts",
    performance: "Performance"
  }

  defp determine_active_nav(path) do
    @nav_segments
    |> Enum.find_value(:dashboard, fn {segment, nav} ->
      if String.contains?(path, "/admin/#{segment}"), do: nav
    end)
  end

  defp page_title_for(nav) do
    Map.get(@nav_titles, nav, "Admin")
  end
end
