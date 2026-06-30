defmodule SecretHub.Web.AdminLayoutHook do
  @moduledoc """
  LiveView hook that sets up the admin layout for all admin pages.
  Uses attach_hook to update navigation on every page navigation.
  """

  import Phoenix.Component
  import Phoenix.LiveView

  alias SecretHub.Core.Vault.SealState

  def on_mount(:default, _params, _session, socket) do
    # Set default values and attach hook for navigation updates
    socket =
      socket
      |> assign(:active_nav, :dashboard)
      |> assign(:page_title, "Dashboard")
      |> assign(:vault_status, vault_status())
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
      |> assign(:vault_status, vault_status())

    {:cont, socket}
  end

  defp vault_status do
    case Process.whereis(SealState) do
      nil ->
        nil

      _pid ->
        SealState.status()
    end
  catch
    :exit, _reason -> nil
  end

  @pki_nav_paths [
    {"/admin/pki/certificates/issue", :pki_certificates_issue},
    {"/admin/pki/certificates", :pki_certificates},
    {"/admin/pki/csr/upload", :pki_csr_upload},
    {"/admin/pki/csr", :pki_csr},
    {"/admin/pki/search", :pki_search},
    {"/admin/pki/analytics", :pki_analytics},
    {"/admin/pki/ca/new", :pki_ca_list},
    {"/admin/pki/ca", :pki_ca_list},
    {"/admin/pki/cas/new", :pki_ca_list},
    {"/admin/pki/cas", :pki_ca_list},
    {"/admin/pki/crl", :pki_ca_list},
    {"/admin/pki", :pki_overview}
  ]

  # Data-driven mapping from URL path segments to nav keys
  @nav_segments %{
    "secrets" => :secrets,
    "rotators" => :rotators,
    "engines" => :engines,
    "rotations" => :rotations,
    "leases" => :leases,
    "policies" => :policies,
    "approles" => :approles,
    "pending-agents" => :pending_agents,
    "cli-access" => :cli_access,
    "agents" => :agents,
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
    rotators: "Secret Rotators",
    engines: "Secret Engines",
    rotations: "Rotation Logs",
    leases: "Lease Management",
    policies: "Policy Management",
    approles: "AppRole Management",
    pending_agents: "Pending Agents",
    cli_access: "CLI Access",
    agents: "Agent Monitoring",
    pki_overview: "PKI Overview",
    pki_ca_list: "PKI CA List",
    pki_certificates: "PKI Certificate List",
    pki_certificates_issue: "Issue PKI Certificate",
    pki_csr: "PKI CSR Management",
    pki_csr_upload: "Upload PKI CSR",
    pki_search: "PKI Search",
    pki_analytics: "PKI Analytics",
    certificates: "Certificates",
    audit: "Audit Log",
    cluster: "Cluster Status",
    templates: "Template Management",
    alerts: "Alerts",
    performance: "Performance"
  }

  defp determine_active_nav(path) do
    pki_nav =
      Enum.find_value(@pki_nav_paths, fn {prefix, nav} ->
        if path == prefix or String.starts_with?(path, prefix <> "/"), do: nav
      end)

    pki_nav ||
      Enum.find_value(@nav_segments, :dashboard, fn {segment, nav} ->
        if String.contains?(path, "/admin/#{segment}"), do: nav
      end)
  end

  defp page_title_for(nav) do
    Map.get(@nav_titles, nav, "Admin")
  end
end
