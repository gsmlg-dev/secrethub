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

  defp determine_active_nav(path) do
    cond do
      String.contains?(path, "/admin/secrets") -> :secrets
      String.contains?(path, "/admin/engines") -> :engines
      String.contains?(path, "/admin/rotations") -> :rotations
      String.contains?(path, "/admin/leases") -> :leases
      String.contains?(path, "/admin/policies") -> :policies
      String.contains?(path, "/admin/approles") -> :approles
      String.contains?(path, "/admin/agents") -> :agents
      String.contains?(path, "/admin/pki") -> :pki
      String.contains?(path, "/admin/certificates") -> :certificates
      String.contains?(path, "/admin/audit") -> :audit
      String.contains?(path, "/admin/cluster") -> :cluster
      String.contains?(path, "/admin/templates") -> :templates
      String.contains?(path, "/admin/alerts") -> :alerts
      String.contains?(path, "/admin/performance") -> :performance
      String.contains?(path, "/admin/dashboard") -> :dashboard
      true -> :dashboard
    end
  end

  defp page_title_for(nav) do
    case nav do
      :dashboard -> "Dashboard"
      :secrets -> "Secret Management"
      :engines -> "Secret Engines"
      :rotations -> "Rotation Schedule"
      :leases -> "Lease Management"
      :policies -> "Policy Management"
      :approles -> "AppRole Management"
      :agents -> "Agent Monitoring"
      :pki -> "PKI Management"
      :certificates -> "Certificates"
      :audit -> "Audit Log"
      :cluster -> "Cluster Status"
      :templates -> "Template Management"
      :alerts -> "Alerts"
      :performance -> "Performance"
      _ -> "Admin"
    end
  end
end
