defmodule SecretHub.Web.AdminSidebarLive do
  @moduledoc "Persistent admin sidebar across LiveView navigation."

  use SecretHub.Web, :live_view

  import SecretHub.Web.Layouts, only: [version_badge: 1, sidebar_menu_group: 1]

  @menu_ids ~w(
    dashboard secrets rotators engines rotations leases policies approles agents
    pending_agents cli_access ssh_access audit pki_overview pki_ca_list pki_certificates
    pki_certificates_issue pki_csr pki_csr_upload pki_search pki_analytics
    pki_public_trust pki_acme
    cluster templates alerts performance
  )

  @impl true
  def mount(_params, session, socket) do
    {:ok, assign(socket, :active_nav, Map.get(session, "active_nav", "dashboard")), layout: false}
  end

  @impl true
  def handle_event("set_active_nav", %{"active_nav" => active_nav}, socket)
      when active_nav in @menu_ids do
    {:noreply, assign(socket, :active_nav, active_nav)}
  end

  def handle_event("set_active_nav", _params, socket) do
    {:noreply, socket}
  end
end
