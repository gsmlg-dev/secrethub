defmodule SecretHub.Web.PKIManagementLive do
  @moduledoc """
  LiveView for SecretHub PKI management.
  """

  use SecretHub.Web, :live_view

  require Logger

  alias SecretHub.Core.PKI.{CA, Events}
  alias SecretHub.Core.Vault.SealState

  @remove_confirmation_text "I know remove certificate will break everything, I'm sure I want remove it"

  @sealed_vault_status %{
    initialized: true,
    sealed: true,
    progress: 0,
    threshold: nil,
    total_shares: nil
  }

  @cert_type_filters ~w(all root_ca intermediate_ca agent_client app_client admin_client)
  @issue_cert_types ~w(agent_client app_client admin_client)

  @impl true
  def mount(_params, _session, socket) do
    socket =
      socket
      |> assign(:certificates, [])
      |> assign(:filtered_certificates, [])
      |> assign(:ca_certificates, [])
      |> assign(:stats, empty_stats())
      |> assign(:event_stats, empty_event_stats())
      |> assign(:selected_cert, nil)
      |> assign(:selected_ca, nil)
      |> assign(:ca_events, [])
      |> assign(:revocations, [])
      |> assign(:remove_cert, nil)
      |> assign(:remove_confirmation_text, @remove_confirmation_text)
      |> assign(:show_ca_form, false)
      |> assign(:ca_form_type, :root)
      |> assign(:ca_form_data, default_root_ca_form())
      |> assign(:issue_form_data, default_issue_form())
      |> assign(:issued_certificate, nil)
      |> assign(:validation_errors, [])
      |> assign(:filter_type, "all")
      |> assign(:search_query, "")
      |> assign(:active_section, "overview")
      |> assign(:page_title, "PKI Management")

    {:ok, socket}
  end

  @impl true
  def handle_params(params, _uri, socket) do
    certificates = list_certificates()
    event_stats = get_event_stats()
    active_section = section_for(socket.assigns.live_action)
    filter_type = normalize_filter_type(Map.get(params, "type", socket.assigns.filter_type))
    search_query = Map.get(params, "query", "")
    selected_cert = selected_certificate(socket.assigns.live_action, params, certificates)
    selected_ca = selected_ca(socket.assigns.live_action, params, certificates)
    ca_events = selected_ca_events(selected_ca)
    revocations = selected_revocations(socket.assigns.live_action, selected_ca)
    show_ca_form = socket.assigns.show_ca_form or socket.assigns.live_action == :new_ca
    issue_form_data = issue_form_data(socket.assigns.issue_form_data, certificates)

    socket =
      socket
      |> assign(:certificates, certificates)
      |> assign(
        :filtered_certificates,
        filtered_certificates(certificates, filter_type, search_query)
      )
      |> assign(:ca_certificates, ca_certificates(certificates))
      |> assign(:stats, get_pki_stats(certificates, event_stats))
      |> assign(:event_stats, event_stats)
      |> assign(:selected_cert, selected_cert)
      |> assign(:selected_ca, selected_ca)
      |> assign(:ca_events, ca_events)
      |> assign(:revocations, revocations)
      |> assign(:show_ca_form, show_ca_form)
      |> assign(:issue_form_data, issue_form_data)
      |> assign(:filter_type, filter_type)
      |> assign(:search_query, search_query)
      |> assign(:active_section, active_section)
      |> assign(:page_title, page_title_for(active_section, socket.assigns.live_action))

    {:noreply, socket}
  end

  @impl true
  def handle_event("new_root_ca", _params, socket) do
    {:noreply,
     socket
     |> assign(:show_ca_form, true)
     |> assign(:ca_form_type, :root)
     |> assign(:ca_form_data, default_root_ca_form())
     |> assign(:validation_errors, [])}
  end

  @impl true
  def handle_event("new_intermediate_ca", _params, socket) do
    parent_ca_id =
      socket.assigns.certificates
      |> active_parent_cas()
      |> List.first()
      |> then(fn
        nil -> ""
        cert -> cert.id
      end)

    {:noreply,
     socket
     |> assign(:show_ca_form, true)
     |> assign(:ca_form_type, :intermediate)
     |> assign(:ca_form_data, default_intermediate_ca_form(parent_ca_id))
     |> assign(:validation_errors, [])}
  end

  @impl true
  def handle_event("generate_ca", %{"ca" => ca_params}, socket) do
    case socket.assigns.ca_form_type do
      :root -> generate_root_ca(socket, ca_params)
      :intermediate -> generate_intermediate_ca(socket, ca_params)
    end
  end

  @impl true
  def handle_event("cancel_ca_form", _params, socket) do
    {:noreply, assign(socket, show_ca_form: false, validation_errors: [])}
  end

  @impl true
  def handle_event("view_certificate", %{"cert_id" => cert_id}, socket) do
    case CA.get_certificate(cert_id) do
      {:ok, certificate} ->
        {:noreply, assign(socket, :selected_cert, certificate)}

      {:error, _reason} ->
        {:noreply, put_flash(socket, :error, "Failed to load certificate")}
    end
  end

  @impl true
  def handle_event("close_certificate_details", _params, socket) do
    {:noreply, assign(socket, :selected_cert, nil)}
  end

  @impl true
  def handle_event("request_remove_certificate", %{"cert_id" => cert_id}, socket) do
    case CA.get_certificate(cert_id) do
      {:ok, certificate} ->
        {:noreply, assign(socket, remove_cert: certificate, validation_errors: [])}

      {:error, _reason} ->
        {:noreply, put_flash(socket, :error, "Failed to load certificate")}
    end
  end

  @impl true
  def handle_event("cancel_remove_certificate", _params, socket) do
    {:noreply, assign(socket, remove_cert: nil, validation_errors: [])}
  end

  @impl true
  def handle_event(
        "remove_certificate",
        %{"remove" => %{"confirmation" => @remove_confirmation_text}},
        socket
      ) do
    remove_certificate(socket, socket.assigns.remove_cert)
  end

  @impl true
  def handle_event("remove_certificate", _params, socket) do
    {:noreply,
     socket
     |> assign(:validation_errors, ["Confirmation text does not match"])
     |> put_flash(:error, "Failed to remove certificate")}
  end

  @impl true
  def handle_event("revoke_certificate", %{"cert_id" => cert_id}, socket) do
    case CA.revoke_certificate(cert_id) do
      {:ok, _certificate} ->
        {:noreply,
         socket
         |> reload_pki()
         |> assign(:selected_cert, nil)
         |> put_flash(:info, "Certificate revoked successfully")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to revoke certificate: #{inspect(reason)}")}
    end
  end

  @impl true
  def handle_event("issue_certificate", %{"issue" => issue_params}, socket) do
    issue_certificate(socket, issue_params)
  end

  @impl true
  def handle_event("filter_certificates", %{"filter_type" => filter_type}, socket) do
    filter_type = normalize_filter_type(filter_type)

    {:noreply,
     socket
     |> assign(:filter_type, filter_type)
     |> assign(
       :filtered_certificates,
       filtered_certificates(
         socket.assigns.certificates,
         filter_type,
         socket.assigns.search_query
       )
     )}
  end

  @impl true
  def handle_event("search_certificates", %{"query" => query}, socket) do
    {:noreply,
     socket
     |> assign(:search_query, query)
     |> assign(
       :filtered_certificates,
       filtered_certificates(socket.assigns.certificates, socket.assigns.filter_type, query)
     )}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="space-y-6">
      <div class="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 class="text-xl font-semibold text-on-surface">{@page_title}</h2>
        </div>
        <div class="flex flex-wrap items-center gap-2">
          <button
            type="button"
            phx-click="new_root_ca"
            class="inline-flex items-center gap-2 rounded-md bg-primary px-3 py-2 text-sm font-medium text-primary-content"
          >
            <.dm_mdi name="plus" class="h-4 w-4" /> Generate Root CA
          </button>
          <button
            type="button"
            phx-click="new_intermediate_ca"
            class="inline-flex items-center gap-2 rounded-md border border-outline-variant px-3 py-2 text-sm font-medium text-on-surface"
          >
            <.dm_mdi name="source-branch-plus" class="h-4 w-4" /> Generate Intermediate CA
          </button>
        </div>
      </div>

      <nav class="flex flex-wrap gap-2" aria-label="PKI sections">
        <.dm_link navigate={~p"/admin/pki"} class={tab_class(@active_section, "overview")}>
          <.dm_mdi name="chart-box-outline" class="h-4 w-4" /> Overview
        </.dm_link>
        <.dm_link navigate={~p"/admin/pki/ca"} class={tab_class(@active_section, "cas")}>
          <.dm_mdi name="shield-key-outline" class="h-4 w-4" /> CA List
        </.dm_link>
        <.dm_link navigate={~p"/admin/pki/ca/new"} class={tab_class(@active_section, "new_ca")}>
          <.dm_mdi name="shield-plus-outline" class="h-4 w-4" /> New CA
        </.dm_link>
        <.dm_link
          navigate={~p"/admin/pki/certificates"}
          class={tab_class(@active_section, "certificates")}
        >
          <.dm_mdi name="certificate-outline" class="h-4 w-4" /> Certificate List
        </.dm_link>
        <.dm_link
          navigate={~p"/admin/pki/certificates/issue"}
          class={tab_class(@active_section, "issue_certificate")}
        >
          <.dm_mdi name="file-sign" class="h-4 w-4" /> Issue Certificate
        </.dm_link>
        <.dm_link navigate={~p"/admin/pki/csr"} class={tab_class(@active_section, "csr")}>
          <.dm_mdi name="file-document-edit-outline" class="h-4 w-4" /> CSR Management
        </.dm_link>
        <.dm_link
          navigate={~p"/admin/pki/csr/upload"}
          class={tab_class(@active_section, "upload_csr")}
        >
          <.dm_mdi name="upload" class="h-4 w-4" /> Upload CSR
        </.dm_link>
        <.dm_link navigate={~p"/admin/pki/search"} class={tab_class(@active_section, "search")}>
          <.dm_mdi name="magnify" class="h-4 w-4" /> Search
        </.dm_link>
        <.dm_link
          navigate={~p"/admin/pki/analytics"}
          class={tab_class(@active_section, "analytics")}
        >
          <.dm_mdi name="chart-line" class="h-4 w-4" /> Analytics
        </.dm_link>
      </nav>

      <%= case @active_section do %>
        <% "overview" -> %>
          <.overview stats={@stats} event_stats={@event_stats} certificates={@certificates} />
        <% "cas" -> %>
          <%= if @selected_ca do %>
            <%= if @live_action == :crl do %>
              <.crl_panel ca={@selected_ca} revocations={@revocations} />
            <% else %>
              <.ca_detail ca={@selected_ca} ca_events={@ca_events} />
            <% end %>
          <% else %>
            <.ca_listing ca_certificates={@ca_certificates} />
          <% end %>
        <% "new_ca" -> %>
          <.ca_listing ca_certificates={@ca_certificates} />
        <% "certificates" -> %>
          <%= if @selected_cert do %>
            <.certificate_show certificate={@selected_cert} />
          <% else %>
            <.certificate_listing
              certificates={@filtered_certificates}
              filter_type={@filter_type}
              search_query={@search_query}
            />
          <% end %>
        <% "issue_certificate" -> %>
          <.issue_certificate_panel
            title="Issue New Certificate"
            certificates={@certificates}
            issue_form_data={@issue_form_data}
            issued_certificate={@issued_certificate}
            validation_errors={@validation_errors}
          />
        <% "csr" -> %>
          <.csr_panel />
        <% "upload_csr" -> %>
          <.issue_certificate_panel
            title="Upload CSR"
            certificates={@certificates}
            issue_form_data={@issue_form_data}
            issued_certificate={@issued_certificate}
            validation_errors={@validation_errors}
          />
        <% "search" -> %>
          <.search_panel certificates={@filtered_certificates} search_query={@search_query} />
        <% "analytics" -> %>
          <.analytics_panel
            stats={@stats}
            event_stats={@event_stats}
            certificates={@certificates}
          />
      <% end %>

      <.ca_form_modal
        :if={@show_ca_form}
        ca_form_type={@ca_form_type}
        ca_form_data={@ca_form_data}
        certificates={@certificates}
        validation_errors={@validation_errors}
      />

      <.certificate_details_modal :if={@selected_cert} certificate={@selected_cert} />

      <.remove_certificate_modal
        :if={@remove_cert}
        certificate={@remove_cert}
        remove_confirmation_text={@remove_confirmation_text}
        validation_errors={@validation_errors}
      />
    </div>
    """
  end

  defp overview(assigns) do
    ~H"""
    <div class="space-y-6">
      <div class="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        <.dm_card shadow="sm">
          <.dm_stat title="Total Certificates" value={Integer.to_string(@stats.total)}>
            <:icon><.dm_mdi name="certificate-outline" class="h-6 w-6" /></:icon>
          </.dm_stat>
        </.dm_card>
        <.dm_card shadow="sm">
          <.dm_stat title="Active" value={Integer.to_string(@stats.active)} color="success">
            <:icon><.dm_mdi name="check-circle-outline" class="h-6 w-6" /></:icon>
          </.dm_stat>
        </.dm_card>
        <.dm_card shadow="sm">
          <.dm_stat title="Revoked" value={Integer.to_string(@stats.revoked)} color="error">
            <:icon><.dm_mdi name="cancel" class="h-6 w-6" /></:icon>
          </.dm_stat>
        </.dm_card>
        <.dm_card shadow="sm">
          <.dm_stat title="PKI Events" value={Integer.to_string(@event_stats.total_events)}>
            <:icon><.dm_mdi name="timeline-text-outline" class="h-6 w-6" /></:icon>
          </.dm_stat>
        </.dm_card>
      </div>

      <.dm_card shadow="sm">
        <:title>PKI Overview</:title>
        <div class="overflow-x-auto">
          <.dm_table data={Enum.take(@certificates, 8)} compact hover>
            <:col :let={cert} label="Certificate">
              <div class="font-medium text-on-surface">{cert.common_name}</div>
              <div class="font-mono text-xs text-on-surface-variant">
                {short_serial(cert.serial_number)}
              </div>
            </:col>
            <:col :let={cert} label="Type">{format_cert_type(cert.cert_type)}</:col>
            <:col :let={cert} label="Status">
              <.dm_badge variant={status_badge_variant(cert)} size="sm" soft>
                {status_text(cert)}
              </.dm_badge>
            </:col>
            <:col :let={cert} label="Expires">Expires: {format_expiry(cert.valid_until)}</:col>
          </.dm_table>
        </div>
      </.dm_card>
    </div>
    """
  end

  defp ca_listing(assigns) do
    ~H"""
    <.dm_card shadow="sm">
      <:title>Certificate Authorities</:title>
      <div class="overflow-x-auto">
        <.dm_table data={@ca_certificates} compact hover>
          <:col :let={ca} label="CA">
            <div class="font-medium text-on-surface">{ca.common_name}</div>
            <div class="font-mono text-xs text-on-surface-variant">
              {short_serial(ca.serial_number)}
            </div>
          </:col>
          <:col :let={ca} label="Type">{format_cert_type(ca.cert_type)}</:col>
          <:col :let={ca} label="Status">
            <.dm_badge variant={status_badge_variant(ca)} size="sm" soft>{status_text(ca)}</.dm_badge>
          </:col>
          <:col :let={ca} label="Valid Until">{format_expiry(ca.valid_until)}</:col>
          <:col :let={ca} label="Actions">
            <div class="flex flex-wrap gap-2">
              <.dm_link
                navigate={~p"/admin/pki/ca/#{ca.id}"}
                class="inline-flex items-center gap-1 text-sm text-primary"
              >
                <.dm_mdi name="eye-outline" class="h-4 w-4" /> View
              </.dm_link>
              <.dm_link
                navigate={~p"/admin/pki/crl/#{ca.id}"}
                class="inline-flex items-center gap-1 text-sm text-secondary"
              >
                <.dm_mdi name="file-document-outline" class="h-4 w-4" /> CRL
              </.dm_link>
            </div>
          </:col>
        </.dm_table>
      </div>
    </.dm_card>
    """
  end

  defp ca_detail(assigns) do
    ~H"""
    <div class="space-y-6">
      <.dm_card shadow="sm">
        <:title>CA Details</:title>
        <div class="grid grid-cols-1 gap-4 md:grid-cols-2">
          <.detail_item label="Common Name" value={@ca.common_name} />
          <.detail_item label="Type" value={format_cert_type(@ca.cert_type)} />
          <.detail_item label="Serial" value={@ca.serial_number} mono />
          <.detail_item label="Fingerprint" value={@ca.fingerprint} mono />
          <.detail_item label="Subject" value={@ca.subject} mono />
          <.detail_item label="Issuer" value={@ca.issuer} mono />
        </div>
      </.dm_card>

      <.dm_card shadow="sm">
        <:title>Event History</:title>
        <.dm_table data={@ca_events} compact hover>
          <:col :let={event} label="Sequence">{event.sequence}</:col>
          <:col :let={event} label="Type">{event.event_type}</:col>
          <:col :let={event} label="Serial">{metadata_value(event, :serial)}</:col>
          <:col :let={event} label="Timestamp">{format_datetime(event.timestamp)}</:col>
        </.dm_table>
      </.dm_card>
    </div>
    """
  end

  defp crl_panel(assigns) do
    ~H"""
    <.dm_card shadow="sm">
      <:title>CRL - {@ca.common_name}</:title>
      <.dm_table data={@revocations} compact hover>
        <:col :let={revocation} label="Serial">{revocation.serial}</:col>
        <:col :let={revocation} label="Reason">{revocation.reason}</:col>
        <:col :let={revocation} label="Revoked At">
          {format_datetime(revocation.revocation_date)}
        </:col>
      </.dm_table>
    </.dm_card>
    """
  end

  defp certificate_listing(assigns) do
    ~H"""
    <div class="space-y-4">
      <.dm_card shadow="sm">
        <:title>Certificate List</:title>
        <div class="mb-4">
          <.dm_link
            navigate={~p"/admin/pki/certificates/issue"}
            class="inline-flex items-center gap-2 rounded-md bg-primary px-3 py-2 text-sm font-medium text-primary-content"
          >
            <.dm_mdi name="file-sign" class="h-4 w-4" /> Issue Certificate
          </.dm_link>
        </div>
        <div class="grid grid-cols-1 gap-3 md:grid-cols-[220px_1fr]">
          <form phx-change="filter_certificates">
            <.dm_input
              type="select"
              name="filter_type"
              label="Type"
              value={@filter_type}
              options={[
                {"All", "all"},
                {"Root CA", "root_ca"},
                {"Intermediate CA", "intermediate_ca"},
                {"Agent Client", "agent_client"},
                {"App Client", "app_client"},
                {"Admin Client", "admin_client"}
              ]}
            />
          </form>
          <form phx-change="search_certificates">
            <.dm_input
              type="search"
              name="query"
              label="Search"
              value={@search_query}
              placeholder="Common name or serial"
            />
          </form>
        </div>
      </.dm_card>

      <.certificate_table certificates={@certificates} />
    </div>
    """
  end

  defp certificate_table(assigns) do
    ~H"""
    <.dm_card shadow="sm">
      <div :if={Enum.empty?(@certificates)} class="px-4 py-10 text-center text-on-surface-variant">
        No certificates found.
      </div>
      <div :if={!Enum.empty?(@certificates)} class="overflow-x-auto">
        <.dm_table data={@certificates} compact hover>
          <:col :let={cert} label="Certificate">
            <div class="font-medium text-on-surface">{cert.common_name}</div>
            <div class="font-mono text-xs text-on-surface-variant">
              {short_serial(cert.serial_number)}
            </div>
          </:col>
          <:col :let={cert} label="Type">{format_cert_type(cert.cert_type)}</:col>
          <:col :let={cert} label="Status">
            <.dm_badge variant={status_badge_variant(cert)} size="sm" soft>
              {status_text(cert)}
            </.dm_badge>
          </:col>
          <:col :let={cert} label="Expires">Expires: {format_expiry(cert.valid_until)}</:col>
          <:col :let={cert} label="Actions">
            <div class="flex flex-wrap gap-2">
              <button
                type="button"
                phx-click="view_certificate"
                phx-value-cert_id={cert.id}
                class="inline-flex items-center gap-1 rounded border border-outline-variant px-2 py-1 text-xs text-on-surface"
              >
                <.dm_mdi name="eye-outline" class="h-4 w-4" /> View Details
              </button>
              <%= if !cert.revoked and cert.cert_type not in [:root_ca, :intermediate_ca] do %>
                <button
                  type="button"
                  phx-click="revoke_certificate"
                  phx-value-cert_id={cert.id}
                  data-confirm="Are you sure you want to revoke this certificate?"
                  class="inline-flex items-center gap-1 rounded border border-error px-2 py-1 text-xs text-error"
                >
                  <.dm_mdi name="cancel" class="h-4 w-4" /> Revoke
                </button>
              <% end %>
              <button
                type="button"
                phx-click="request_remove_certificate"
                phx-value-cert_id={cert.id}
                class="inline-flex items-center gap-1 rounded border border-error px-2 py-1 text-xs text-error"
              >
                <.dm_mdi name="trash-can-outline" class="h-4 w-4" /> Remove
              </button>
            </div>
          </:col>
        </.dm_table>
      </div>
    </.dm_card>
    """
  end

  defp csr_panel(assigns) do
    ~H"""
    <.dm_card shadow="sm">
      <:title>CSR Management</:title>
      <div class="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <.dm_input
          type="textarea"
          name="csr[pem]"
          label="CSR PEM"
          rows="14"
          placeholder="-----BEGIN CERTIFICATE REQUEST-----"
        />
        <div class="rounded-md border border-outline-variant p-4">
          <h3 class="text-sm font-semibold text-on-surface">Pending CSRs</h3>
          <p class="mt-4 text-sm text-on-surface-variant">No CSR records found.</p>
          <.dm_link
            navigate={~p"/admin/pki/csr/upload"}
            class="mt-4 inline-flex items-center gap-2 rounded-md border border-outline-variant px-3 py-2 text-sm text-on-surface"
          >
            <.dm_mdi name="upload" class="h-4 w-4" /> Upload CSR
          </.dm_link>
        </div>
      </div>
    </.dm_card>
    """
  end

  defp issue_certificate_panel(assigns) do
    ~H"""
    <div class="space-y-4">
      <.dm_card shadow="sm">
        <:title>{@title}</:title>
        <form phx-submit="issue_certificate" class="space-y-4">
          <div class="grid grid-cols-1 gap-4 lg:grid-cols-3">
            <.dm_input
              type="select"
              name="issue[ca_id]"
              label="Certificate Authority"
              value={@issue_form_data["ca_id"]}
              prompt="Select CA"
              options={parent_ca_options(@certificates)}
              required
            />
            <.dm_input
              type="select"
              name="issue[cert_type]"
              label="Certificate Template"
              value={@issue_form_data["cert_type"]}
              options={cert_type_options()}
              required
            />
            <.dm_input
              type="number"
              name="issue[validity_days]"
              label="Validity (days)"
              value={@issue_form_data["validity_days"]}
              required
            />
          </div>

          <.dm_input
            type="textarea"
            name="issue[csr_pem]"
            label="Certificate Signing Request (CSR)"
            rows="14"
            value={@issue_form_data["csr_pem"]}
            placeholder="-----BEGIN CERTIFICATE REQUEST-----"
            required
          />

          <div :if={!Enum.empty?(@validation_errors)} class="border-l-4 border-error bg-error/5 p-4">
            <ul class="list-inside list-disc text-sm text-error">
              <li :for={error <- @validation_errors}>{error}</li>
            </ul>
          </div>

          <div class="flex justify-end">
            <button
              type="submit"
              class="inline-flex items-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-content"
            >
              <.dm_mdi name="file-sign" class="h-4 w-4" /> Issue Certificate
            </button>
          </div>
        </form>
      </.dm_card>

      <.dm_card :if={@issued_certificate} shadow="sm">
        <:title>Issued Certificate</:title>
        <div class="grid grid-cols-1 gap-4 md:grid-cols-2">
          <.detail_item label="Common Name" value={@issued_certificate.cert_record.common_name} />
          <.detail_item
            label="Serial Number"
            value={@issued_certificate.cert_record.serial_number}
            mono
          />
          <.detail_item
            label="Type"
            value={format_cert_type(@issued_certificate.cert_record.cert_type)}
          />
          <.detail_item
            label="Valid Until"
            value={format_datetime(@issued_certificate.cert_record.valid_until)}
          />
        </div>
        <pre class="mt-4 overflow-x-auto rounded-md border border-outline-variant bg-surface-container-low p-4 font-mono text-xs">{@issued_certificate.certificate}</pre>
      </.dm_card>
    </div>
    """
  end

  defp certificate_show(assigns) do
    ~H"""
    <div class="space-y-4">
      <.dm_link
        navigate={~p"/admin/pki/certificates"}
        class="inline-flex items-center gap-1 text-sm text-primary"
      >
        <.dm_mdi name="arrow-left" class="h-4 w-4" /> Certificate List
      </.dm_link>
      <.dm_card shadow="sm">
        <:title>Certificate Details</:title>
        <div class="grid grid-cols-1 gap-4 md:grid-cols-2">
          <.detail_item label="Common Name" value={@certificate.common_name} />
          <.detail_item label="Type" value={format_cert_type(@certificate.cert_type)} />
          <.detail_item label="Serial Number" value={@certificate.serial_number} mono />
          <.detail_item label="Fingerprint" value={@certificate.fingerprint} mono />
          <.detail_item label="Subject" value={@certificate.subject} mono />
          <.detail_item label="Issuer" value={@certificate.issuer} mono />
        </div>
      </.dm_card>
    </div>
    """
  end

  defp analytics_panel(assigns) do
    ~H"""
    <div class="space-y-6">
      <div class="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        <.dm_card shadow="sm">
          <.dm_stat title="Total Certificates" value={Integer.to_string(@stats.total)} />
        </.dm_card>
        <.dm_card shadow="sm">
          <.dm_stat title="Certificate Authorities" value={Integer.to_string(@stats.cas)} />
        </.dm_card>
        <.dm_card shadow="sm">
          <.dm_stat title="Expired" value={Integer.to_string(@stats.expired)} color="warning" />
        </.dm_card>
        <.dm_card shadow="sm">
          <.dm_stat title="PKI Events" value={Integer.to_string(@event_stats.total_events)} />
        </.dm_card>
      </div>

      <.dm_card shadow="sm">
        <:title>Event Types</:title>
        <.dm_table data={event_type_rows(@event_stats.events_by_type)} compact hover>
          <:col :let={row} label="Event Type">{row.type}</:col>
          <:col :let={row} label="Count">{row.count}</:col>
        </.dm_table>
      </.dm_card>

      <section class="space-y-3">
        <h3 class="text-base font-semibold text-on-surface">Expiring Certificates</h3>
        <.certificate_table certificates={expiring_certificates(@certificates, 30)} />
      </section>
    </div>
    """
  end

  defp search_panel(assigns) do
    ~H"""
    <div class="space-y-4">
      <.dm_card shadow="sm">
        <:title>PKI Search</:title>
        <form phx-change="search_certificates">
          <.dm_input
            type="search"
            name="query"
            label="Search"
            value={@search_query}
            placeholder="Common name or serial"
          />
        </form>
      </.dm_card>

      <.certificate_table certificates={@certificates} />
    </div>
    """
  end

  defp ca_form_modal(assigns) do
    ~H"""
    <div class="fixed inset-0 z-40 flex items-center justify-center bg-surface-container-low/80 p-4">
      <div class="max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-lg border border-outline-variant bg-surface-container shadow-xl">
        <div class="border-b border-outline-variant px-6 py-4">
          <h3 class="text-lg font-medium text-on-surface">
            {if @ca_form_type == :root, do: "Generate Root CA", else: "Generate Intermediate CA"}
          </h3>
        </div>

        <form phx-submit="generate_ca" class="space-y-4 px-6 py-4">
          <%= if @ca_form_type == :intermediate do %>
            <.dm_input
              type="select"
              name="ca[parent_ca_id]"
              label="Parent CA"
              value={@ca_form_data["parent_ca_id"]}
              prompt="Select parent CA"
              options={parent_ca_options(@certificates)}
              required
            />
          <% end %>

          <.dm_input
            name="ca[common_name]"
            label="Common Name"
            value={@ca_form_data["common_name"]}
            required
          />

          <div class="grid grid-cols-1 gap-4 md:grid-cols-2">
            <.dm_input
              name="ca[organization]"
              label="Organization"
              value={@ca_form_data["organization"]}
              required
            />
            <.dm_input
              name="ca[country]"
              label="Country"
              value={@ca_form_data["country"]}
              maxlength="2"
              required
            />
          </div>

          <div class="grid grid-cols-1 gap-4 md:grid-cols-3">
            <.dm_input
              type="select"
              name="ca[key_type]"
              label="Key Type"
              value={@ca_form_data["key_type"]}
              options={[{"RSA", "rsa"}, {"ECDSA", "ecdsa"}]}
            />
            <.dm_input
              type="select"
              name="ca[key_bits]"
              label="Key Bits"
              value={@ca_form_data["key_bits"]}
              options={[{"2048", "2048"}, {"4096", "4096"}]}
            />
            <.dm_input
              type="number"
              name="ca[ttl_days]"
              label="TTL (days)"
              value={@ca_form_data["ttl_days"]}
              required
            />
          </div>

          <div :if={!Enum.empty?(@validation_errors)} class="border-l-4 border-error bg-error/5 p-4">
            <ul class="list-inside list-disc text-sm text-error">
              <li :for={error <- @validation_errors}>{error}</li>
            </ul>
          </div>

          <div class="flex justify-end gap-3 pt-4">
            <button
              type="button"
              phx-click="cancel_ca_form"
              class="rounded-md border border-outline-variant px-4 py-2 text-sm text-on-surface"
            >
              Cancel
            </button>
            <button
              type="submit"
              class="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-content"
            >
              Generate CA
            </button>
          </div>
        </form>
      </div>
    </div>
    """
  end

  defp certificate_details_modal(assigns) do
    ~H"""
    <div class="fixed inset-0 z-40 flex items-center justify-center bg-surface-container-low/80 p-4">
      <div class="max-h-[90vh] w-full max-w-4xl overflow-y-auto rounded-lg border border-outline-variant bg-surface-container shadow-xl">
        <div class="flex items-center justify-between border-b border-outline-variant px-6 py-4">
          <h3 class="text-lg font-medium text-on-surface">Certificate Details</h3>
          <button type="button" phx-click="close_certificate_details" class="text-on-surface-variant">
            <.dm_mdi name="close" class="h-6 w-6" />
          </button>
        </div>

        <div class="space-y-4 px-6 py-4">
          <div class="grid grid-cols-1 gap-4 md:grid-cols-2">
            <.detail_item label="Common Name" value={@certificate.common_name} />
            <.detail_item label="Type" value={format_cert_type(@certificate.cert_type)} />
            <.detail_item label="Serial Number" value={@certificate.serial_number} mono />
            <.detail_item label="Fingerprint (SHA-256)" value={@certificate.fingerprint} mono />
            <.detail_item label="Valid From" value={format_datetime(@certificate.valid_from)} />
            <.detail_item label="Valid Until" value={format_datetime(@certificate.valid_until)} />
          </div>

          <div>
            <span class="block text-sm font-medium text-on-surface-variant">Status</span>
            <.dm_badge variant={status_badge_variant(@certificate)} size="sm" soft>
              <%= if @certificate.revoked do %>
                Revoked at {format_datetime(@certificate.revoked_at)}
              <% else %>
                Active
              <% end %>
            </.dm_badge>
          </div>

          <.detail_item label="Issuer:" value={@certificate.issuer} mono />
          <.detail_item label="Subject:" value={@certificate.subject} mono />

          <div>
            <span class="mb-2 block text-sm font-medium text-on-surface-variant">
              X509v3 extensions:
            </span>
            <div class="rounded-md border border-outline-variant bg-surface-container-low p-4">
              <%= case x509_extensions(@certificate) do %>
                <% [] -> %>
                  <p class="text-sm text-on-surface-variant">No X509v3 extensions found.</p>
                <% extensions -> %>
                  <dl class="space-y-3">
                    <div :for={extension <- extensions}>
                      <dt class="text-xs font-semibold text-on-surface">
                        {extension.name}
                        <span :if={extension.critical} class="ml-2 text-error">critical</span>
                      </dt>
                      <dd class="mt-1 break-all font-mono text-xs text-on-surface-variant">
                        {extension.value}
                      </dd>
                    </div>
                  </dl>
              <% end %>
            </div>
          </div>

          <div>
            <span class="mb-2 block text-sm font-medium text-on-surface-variant">
              Certificate PEM
            </span>
            <pre class="overflow-x-auto rounded-md border border-outline-variant bg-surface-container-low p-4 font-mono text-xs">{@certificate.certificate_pem}</pre>
          </div>
        </div>
      </div>
    </div>
    """
  end

  defp remove_certificate_modal(assigns) do
    ~H"""
    <div class="fixed inset-0 z-50 flex items-center justify-center bg-surface-container-low/80 p-4">
      <div class="w-full max-w-2xl rounded-lg border border-outline-variant bg-surface-container shadow-xl">
        <div class="border-b border-outline-variant px-6 py-4">
          <h3 class="text-lg font-medium text-error">Remove Certificate</h3>
        </div>

        <form phx-submit="remove_certificate" class="space-y-4 px-6 py-4">
          <p class="text-sm text-on-surface">
            Removing {@certificate.common_name} permanently deletes the certificate record and may break certificate chains, mTLS authentication, and dependent services.
          </p>
          <p class="text-sm text-on-surface-variant">Type this exact text to continue:</p>
          <pre class="whitespace-pre-wrap rounded-md border border-outline-variant bg-surface-container-low p-3 font-mono text-xs">{@remove_confirmation_text}</pre>
          <.dm_input name="remove[confirmation]" value="" autocomplete="off" />

          <div :if={!Enum.empty?(@validation_errors)} class="border-l-4 border-error bg-error/5 p-4">
            <ul class="list-inside list-disc text-sm text-error">
              <li :for={error <- @validation_errors}>{error}</li>
            </ul>
          </div>

          <div class="flex justify-end gap-3 pt-4">
            <button
              type="button"
              phx-click="cancel_remove_certificate"
              class="rounded-md border border-outline-variant px-4 py-2 text-sm text-on-surface"
            >
              Cancel
            </button>
            <button
              type="submit"
              class="rounded-md border border-error px-4 py-2 text-sm font-medium text-error"
            >
              Remove Certificate
            </button>
          </div>
        </form>
      </div>
    </div>
    """
  end

  attr :label, :string, required: true
  attr :value, :any, required: true
  attr :mono, :boolean, default: false

  defp detail_item(assigns) do
    ~H"""
    <div>
      <span class="block text-sm font-medium text-on-surface-variant">{@label}</span>
      <p class={["mt-1 break-all text-sm text-on-surface", @mono && "font-mono"]}>{@value}</p>
    </div>
    """
  end

  defp remove_certificate(socket, nil) do
    {:noreply,
     socket
     |> assign(:remove_cert, nil)
     |> put_flash(:error, "Failed to remove certificate")}
  end

  defp remove_certificate(socket, certificate) do
    case CA.delete_certificate(certificate.id) do
      {:ok, _certificate} ->
        {:noreply,
         socket
         |> reload_pki()
         |> assign(:selected_cert, nil)
         |> assign(:remove_cert, nil)
         |> assign(:validation_errors, [])
         |> put_flash(:info, "Certificate removed successfully")}

      {:error, reason} ->
        {:noreply,
         socket
         |> assign(:validation_errors, ["Failed to remove certificate: #{inspect(reason)}"])
         |> put_flash(:error, "Failed to remove certificate")}
    end
  end

  defp issue_certificate(socket, issue_params) do
    with {:ok, ca_id} <- required_value(issue_params["ca_id"], "Select a Certificate Authority"),
         {:ok, csr_pem} <- required_value(issue_params["csr_pem"], "CSR PEM is required"),
         {:ok, cert_type} <- issue_cert_type(issue_params["cert_type"]),
         {:ok, validity_days} <- positive_integer(issue_params["validity_days"], "Validity") do
      case CA.sign_csr(csr_pem, ca_id, cert_type, validity_days: validity_days) do
        {:ok, issued_certificate} ->
          {:noreply,
           socket
           |> reload_pki()
           |> assign(:issued_certificate, issued_certificate)
           |> assign(:issue_form_data, default_issue_form())
           |> assign(:validation_errors, [])
           |> put_flash(:info, "Certificate issued successfully")}

        {:error, "Vault is sealed"} ->
          {:noreply, show_vault_sealed_banner(socket)}

        {:error, reason} ->
          {:noreply,
           socket
           |> assign(:issue_form_data, issue_params)
           |> assign(:issued_certificate, nil)
           |> assign(:validation_errors, [format_ca_error(reason)])
           |> put_flash(:error, "Failed to issue certificate")}
      end
    else
      {:error, message} ->
        {:noreply,
         socket
         |> assign(:issue_form_data, issue_params)
         |> assign(:issued_certificate, nil)
         |> assign(:validation_errors, [message])
         |> put_flash(:error, "Failed to issue certificate")}
    end
  end

  defp generate_root_ca(socket, ca_params) do
    with {:ok, ttl_days} <- positive_integer(ca_params["ttl_days"], "TTL"),
         {:ok, key_bits} <- positive_integer(ca_params["key_bits"], "Key bits") do
      key_type = parse_key_type(ca_params["key_type"])

      case CA.generate_root_ca(
             ca_params["common_name"],
             ca_params["organization"],
             country: ca_params["country"],
             key_type: key_type,
             key_size: key_bits,
             validity_days: ttl_days
           ) do
        {:ok, _certificate} ->
          {:noreply,
           socket
           |> reload_pki()
           |> assign(:show_ca_form, false)
           |> put_flash(:info, "Root CA generated successfully")}

        {:error, "Vault is sealed"} ->
          {:noreply, show_vault_sealed_banner(socket)}

        {:error, reason} ->
          {:noreply,
           socket
           |> assign(:validation_errors, [format_ca_error(reason)])
           |> put_flash(:error, "Failed to generate Root CA")}
      end
    else
      {:error, message} ->
        {:noreply,
         socket
         |> assign(:validation_errors, [message])
         |> put_flash(:error, "Failed to generate Root CA")}
    end
  end

  defp generate_intermediate_ca(socket, ca_params) do
    with {:ok, ttl_days} <- positive_integer(ca_params["ttl_days"], "TTL"),
         {:ok, key_bits} <- positive_integer(ca_params["key_bits"], "Key bits"),
         {:ok, parent_ca_id} <- parent_ca_id(ca_params["parent_ca_id"]) do
      key_type = parse_key_type(ca_params["key_type"])

      do_generate_intermediate_ca(socket, ca_params, parent_ca_id, key_type, key_bits, ttl_days)
    else
      {:error, message} ->
        {:noreply,
         socket
         |> assign(:validation_errors, [message])
         |> put_flash(:error, "Failed to generate Intermediate CA")}
    end
  end

  defp do_generate_intermediate_ca(
         socket,
         ca_params,
         root_ca_cert_id,
         key_type,
         key_bits,
         ttl_days
       ) do
    case CA.generate_intermediate_ca(
           ca_params["common_name"],
           ca_params["organization"],
           root_ca_cert_id,
           country: ca_params["country"],
           key_type: key_type,
           key_size: key_bits,
           validity_days: ttl_days
         ) do
      {:ok, _certificate} ->
        {:noreply,
         socket
         |> reload_pki()
         |> assign(:show_ca_form, false)
         |> put_flash(:info, "Intermediate CA generated successfully")}

      {:error, "Vault is sealed"} ->
        {:noreply, show_vault_sealed_banner(socket)}

      {:error, reason} ->
        {:noreply,
         socket
         |> assign(:validation_errors, [format_ca_error(reason)])
         |> put_flash(:error, "Failed to generate Intermediate CA")}
    end
  end

  defp reload_pki(socket) do
    certificates = list_certificates()
    event_stats = get_event_stats()

    socket
    |> assign(:certificates, certificates)
    |> assign(
      :filtered_certificates,
      filtered_certificates(certificates, socket.assigns.filter_type, socket.assigns.search_query)
    )
    |> assign(:ca_certificates, ca_certificates(certificates))
    |> assign(:stats, get_pki_stats(certificates, event_stats))
    |> assign(:event_stats, event_stats)
  end

  defp list_certificates do
    case CA.list_certificates() do
      {:ok, certificates} -> certificates
      {:error, _reason} -> []
      certificates when is_list(certificates) -> certificates
    end
    |> Enum.sort_by(
      &(&1.inserted_at || &1.valid_from || ~U[1970-01-01 00:00:00Z]),
      {:desc, DateTime}
    )
  end

  defp get_event_stats do
    case Events.get_stats() do
      {:ok, stats} -> Map.merge(empty_event_stats(), stats)
      {:error, _reason} -> empty_event_stats()
    end
  end

  defp selected_certificate(action, params, certificates)
       when action in [:certificate_show, :certificate_revoke] do
    identifier = params["id"] || params["serial"]

    Enum.find(certificates, fn certificate ->
      certificate.id == identifier or certificate.serial_number == identifier
    end)
  end

  defp selected_certificate(_action, _params, _certificates), do: nil

  defp selected_ca(action, params, certificates) when action in [:ca_show, :ca_stats, :crl] do
    id = params["id"] || params["ca_id"]

    Enum.find(certificates, &(&1.id == id and &1.cert_type in [:root_ca, :intermediate_ca]))
  end

  defp selected_ca(_action, _params, _certificates), do: nil

  defp selected_ca_events(nil), do: []

  defp selected_ca_events(ca) do
    case Events.query_by_ca(ca.id) do
      {:ok, events} -> events
      {:error, _reason} -> []
    end
  end

  defp selected_revocations(:crl, nil), do: []

  defp selected_revocations(:crl, ca) do
    case Events.get_revocations(ca.id) do
      {:ok, revocations} -> revocations
      {:error, _reason} -> []
    end
  end

  defp selected_revocations(_action, _ca), do: []

  defp get_pki_stats(certificates, event_stats) do
    total = length(certificates)
    revoked = Enum.count(certificates, & &1.revoked)
    expired = Enum.count(certificates, &expired?/1)
    active = total - revoked - expired
    cas = Enum.count(certificates, &(&1.cert_type in [:root_ca, :intermediate_ca]))

    %{
      total: total,
      active: max(active, 0),
      revoked: revoked,
      expired: expired,
      cas: cas,
      events: event_stats.total_events
    }
  end

  defp empty_stats, do: %{total: 0, active: 0, revoked: 0, expired: 0, cas: 0, events: 0}
  defp empty_event_stats, do: %{total_events: 0, events_by_type: %{}, storage_backend: :postgres}

  defp default_root_ca_form do
    %{
      "common_name" => "SecretHub Root CA",
      "organization" => "SecretHub",
      "country" => "US",
      "key_type" => "rsa",
      "key_bits" => "4096",
      "ttl_days" => "3650"
    }
  end

  defp default_intermediate_ca_form(parent_ca_id) do
    %{
      "common_name" => "SecretHub Intermediate CA",
      "organization" => "SecretHub",
      "country" => "US",
      "parent_ca_id" => parent_ca_id,
      "key_type" => "rsa",
      "key_bits" => "2048",
      "ttl_days" => "1825"
    }
  end

  defp default_issue_form do
    %{
      "ca_id" => "",
      "cert_type" => "agent_client",
      "validity_days" => "365",
      "csr_pem" => ""
    }
  end

  defp issue_form_data(form_data, certificates) do
    form_data = Map.merge(default_issue_form(), form_data || %{})

    if form_data["ca_id"] in [nil, ""] do
      certificates
      |> active_parent_cas()
      |> List.first()
      |> case do
        nil -> form_data
        ca -> Map.put(form_data, "ca_id", ca.id)
      end
    else
      form_data
    end
  end

  defp ca_certificates(certificates) do
    Enum.filter(certificates, &(&1.cert_type in [:root_ca, :intermediate_ca]))
  end

  defp active_parent_cas(certificates) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    certificates
    |> Enum.filter(&active_ca?(&1, now))
    |> Enum.sort_by(&(&1.inserted_at || &1.valid_from), {:desc, DateTime})
  end

  defp active_ca?(cert, now) do
    cert.cert_type in [:root_ca, :intermediate_ca] and not cert.revoked and
      DateTime.compare(cert.valid_until, now) == :gt
  end

  defp parent_ca_options(certificates) do
    certificates
    |> active_parent_cas()
    |> Enum.map(&{"#{&1.common_name} (#{format_cert_type(&1.cert_type)})", &1.id})
  end

  defp cert_type_options do
    [
      {"Agent Client", "agent_client"},
      {"Application Client", "app_client"},
      {"Admin Client", "admin_client"}
    ]
  end

  defp filtered_certificates(certs, "all", ""), do: certs

  defp filtered_certificates(certs, filter_type, "") when filter_type != "all" do
    filter_atom = String.to_existing_atom(filter_type)
    Enum.filter(certs, &(&1.cert_type == filter_atom))
  end

  defp filtered_certificates(certs, "all", query) do
    normalized_query = query |> to_string() |> String.downcase()

    Enum.filter(certs, fn cert ->
      String.contains?(String.downcase(cert.common_name || ""), normalized_query) or
        String.contains?(String.downcase(cert.serial_number || ""), normalized_query) or
        String.contains?(String.downcase(cert.fingerprint || ""), normalized_query)
    end)
  end

  defp filtered_certificates(certs, filter_type, query) do
    certs
    |> filtered_certificates(filter_type, "")
    |> filtered_certificates("all", query)
  end

  defp normalize_filter_type(filter_type) when filter_type in @cert_type_filters, do: filter_type
  defp normalize_filter_type(_filter_type), do: "all"

  defp section_for(:cas), do: "cas"
  defp section_for(:new_ca), do: "new_ca"
  defp section_for(:ca_show), do: "cas"
  defp section_for(:ca_stats), do: "cas"
  defp section_for(:crl), do: "cas"
  defp section_for(:certificates), do: "certificates"
  defp section_for(:certificate_show), do: "certificates"
  defp section_for(:certificate_revoke), do: "certificates"
  defp section_for(:issue_certificate), do: "issue_certificate"
  defp section_for(:csr), do: "csr"
  defp section_for(:upload_csr), do: "upload_csr"
  defp section_for(:search), do: "search"
  defp section_for(:analytics), do: "analytics"
  defp section_for(_action), do: "overview"

  defp page_title_for("overview", _action), do: "PKI Overview"
  defp page_title_for("cas", :ca_show), do: "CA Details"
  defp page_title_for("cas", :ca_stats), do: "CA Statistics"
  defp page_title_for("cas", :crl), do: "Certificate Revocation List"
  defp page_title_for("cas", _action), do: "CA List"
  defp page_title_for("new_ca", _action), do: "New CA"
  defp page_title_for("certificates", :certificate_show), do: "Certificate Details"
  defp page_title_for("certificates", _action), do: "Certificate List"
  defp page_title_for("issue_certificate", _action), do: "Issue Certificate"
  defp page_title_for("csr", _action), do: "CSR Management"
  defp page_title_for("upload_csr", _action), do: "Upload CSR"
  defp page_title_for("search", _action), do: "PKI Search"
  defp page_title_for("analytics", _action), do: "PKI Analytics"

  defp tab_class(active, section) do
    [
      "inline-flex items-center gap-2 rounded-md border px-3 py-2 text-sm font-medium",
      if(active == section,
        do: "border-primary bg-primary text-primary-content",
        else: "border-outline-variant text-on-surface"
      )
    ]
  end

  defp show_vault_sealed_banner(socket) do
    socket
    |> assign(:vault_status, current_vault_status())
    |> assign(:validation_errors, [])
  end

  defp current_vault_status do
    case Process.whereis(SealState) do
      nil -> @sealed_vault_status
      _pid -> SealState.status()
    end
  catch
    :exit, _reason -> @sealed_vault_status
  end

  defp positive_integer(value, label) do
    integer = String.to_integer(to_string(value))

    if integer > 0 do
      {:ok, integer}
    else
      {:error, "#{label} must be greater than 0"}
    end
  rescue
    ArgumentError -> {:error, "#{label} must be a positive integer"}
  end

  defp parent_ca_id(parent_ca_id) when parent_ca_id in [nil, ""] do
    {:error, "Select a Parent CA before generating an Intermediate CA"}
  end

  defp parent_ca_id(parent_ca_id), do: {:ok, parent_ca_id}

  defp required_value(value, message) when value in [nil, ""], do: {:error, message}
  defp required_value(value, _message), do: {:ok, value}

  defp issue_cert_type(cert_type) when cert_type in @issue_cert_types do
    {:ok, String.to_existing_atom(cert_type)}
  end

  defp issue_cert_type(_cert_type), do: {:error, "Select a valid Certificate Template"}

  defp parse_key_type("ecdsa"), do: :ecdsa
  defp parse_key_type(_key_type), do: :rsa

  defp format_cert_type(:root_ca), do: "Root CA"
  defp format_cert_type(:intermediate_ca), do: "Intermediate CA"
  defp format_cert_type(:agent_client), do: "Agent Client"
  defp format_cert_type(:app_client), do: "App Client"
  defp format_cert_type(:admin_client), do: "Admin Client"
  defp format_cert_type(type), do: to_string(type)

  defp format_ca_error("Vault is sealed") do
    "Vault is sealed. Unseal the vault before generating CA certificates."
  end

  defp format_ca_error(reason) when is_binary(reason), do: reason
  defp format_ca_error(reason), do: inspect(reason)

  defp status_text(%{revoked: true}), do: "Revoked"
  defp status_text(cert), do: if(expired?(cert), do: "Expired", else: "Active")

  defp status_badge_variant(%{revoked: true}), do: "error"
  defp status_badge_variant(cert), do: if(expired?(cert), do: "warning", else: "success")

  defp expired?(%{valid_until: nil}), do: false

  defp expired?(%{valid_until: valid_until}),
    do: DateTime.compare(valid_until, DateTime.utc_now()) == :lt

  defp format_expiry(nil), do: "n/a"

  defp format_expiry(datetime) do
    datetime
    |> DateTime.to_date()
    |> Date.to_string()
  end

  defp format_datetime(nil), do: "n/a"
  defp format_datetime(%DateTime{} = datetime), do: DateTime.to_string(datetime)
  defp format_datetime(value), do: to_string(value)

  defp short_serial(nil), do: "n/a"

  defp short_serial(serial) do
    serial = to_string(serial)

    if String.length(serial) > 18 do
      "#{String.slice(serial, 0, 18)}..."
    else
      serial
    end
  end

  defp metadata_value(%{metadata: metadata}, key) when is_map(metadata) do
    Map.get(metadata, key) || Map.get(metadata, Atom.to_string(key)) || ""
  end

  defp metadata_value(_event, _key), do: ""

  defp event_type_rows(events_by_type) when is_map(events_by_type) do
    events_by_type
    |> Enum.map(fn {type, count} -> %{type: to_string(type), count: count} end)
    |> Enum.sort_by(& &1.type)
  end

  defp event_type_rows(_events_by_type), do: []

  defp expiring_certificates(certificates, days) do
    deadline = DateTime.utc_now() |> DateTime.add(days, :day)

    Enum.filter(certificates, fn certificate ->
      (not certificate.revoked and certificate.valid_until) &&
        DateTime.compare(certificate.valid_until, deadline) in [:lt, :eq]
    end)
  end

  defp x509_extensions(cert) do
    case :public_key.pem_decode(cert.certificate_pem) do
      [{:Certificate, der, _} | _] ->
        der
        |> :public_key.der_decode(:Certificate)
        |> then(&elem(&1, 1))
        |> then(&elem(&1, 10))
        |> format_extensions()

      _ ->
        []
    end
  rescue
    _ -> []
  end

  defp format_extensions(:asn1_NOVALUE), do: []

  defp format_extensions(extensions) when is_list(extensions) do
    Enum.map(extensions, fn {:Extension, oid, critical, value} ->
      name = extension_name(oid)

      %{
        name: name,
        critical: critical,
        value: extension_value(name, value)
      }
    end)
  end

  defp format_extensions(_), do: []

  defp extension_name({2, 5, 29, 14}), do: "X509v3 Subject Key Identifier"
  defp extension_name({2, 5, 29, 15}), do: "X509v3 Key Usage"
  defp extension_name({2, 5, 29, 19}), do: "X509v3 Basic Constraints"
  defp extension_name(oid), do: "OID #{format_oid(oid)}"

  defp extension_value("X509v3 Basic Constraints", {:BasicConstraints, true, _}), do: "CA:TRUE"
  defp extension_value("X509v3 Basic Constraints", {:BasicConstraints, false, _}), do: "CA:FALSE"

  defp extension_value("X509v3 Basic Constraints", value) when is_binary(value) do
    case :public_key.der_decode(:BasicConstraints, value) do
      {:BasicConstraints, ca?, _} -> "CA:#{String.upcase(to_string(ca?))}"
      _ -> format_extension_binary(value)
    end
  rescue
    _ -> format_extension_binary(value)
  end

  defp extension_value("X509v3 Key Usage", <<3, 2, 1, 6>>), do: "Certificate Sign, CRL Sign"

  defp extension_value("X509v3 Key Usage", <<3, 2, 5, 160>>),
    do: "Digital Signature, Key Encipherment"

  defp extension_value("X509v3 Subject Key Identifier", <<4, 20, key_id::binary-size(20)>>) do
    format_extension_binary(key_id)
  end

  defp extension_value(_name, value) when is_binary(value), do: format_extension_binary(value)
  defp extension_value(_name, value), do: inspect(value)

  defp format_oid(oid) when is_tuple(oid) do
    oid
    |> Tuple.to_list()
    |> Enum.join(".")
  end

  defp format_extension_binary(value) do
    value
    |> Base.encode16(case: :lower)
    |> String.graphemes()
    |> Enum.chunk_every(2)
    |> Enum.join(":")
  end
end
