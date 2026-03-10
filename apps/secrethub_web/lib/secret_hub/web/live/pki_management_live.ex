defmodule SecretHub.Web.PKIManagementLive do
  @moduledoc """
  LiveView for PKI (Public Key Infrastructure) management.

  Features:
  - Generate Root and Intermediate CAs
  - View certificate hierarchy
  - Search and filter certificates
  - Revoke certificates
  - View certificate details (validity, fingerprints, extensions)
  """

  use SecretHub.Web, :live_view
  require Logger

  alias SecretHub.Core.PKI.CA

  @impl true
  def mount(_params, _session, socket) do
    certificates = list_certificates()
    stats = get_pki_stats(certificates)

    socket =
      socket
      |> assign(:certificates, certificates)
      |> assign(:stats, stats)
      |> assign(:selected_cert, nil)
      |> assign(:show_ca_form, false)
      |> assign(:ca_form_type, :root)
      |> assign(:ca_form_data, %{
        "common_name" => "",
        "organization" => "SecretHub",
        "country" => "US",
        "key_type" => "rsa",
        "key_bits" => "4096",
        "ttl_days" => "3650"
      })
      |> assign(:validation_errors, [])
      |> assign(:filter_type, "all")
      |> assign(:search_query, "")
      |> assign(:page_title, "PKI Management")

    {:ok, socket}
  end

  @impl true
  def handle_event("new_root_ca", _params, socket) do
    socket =
      socket
      |> assign(:show_ca_form, true)
      |> assign(:ca_form_type, :root)
      |> assign(:ca_form_data, %{
        "common_name" => "SecretHub Root CA",
        "organization" => "SecretHub",
        "country" => "US",
        "key_type" => "rsa",
        "key_bits" => "4096",
        "ttl_days" => "3650"
      })

    {:noreply, socket}
  end

  @impl true
  def handle_event("new_intermediate_ca", _params, socket) do
    socket =
      socket
      |> assign(:show_ca_form, true)
      |> assign(:ca_form_type, :intermediate)
      |> assign(:ca_form_data, %{
        "common_name" => "SecretHub Intermediate CA",
        "organization" => "SecretHub",
        "country" => "US",
        "key_type" => "rsa",
        "key_bits" => "2048",
        "ttl_days" => "1825"
      })

    {:noreply, socket}
  end

  @impl true
  def handle_event("generate_ca", %{"ca" => ca_params}, socket) do
    case socket.assigns.ca_form_type do
      :root ->
        generate_root_ca(socket, ca_params)

      :intermediate ->
        generate_intermediate_ca(socket, ca_params)
    end
  end

  @impl true
  def handle_event("cancel_ca_form", _params, socket) do
    socket =
      socket
      |> assign(:show_ca_form, false)
      |> assign(:validation_errors, [])

    {:noreply, socket}
  end

  @impl true
  def handle_event("view_certificate", %{"cert_id" => cert_id}, socket) do
    case CA.get_certificate(cert_id) do
      {:ok, certificate} ->
        {:noreply, assign(socket, :selected_cert, certificate)}

      {:error, _reason} ->
        socket = put_flash(socket, :error, "Failed to load certificate")
        {:noreply, socket}
    end
  end

  @impl true
  def handle_event("close_certificate_details", _params, socket) do
    {:noreply, assign(socket, :selected_cert, nil)}
  end

  @impl true
  def handle_event("revoke_certificate", %{"cert_id" => cert_id}, socket) do
    case CA.revoke_certificate(cert_id) do
      {:ok, _certificate} ->
        certificates = list_certificates()
        stats = get_pki_stats(certificates)

        socket =
          socket
          |> assign(:certificates, certificates)
          |> assign(:stats, stats)
          |> assign(:selected_cert, nil)
          |> put_flash(:info, "Certificate revoked successfully")

        {:noreply, socket}

      {:error, reason} ->
        socket = put_flash(socket, :error, "Failed to revoke certificate: #{inspect(reason)}")
        {:noreply, socket}
    end
  end

  @impl true
  def handle_event("filter_certificates", %{"filter_type" => filter_type}, socket) do
    {:noreply, assign(socket, :filter_type, filter_type)}
  end

  @impl true
  def handle_event("search_certificates", %{"query" => query}, socket) do
    {:noreply, assign(socket, :search_query, query)}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div class="mb-8">
        <h1 class="text-3xl font-bold text-on-surface">PKI Management</h1>
        <p class="mt-2 text-sm text-on-surface-variant">
          Manage Certificate Authorities and certificates for mTLS authentication.
        </p>
      </div>
      
    <!-- Statistics Cards -->
      <div class="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4 mb-8">
        <div class="bg-surface-container overflow-hidden shadow rounded-lg">
          <div class="p-5">
            <div class="flex items-center">
              <div class="flex-shrink-0">
                <svg
                  class="h-6 w-6 text-on-surface-variant"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    stroke-width="2"
                    d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                  />
                </svg>
              </div>
              <div class="ml-5 w-0 flex-1">
                <dl>
                  <dt class="text-sm font-medium text-on-surface-variant truncate">Total Certificates</dt>
                  <dd class="text-lg font-semibold text-on-surface">{@stats.total}</dd>
                </dl>
              </div>
            </div>
          </div>
        </div>

        <div class="bg-surface-container overflow-hidden shadow rounded-lg">
          <div class="p-5">
            <div class="flex items-center">
              <div class="flex-shrink-0">
                <svg
                  class="h-6 w-6 text-success"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    stroke-width="2"
                    d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
                  />
                </svg>
              </div>
              <div class="ml-5 w-0 flex-1">
                <dl>
                  <dt class="text-sm font-medium text-on-surface-variant truncate">Active</dt>
                  <dd class="text-lg font-semibold text-on-surface">{@stats.active}</dd>
                </dl>
              </div>
            </div>
          </div>
        </div>

        <div class="bg-surface-container overflow-hidden shadow rounded-lg">
          <div class="p-5">
            <div class="flex items-center">
              <div class="flex-shrink-0">
                <svg
                  class="h-6 w-6 text-error"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    stroke-width="2"
                    d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z"
                  />
                </svg>
              </div>
              <div class="ml-5 w-0 flex-1">
                <dl>
                  <dt class="text-sm font-medium text-on-surface-variant truncate">Revoked</dt>
                  <dd class="text-lg font-semibold text-on-surface">{@stats.revoked}</dd>
                </dl>
              </div>
            </div>
          </div>
        </div>

        <div class="bg-surface-container overflow-hidden shadow rounded-lg">
          <div class="p-5">
            <div class="flex items-center">
              <div class="flex-shrink-0">
                <svg
                  class="h-6 w-6 text-primary"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    stroke-width="2"
                    d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4"
                  />
                </svg>
              </div>
              <div class="ml-5 w-0 flex-1">
                <dl>
                  <dt class="text-sm font-medium text-on-surface-variant truncate">CAs</dt>
                  <dd class="text-lg font-semibold text-on-surface">{@stats.cas}</dd>
                </dl>
              </div>
            </div>
          </div>
        </div>
      </div>
      
    <!-- Action Buttons -->
      <div class="mb-6 flex gap-3">
        <button
          phx-click="new_root_ca"
          class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-on-primary bg-primary hover:bg-primary focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary"
        >
          <svg class="-ml-1 mr-2 h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path
              stroke-linecap="round"
              stroke-linejoin="round"
              stroke-width="2"
              d="M12 6v6m0 0v6m0-6h6m-6 0H6"
            />
          </svg>
          Generate Root CA
        </button>

        <button
          phx-click="new_intermediate_ca"
          class="inline-flex items-center px-4 py-2 border border-outline-variant shadow-sm text-sm font-medium rounded-md text-on-surface bg-surface-container hover:bg-surface-container-low focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary"
        >
          <svg class="-ml-1 mr-2 h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path
              stroke-linecap="round"
              stroke-linejoin="round"
              stroke-width="2"
              d="M12 6v6m0 0v6m0-6h6m-6 0H6"
            />
          </svg>
          Generate Intermediate CA
        </button>
      </div>
      
    <!-- CA Generation Form Modal -->
      <%= if @show_ca_form do %>
        <div class="fixed inset-0 bg-surface-container-low0 bg-opacity-75 z-40 flex items-center justify-center p-4">
          <div class="bg-surface-container rounded-lg shadow-xl max-w-2xl w-full">
            <div class="px-6 py-4 border-b border-outline-variant">
              <h3 class="text-lg font-medium text-on-surface">
                {if @ca_form_type == :root, do: "Generate Root CA", else: "Generate Intermediate CA"}
              </h3>
            </div>

            <form phx-submit="generate_ca" class="px-6 py-4 space-y-4">
              <div>
                <label class="block text-sm font-medium text-on-surface">Common Name</label>
                <input
                  type="text"
                  name="ca[common_name]"
                  value={@ca_form_data["common_name"]}
                  required
                  class="mt-1 block w-full border border-outline-variant rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-primary focus:border-primary sm:text-sm"
                />
              </div>

              <div class="grid grid-cols-2 gap-4">
                <div>
                  <label class="block text-sm font-medium text-on-surface">Organization</label>
                  <input
                    type="text"
                    name="ca[organization]"
                    value={@ca_form_data["organization"]}
                    required
                    class="mt-1 block w-full border border-outline-variant rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-primary focus:border-primary sm:text-sm"
                  />
                </div>

                <div>
                  <label class="block text-sm font-medium text-on-surface">Country</label>
                  <input
                    type="text"
                    name="ca[country]"
                    value={@ca_form_data["country"]}
                    maxlength="2"
                    required
                    class="mt-1 block w-full border border-outline-variant rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-primary focus:border-primary sm:text-sm"
                  />
                </div>
              </div>

              <div class="grid grid-cols-2 gap-4">
                <div>
                  <label class="block text-sm font-medium text-on-surface">Key Type</label>
                  <select
                    name="ca[key_type]"
                    class="mt-1 block w-full border border-outline-variant rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-primary focus:border-primary sm:text-sm"
                  >
                    <option value="rsa" selected={@ca_form_data["key_type"] == "rsa"}>RSA</option>
                    <option value="ecdsa" selected={@ca_form_data["key_type"] == "ecdsa"}>
                      ECDSA
                    </option>
                  </select>
                </div>

                <div>
                  <label class="block text-sm font-medium text-on-surface">Key Bits</label>
                  <select
                    name="ca[key_bits]"
                    class="mt-1 block w-full border border-outline-variant rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-primary focus:border-primary sm:text-sm"
                  >
                    <option value="2048" selected={@ca_form_data["key_bits"] == "2048"}>
                      2048
                    </option>
                    <option value="4096" selected={@ca_form_data["key_bits"] == "4096"}>
                      4096
                    </option>
                  </select>
                </div>
              </div>

              <div>
                <label class="block text-sm font-medium text-on-surface">
                  TTL (days)
                </label>
                <input
                  type="number"
                  name="ca[ttl_days]"
                  value={@ca_form_data["ttl_days"]}
                  required
                  class="mt-1 block w-full border border-outline-variant rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-primary focus:border-primary sm:text-sm"
                />
              </div>

              <%= if !Enum.empty?(@validation_errors) do %>
                <div class="bg-error/5 border-l-4 border-red-400 p-4">
                  <ul class="text-sm text-error list-disc list-inside">
                    <%= for error <- @validation_errors do %>
                      <li>{error}</li>
                    <% end %>
                  </ul>
                </div>
              <% end %>

              <div class="flex justify-end space-x-3 pt-4">
                <button
                  type="button"
                  phx-click="cancel_ca_form"
                  class="inline-flex items-center px-4 py-2 border border-outline-variant shadow-sm text-sm font-medium rounded-md text-on-surface bg-surface-container hover:bg-surface-container-low"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-on-primary bg-primary hover:bg-primary"
                >
                  Generate CA
                </button>
              </div>
            </form>
          </div>
        </div>
      <% end %>
      
    <!-- Filters and Search -->
      <div class="bg-surface-container p-4 rounded-lg shadow mb-6">
        <div class="flex gap-4 items-center">
          <div class="flex items-center space-x-2">
            <label class="text-sm font-medium text-on-surface">Type:</label>
            <select
              phx-change="filter_certificates"
              name="filter_type"
              class="form-select rounded-md border-outline-variant"
            >
              <option value="all">All</option>
              <option value="root_ca">Root CA</option>
              <option value="intermediate_ca">Intermediate CA</option>
              <option value="agent_client">Agent Client</option>
              <option value="app_client">App Client</option>
              <option value="admin_client">Admin Client</option>
            </select>
          </div>

          <div class="flex items-center space-x-2 flex-1">
            <label class="text-sm font-medium text-on-surface">Search:</label>
            <input
              type="text"
              phx-change="search_certificates"
              name="query"
              value={@search_query}
              placeholder="Search by common name or serial..."
              class="form-input flex-1 rounded-md border-outline-variant"
            />
          </div>
        </div>
      </div>
      
    <!-- Certificates List -->
      <div class="bg-surface-container shadow overflow-hidden sm:rounded-md">
        <ul role="list" class="divide-y divide-outline-variant">
          <%= if Enum.empty?(filtered_certificates(@certificates, @filter_type, @search_query)) do %>
            <li class="px-6 py-12 text-center">
              <p class="text-on-surface-variant">No certificates found.</p>
            </li>
          <% else %>
            <%= for cert <- filtered_certificates(@certificates, @filter_type, @search_query) do %>
              <li class="px-6 py-4 hover:bg-surface-container-low">
                <div class="flex items-center justify-between">
                  <div class="flex-1">
                    <div class="flex items-center">
                      <div class="flex-shrink-0">
                        <div class={"h-10 w-10 rounded-full flex items-center justify-center #{cert_type_bg_color(cert.cert_type)}"}>
                          <svg
                            class={"h-6 w-6 #{cert_type_icon_color(cert.cert_type)}"}
                            fill="none"
                            stroke="currentColor"
                            viewBox="0 0 24 24"
                          >
                            <path
                              stroke-linecap="round"
                              stroke-linejoin="round"
                              stroke-width="2"
                              d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                            />
                          </svg>
                        </div>
                      </div>
                      <div class="ml-4">
                        <div class="text-sm font-medium text-on-surface">{cert.common_name}</div>
                        <div class="text-sm text-on-surface-variant">
                          Serial:
                          <span class="font-mono text-xs">
                            {String.slice(cert.serial_number, 0..15)}...
                          </span>
                        </div>
                        <div class="mt-1 flex items-center gap-2">
                          <span class={"inline-flex items-center px-2 py-0.5 rounded text-xs font-medium #{cert_type_badge_color(cert.cert_type)}"}>
                            {format_cert_type(cert.cert_type)}
                          </span>
                          <%= if cert.revoked do %>
                            <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-error/10 text-error">
                              Revoked
                            </span>
                          <% else %>
                            <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-success/10 text-success">
                              Active
                            </span>
                          <% end %>
                          <span class="text-xs text-on-surface-variant">
                            Expires: {format_expiry(cert.not_after)}
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>
                  <div class="ml-4 flex-shrink-0 flex space-x-2">
                    <button
                      phx-click="view_certificate"
                      phx-value-cert_id={cert.id}
                      class="inline-flex items-center px-3 py-1.5 border border-outline-variant shadow-sm text-xs font-medium rounded text-on-surface bg-surface-container hover:bg-surface-container-low"
                    >
                      View Details
                    </button>
                    <%= if !cert.revoked and cert.cert_type not in [:root_ca, :intermediate_ca] do %>
                      <button
                        phx-click="revoke_certificate"
                        phx-value-cert_id={cert.id}
                        data-confirm="Are you sure you want to revoke this certificate?"
                        class="inline-flex items-center px-3 py-1.5 border border-red-300 shadow-sm text-xs font-medium rounded text-error bg-surface-container hover:bg-error/5"
                      >
                        Revoke
                      </button>
                    <% end %>
                  </div>
                </div>
              </li>
            <% end %>
          <% end %>
        </ul>
      </div>
      
    <!-- Certificate Details Modal -->
      <%= if @selected_cert do %>
        <div class="fixed inset-0 bg-surface-container-low0 bg-opacity-75 z-40 flex items-center justify-center p-4">
          <div class="bg-surface-container rounded-lg shadow-xl max-w-4xl w-full max-h-[90vh] overflow-y-auto">
            <div class="px-6 py-4 border-b border-outline-variant flex justify-between items-center">
              <h3 class="text-lg font-medium text-on-surface">Certificate Details</h3>
              <button
                phx-click="close_certificate_details"
                class="text-on-surface-variant hover:text-on-surface-variant"
              >
                <svg class="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    stroke-width="2"
                    d="M6 18L18 6M6 6l12 12"
                  />
                </svg>
              </button>
            </div>

            <div class="px-6 py-4 space-y-4">
              <div class="grid grid-cols-2 gap-4">
                <div>
                  <label class="block text-sm font-medium text-on-surface-variant">Common Name</label>
                  <p class="mt-1 text-sm text-on-surface">{@selected_cert.common_name}</p>
                </div>
                <div>
                  <label class="block text-sm font-medium text-on-surface-variant">Type</label>
                  <p class="mt-1 text-sm text-on-surface">
                    {format_cert_type(@selected_cert.cert_type)}
                  </p>
                </div>
              </div>

              <div class="grid grid-cols-2 gap-4">
                <div>
                  <label class="block text-sm font-medium text-on-surface-variant">Serial Number</label>
                  <p class="mt-1 text-sm font-mono text-on-surface break-all">
                    {@selected_cert.serial_number}
                  </p>
                </div>
                <div>
                  <label class="block text-sm font-medium text-on-surface-variant">Fingerprint (SHA-256)</label>
                  <p class="mt-1 text-sm font-mono text-on-surface break-all">
                    {@selected_cert.fingerprint_sha256}
                  </p>
                </div>
              </div>

              <div class="grid grid-cols-2 gap-4">
                <div>
                  <label class="block text-sm font-medium text-on-surface-variant">Valid From</label>
                  <p class="mt-1 text-sm text-on-surface">
                    {DateTime.to_string(@selected_cert.not_before)}
                  </p>
                </div>
                <div>
                  <label class="block text-sm font-medium text-on-surface-variant">Valid Until</label>
                  <p class="mt-1 text-sm text-on-surface">
                    {DateTime.to_string(@selected_cert.not_after)}
                  </p>
                </div>
              </div>

              <div>
                <label class="block text-sm font-medium text-on-surface-variant">Status</label>
                <p class="mt-1">
                  <%= if @selected_cert.revoked do %>
                    <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-error/10 text-error">
                      Revoked at {DateTime.to_string(@selected_cert.revoked_at)}
                    </span>
                  <% else %>
                    <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-success/10 text-success">
                      Active
                    </span>
                  <% end %>
                </p>
              </div>

              <div>
                <label class="block text-sm font-medium text-on-surface-variant mb-2">
                  Certificate PEM
                </label>
                <pre class="bg-surface-container-low p-4 rounded-md overflow-x-auto text-xs font-mono border border-outline-variant">{@selected_cert.certificate_pem}</pre>
              </div>
            </div>
          </div>
        </div>
      <% end %>
    </div>
    """
  end

  # Private functions

  defp generate_root_ca(socket, ca_params) do
    ttl_days = String.to_integer(ca_params["ttl_days"])
    key_bits = String.to_integer(ca_params["key_bits"])

    key_type =
      case ca_params["key_type"] do
        "rsa" -> :rsa
        "ecdsa" -> :ecdsa
        _ -> :rsa
      end

    case CA.generate_root_ca(
           ca_params["common_name"],
           ca_params["organization"],
           country: ca_params["country"],
           key_type: key_type,
           key_size: key_bits,
           validity_days: ttl_days
         ) do
      {:ok, _certificate} ->
        certificates = list_certificates()
        stats = get_pki_stats(certificates)

        socket =
          socket
          |> assign(:certificates, certificates)
          |> assign(:stats, stats)
          |> assign(:show_ca_form, false)
          |> put_flash(:info, "Root CA generated successfully")

        {:noreply, socket}

      {:error, reason} ->
        socket =
          socket
          |> assign(:validation_errors, [inspect(reason)])
          |> put_flash(:error, "Failed to generate Root CA")

        {:noreply, socket}
    end
  end

  defp generate_intermediate_ca(socket, ca_params) do
    ttl_days = String.to_integer(ca_params["ttl_days"])
    key_bits = String.to_integer(ca_params["key_bits"])

    key_type =
      case ca_params["key_type"] do
        "rsa" -> :rsa
        "ecdsa" -> :ecdsa
        _ -> :rsa
      end

    # TODO: Get root CA certificate ID from database
    root_ca_cert_id = nil

    case CA.generate_intermediate_ca(
           ca_params["common_name"],
           ca_params["organization"],
           root_ca_cert_id,
           country: ca_params["country"],
           key_type: key_type,
           key_bits: key_bits,
           ttl_days: ttl_days
         ) do
      {:ok, _certificate} ->
        certificates = list_certificates()
        stats = get_pki_stats(certificates)

        socket =
          socket
          |> assign(:certificates, certificates)
          |> assign(:stats, stats)
          |> assign(:show_ca_form, false)
          |> put_flash(:info, "Intermediate CA generated successfully")

        {:noreply, socket}

      {:error, reason} ->
        socket =
          socket
          |> assign(:validation_errors, [inspect(reason)])
          |> put_flash(:error, "Failed to generate Intermediate CA")

        {:noreply, socket}
    end
  end

  defp list_certificates do
    case CA.list_certificates() do
      {:ok, certificates} -> certificates
      {:error, _} -> []
      # Handle when CA returns raw list instead of tuple
      certificates when is_list(certificates) -> certificates
    end
  end

  defp get_pki_stats(certificates) do
    total = length(certificates)
    revoked = Enum.count(certificates, & &1.revoked)
    active = total - revoked
    cas = Enum.count(certificates, &(&1.cert_type in [:root_ca, :intermediate_ca]))

    %{
      total: total,
      active: active,
      revoked: revoked,
      cas: cas
    }
  end

  defp filtered_certificates(certs, "all", ""), do: certs

  defp filtered_certificates(certs, filter_type, "") when filter_type != "all" do
    filter_atom = String.to_existing_atom(filter_type)
    Enum.filter(certs, &(&1.cert_type == filter_atom))
  end

  defp filtered_certificates(certs, "all", query) do
    query = String.downcase(query)

    Enum.filter(certs, fn cert ->
      String.contains?(String.downcase(cert.common_name), query) or
        String.contains?(String.downcase(cert.serial_number), query)
    end)
  end

  defp filtered_certificates(certs, filter_type, query) do
    certs
    |> filtered_certificates(filter_type, "")
    |> filtered_certificates("all", query)
  end

  defp format_cert_type(:root_ca), do: "Root CA"
  defp format_cert_type(:intermediate_ca), do: "Intermediate CA"
  defp format_cert_type(:agent_client), do: "Agent Client"
  defp format_cert_type(:app_client), do: "App Client"
  defp format_cert_type(:admin_client), do: "Admin Client"
  defp format_cert_type(type), do: to_string(type)

  defp cert_type_badge_color(:root_ca), do: "bg-tertiary/10 text-tertiary"
  defp cert_type_badge_color(:intermediate_ca), do: "bg-secondary/10 text-secondary"
  defp cert_type_badge_color(:agent_client), do: "bg-primary/10 text-primary"
  defp cert_type_badge_color(:app_client), do: "bg-success/10 text-success"
  defp cert_type_badge_color(:admin_client), do: "bg-warning/10 text-warning"
  defp cert_type_badge_color(_), do: "bg-surface-container text-on-surface"

  defp cert_type_bg_color(:root_ca), do: "bg-tertiary/10"
  defp cert_type_bg_color(:intermediate_ca), do: "bg-secondary/10"
  defp cert_type_bg_color(_), do: "bg-primary/10"

  defp cert_type_icon_color(:root_ca), do: "text-tertiary"
  defp cert_type_icon_color(:intermediate_ca), do: "text-secondary"
  defp cert_type_icon_color(_), do: "text-primary"

  defp format_expiry(datetime) do
    datetime
    |> DateTime.to_date()
    |> Date.to_string()
  end
end
