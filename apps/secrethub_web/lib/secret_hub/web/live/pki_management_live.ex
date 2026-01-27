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
        <h1 class="text-3xl font-bold text-gray-900">PKI Management</h1>
        <p class="mt-2 text-sm text-gray-600">
          Manage Certificate Authorities and certificates for mTLS authentication.
        </p>
      </div>
      
    <!-- Statistics Cards -->
      <div class="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4 mb-8">
        <div class="bg-white overflow-hidden shadow rounded-lg">
          <div class="p-5">
            <div class="flex items-center">
              <div class="flex-shrink-0">
                <svg
                  class="h-6 w-6 text-gray-400"
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
                  <dt class="text-sm font-medium text-gray-500 truncate">Total Certificates</dt>
                  <dd class="text-lg font-semibold text-gray-900">{@stats.total}</dd>
                </dl>
              </div>
            </div>
          </div>
        </div>

        <div class="bg-white overflow-hidden shadow rounded-lg">
          <div class="p-5">
            <div class="flex items-center">
              <div class="flex-shrink-0">
                <svg
                  class="h-6 w-6 text-green-400"
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
                  <dt class="text-sm font-medium text-gray-500 truncate">Active</dt>
                  <dd class="text-lg font-semibold text-gray-900">{@stats.active}</dd>
                </dl>
              </div>
            </div>
          </div>
        </div>

        <div class="bg-white overflow-hidden shadow rounded-lg">
          <div class="p-5">
            <div class="flex items-center">
              <div class="flex-shrink-0">
                <svg
                  class="h-6 w-6 text-red-400"
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
                  <dt class="text-sm font-medium text-gray-500 truncate">Revoked</dt>
                  <dd class="text-lg font-semibold text-gray-900">{@stats.revoked}</dd>
                </dl>
              </div>
            </div>
          </div>
        </div>

        <div class="bg-white overflow-hidden shadow rounded-lg">
          <div class="p-5">
            <div class="flex items-center">
              <div class="flex-shrink-0">
                <svg
                  class="h-6 w-6 text-blue-400"
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
                  <dt class="text-sm font-medium text-gray-500 truncate">CAs</dt>
                  <dd class="text-lg font-semibold text-gray-900">{@stats.cas}</dd>
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
          class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
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
          class="inline-flex items-center px-4 py-2 border border-gray-300 shadow-sm text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
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
        <div class="fixed inset-0 bg-gray-500 bg-opacity-75 z-40 flex items-center justify-center p-4">
          <div class="bg-white rounded-lg shadow-xl max-w-2xl w-full">
            <div class="px-6 py-4 border-b border-gray-200">
              <h3 class="text-lg font-medium text-gray-900">
                {if @ca_form_type == :root, do: "Generate Root CA", else: "Generate Intermediate CA"}
              </h3>
            </div>

            <form phx-submit="generate_ca" class="px-6 py-4 space-y-4">
              <div>
                <label class="block text-sm font-medium text-gray-700">Common Name</label>
                <input
                  type="text"
                  name="ca[common_name]"
                  value={@ca_form_data["common_name"]}
                  required
                  class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                />
              </div>

              <div class="grid grid-cols-2 gap-4">
                <div>
                  <label class="block text-sm font-medium text-gray-700">Organization</label>
                  <input
                    type="text"
                    name="ca[organization]"
                    value={@ca_form_data["organization"]}
                    required
                    class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                  />
                </div>

                <div>
                  <label class="block text-sm font-medium text-gray-700">Country</label>
                  <input
                    type="text"
                    name="ca[country]"
                    value={@ca_form_data["country"]}
                    maxlength="2"
                    required
                    class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                  />
                </div>
              </div>

              <div class="grid grid-cols-2 gap-4">
                <div>
                  <label class="block text-sm font-medium text-gray-700">Key Type</label>
                  <select
                    name="ca[key_type]"
                    class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                  >
                    <option value="rsa" selected={@ca_form_data["key_type"] == "rsa"}>RSA</option>
                    <option value="ecdsa" selected={@ca_form_data["key_type"] == "ecdsa"}>
                      ECDSA
                    </option>
                  </select>
                </div>

                <div>
                  <label class="block text-sm font-medium text-gray-700">Key Bits</label>
                  <select
                    name="ca[key_bits]"
                    class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
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
                <label class="block text-sm font-medium text-gray-700">
                  TTL (days)
                </label>
                <input
                  type="number"
                  name="ca[ttl_days]"
                  value={@ca_form_data["ttl_days"]}
                  required
                  class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                />
              </div>

              <%= if !Enum.empty?(@validation_errors) do %>
                <div class="bg-red-50 border-l-4 border-red-400 p-4">
                  <ul class="text-sm text-red-700 list-disc list-inside">
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
                  class="inline-flex items-center px-4 py-2 border border-gray-300 shadow-sm text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700"
                >
                  Generate CA
                </button>
              </div>
            </form>
          </div>
        </div>
      <% end %>
      
    <!-- Filters and Search -->
      <div class="bg-white p-4 rounded-lg shadow mb-6">
        <div class="flex gap-4 items-center">
          <div class="flex items-center space-x-2">
            <label class="text-sm font-medium text-gray-700">Type:</label>
            <select
              phx-change="filter_certificates"
              name="filter_type"
              class="form-select rounded-md border-gray-300"
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
            <label class="text-sm font-medium text-gray-700">Search:</label>
            <input
              type="text"
              phx-change="search_certificates"
              name="query"
              value={@search_query}
              placeholder="Search by common name or serial..."
              class="form-input flex-1 rounded-md border-gray-300"
            />
          </div>
        </div>
      </div>
      
    <!-- Certificates List -->
      <div class="bg-white shadow overflow-hidden sm:rounded-md">
        <ul role="list" class="divide-y divide-gray-200">
          <%= if Enum.empty?(filtered_certificates(@certificates, @filter_type, @search_query)) do %>
            <li class="px-6 py-12 text-center">
              <p class="text-gray-500">No certificates found.</p>
            </li>
          <% else %>
            <%= for cert <- filtered_certificates(@certificates, @filter_type, @search_query) do %>
              <li class="px-6 py-4 hover:bg-gray-50">
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
                        <div class="text-sm font-medium text-gray-900">{cert.common_name}</div>
                        <div class="text-sm text-gray-500">
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
                            <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-red-100 text-red-800">
                              Revoked
                            </span>
                          <% else %>
                            <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800">
                              Active
                            </span>
                          <% end %>
                          <span class="text-xs text-gray-500">
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
                      class="inline-flex items-center px-3 py-1.5 border border-gray-300 shadow-sm text-xs font-medium rounded text-gray-700 bg-white hover:bg-gray-50"
                    >
                      View Details
                    </button>
                    <%= if !cert.revoked and cert.cert_type not in [:root_ca, :intermediate_ca] do %>
                      <button
                        phx-click="revoke_certificate"
                        phx-value-cert_id={cert.id}
                        data-confirm="Are you sure you want to revoke this certificate?"
                        class="inline-flex items-center px-3 py-1.5 border border-red-300 shadow-sm text-xs font-medium rounded text-red-700 bg-white hover:bg-red-50"
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
        <div class="fixed inset-0 bg-gray-500 bg-opacity-75 z-40 flex items-center justify-center p-4">
          <div class="bg-white rounded-lg shadow-xl max-w-4xl w-full max-h-[90vh] overflow-y-auto">
            <div class="px-6 py-4 border-b border-gray-200 flex justify-between items-center">
              <h3 class="text-lg font-medium text-gray-900">Certificate Details</h3>
              <button
                phx-click="close_certificate_details"
                class="text-gray-400 hover:text-gray-500"
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
                  <label class="block text-sm font-medium text-gray-500">Common Name</label>
                  <p class="mt-1 text-sm text-gray-900">{@selected_cert.common_name}</p>
                </div>
                <div>
                  <label class="block text-sm font-medium text-gray-500">Type</label>
                  <p class="mt-1 text-sm text-gray-900">
                    {format_cert_type(@selected_cert.cert_type)}
                  </p>
                </div>
              </div>

              <div class="grid grid-cols-2 gap-4">
                <div>
                  <label class="block text-sm font-medium text-gray-500">Serial Number</label>
                  <p class="mt-1 text-sm font-mono text-gray-900 break-all">
                    {@selected_cert.serial_number}
                  </p>
                </div>
                <div>
                  <label class="block text-sm font-medium text-gray-500">Fingerprint (SHA-256)</label>
                  <p class="mt-1 text-sm font-mono text-gray-900 break-all">
                    {@selected_cert.fingerprint_sha256}
                  </p>
                </div>
              </div>

              <div class="grid grid-cols-2 gap-4">
                <div>
                  <label class="block text-sm font-medium text-gray-500">Valid From</label>
                  <p class="mt-1 text-sm text-gray-900">
                    {DateTime.to_string(@selected_cert.not_before)}
                  </p>
                </div>
                <div>
                  <label class="block text-sm font-medium text-gray-500">Valid Until</label>
                  <p class="mt-1 text-sm text-gray-900">
                    {DateTime.to_string(@selected_cert.not_after)}
                  </p>
                </div>
              </div>

              <div>
                <label class="block text-sm font-medium text-gray-500">Status</label>
                <p class="mt-1">
                  <%= if @selected_cert.revoked do %>
                    <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-red-100 text-red-800">
                      Revoked at {DateTime.to_string(@selected_cert.revoked_at)}
                    </span>
                  <% else %>
                    <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800">
                      Active
                    </span>
                  <% end %>
                </p>
              </div>

              <div>
                <label class="block text-sm font-medium text-gray-500 mb-2">
                  Certificate PEM
                </label>
                <pre class="bg-gray-50 p-4 rounded-md overflow-x-auto text-xs font-mono border border-gray-200">{@selected_cert.certificate_pem}</pre>
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

  defp cert_type_badge_color(:root_ca), do: "bg-purple-100 text-purple-800"
  defp cert_type_badge_color(:intermediate_ca), do: "bg-indigo-100 text-indigo-800"
  defp cert_type_badge_color(:agent_client), do: "bg-blue-100 text-blue-800"
  defp cert_type_badge_color(:app_client), do: "bg-green-100 text-green-800"
  defp cert_type_badge_color(:admin_client), do: "bg-yellow-100 text-yellow-800"
  defp cert_type_badge_color(_), do: "bg-gray-100 text-gray-800"

  defp cert_type_bg_color(:root_ca), do: "bg-purple-100"
  defp cert_type_bg_color(:intermediate_ca), do: "bg-indigo-100"
  defp cert_type_bg_color(_), do: "bg-blue-100"

  defp cert_type_icon_color(:root_ca), do: "text-purple-600"
  defp cert_type_icon_color(:intermediate_ca), do: "text-indigo-600"
  defp cert_type_icon_color(_), do: "text-blue-600"

  defp format_expiry(datetime) do
    datetime
    |> DateTime.to_date()
    |> Date.to_string()
  end
end
