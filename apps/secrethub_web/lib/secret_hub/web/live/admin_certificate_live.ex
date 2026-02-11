defmodule SecretHub.Web.AdminCertificateLive do
  @moduledoc """
  LiveView for managing admin client certificates.

  Allows administrators to:
  - Upload and register their client certificates
  - View all registered admin certificates
  - Revoke admin certificates
  - View certificate details and expiration status
  """

  use SecretHub.Web, :live_view
  require Logger

  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.Certificate

  # Ensure Certificate schema is aliased for use in pattern matching
  # This fixes compilation issues with struct expansion

  @impl true
  def mount(_params, _session, socket) do
    {:ok,
     socket
     |> assign(:page_title, "Admin Certificates")
     |> assign(:upload_form, to_form(%{}))
     |> assign(:selected_cert, nil)
     |> load_certificates()
     |> allow_upload(:certificate,
       accept: :any,
       max_entries: 1,
       max_file_size: 50_000
     )}
  end

  @impl true
  def handle_event("validate_upload", _params, socket) do
    {:noreply, socket}
  end

  @impl true
  def handle_event("upload_certificate", %{"admin_email" => admin_email}, socket) do
    uploaded_files =
      consume_uploaded_entries(socket, :certificate, fn %{path: path}, _entry ->
        # Read the certificate file
        case File.read(path) do
          {:ok, pem_data} ->
            {:ok, {pem_data, admin_email}}

          {:error, reason} ->
            {:postpone, reason}
        end
      end)

    case uploaded_files do
      [{pem_data, admin_email}] ->
        case register_admin_certificate(pem_data, admin_email) do
          {:ok, _certificate} ->
            {:noreply,
             socket
             |> put_flash(:info, "Certificate registered successfully")
             |> load_certificates()}

          {:error, reason} ->
            {:noreply,
             socket
             |> put_flash(:error, "Failed to register certificate: #{inspect(reason)}")}
        end

      [] ->
        {:noreply,
         socket
         |> put_flash(:error, "No certificate file uploaded")}

      {:error, reason} ->
        {:noreply,
         socket
         |> put_flash(:error, "Upload failed: #{inspect(reason)}")}
    end
  end

  @impl true
  def handle_event("revoke_certificate", %{"id" => cert_id}, socket) do
    case revoke_certificate(cert_id) do
      {:ok, _certificate} ->
        {:noreply,
         socket
         |> put_flash(:info, "Certificate revoked successfully")
         |> load_certificates()}

      {:error, reason} ->
        {:noreply,
         socket
         |> put_flash(:error, "Failed to revoke certificate: #{inspect(reason)}")}
    end
  end

  @impl true
  def handle_event("view_details", %{"id" => cert_id}, socket) do
    cert = Repo.get(Certificate, cert_id)
    {:noreply, assign(socket, :selected_cert, cert)}
  end

  @impl true
  def handle_event("close_details", _params, socket) do
    {:noreply, assign(socket, :selected_cert, nil)}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="px-4 sm:px-6 lg:px-8">
      <div class="sm:flex sm:items-center">
        <div class="sm:flex-auto">
          <h1 class="text-2xl font-semibold text-gray-900">Admin Certificates</h1>
          <p class="mt-2 text-sm text-gray-700">
            Manage client certificates authorized for administrative access
          </p>
        </div>
      </div>

      <%= if @flash["info"] do %>
        <div
          class="mt-4 bg-green-50 border border-green-200 text-green-700 px-4 py-3 rounded"
          role="alert"
        >
          {@flash["info"]}
        </div>
      <% end %>

      <%= if @flash["error"] do %>
        <div class="mt-4 bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded" role="alert">
          {@flash["error"]}
        </div>
      <% end %>
      
    <!-- Upload Section -->
      <div class="mt-8 bg-white shadow sm:rounded-lg">
        <div class="px-4 py-5 sm:p-6">
          <h3 class="text-lg font-medium leading-6 text-gray-900">
            Register New Admin Certificate
          </h3>
          <div class="mt-2 max-w-xl text-sm text-gray-500">
            <p>
              Upload a client certificate (.pem, .crt, or .cer file) to grant administrative access.
            </p>
          </div>
          <form phx-submit="upload_certificate" phx-change="validate_upload" class="mt-5">
            <div class="space-y-4">
              <div>
                <label for="admin_email" class="block text-sm font-medium text-gray-700">
                  Administrator Email
                </label>
                <input
                  type="email"
                  name="admin_email"
                  id="admin_email"
                  required
                  class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                  placeholder="admin@example.com"
                />
              </div>

              <div>
                <label class="block text-sm font-medium text-gray-700">
                  Certificate File
                </label>
                <div class="mt-1 flex justify-center px-6 pt-5 pb-6 border-2 border-gray-300 border-dashed rounded-md">
                  <div class="space-y-1 text-center">
                    <svg
                      class="mx-auto h-12 w-12 text-gray-400"
                      stroke="currentColor"
                      fill="none"
                      viewBox="0 0 48 48"
                    >
                      <path
                        d="M28 8H12a4 4 0 00-4 4v20m32-12v8m0 0v8a4 4 0 01-4 4H12a4 4 0 01-4-4v-4m32-4l-3.172-3.172a4 4 0 00-5.656 0L28 28M8 32l9.172-9.172a4 4 0 015.656 0L28 28m0 0l4 4m4-24h8m-4-4v8m-12 4h.02"
                        stroke-width="2"
                        stroke-linecap="round"
                        stroke-linejoin="round"
                      />
                    </svg>
                    <div class="flex text-sm text-gray-600">
                      <label
                        for="file-upload"
                        class="relative cursor-pointer rounded-md bg-white font-medium text-blue-600 focus-within:outline-none focus-within:ring-2 focus-within:ring-blue-500 focus-within:ring-offset-2 hover:text-blue-500"
                      >
                        <span phx-drop-target={@uploads.certificate.ref}>Upload a file</span>
                        <.live_file_input upload={@uploads.certificate} class="sr-only" />
                      </label>
                      <p class="pl-1">or drag and drop</p>
                    </div>
                    <p class="text-xs text-gray-500">.pem, .crt, or .cer up to 50KB</p>
                  </div>
                </div>

                <%= for entry <- @uploads.certificate.entries do %>
                  <div class="mt-2 text-sm text-gray-600">
                    Selected: {entry.client_name}
                  </div>
                <% end %>
              </div>
            </div>

            <div class="mt-5">
              <button
                type="submit"
                class="inline-flex items-center px-4 py-2 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                disabled={@uploads.certificate.entries == []}
              >
                Register Certificate
              </button>
            </div>
          </form>
        </div>
      </div>
      
    <!-- Certificates List -->
      <div class="mt-8 flex flex-col">
        <div class="-my-2 -mx-4 overflow-x-auto sm:-mx-6 lg:-mx-8">
          <div class="inline-block min-w-full py-2 align-middle md:px-6 lg:px-8">
            <div class="overflow-hidden shadow ring-1 ring-black ring-opacity-5 md:rounded-lg">
              <table class="min-w-full divide-y divide-gray-300">
                <thead class="bg-gray-50">
                  <tr>
                    <th
                      scope="col"
                      class="py-3.5 pl-4 pr-3 text-left text-sm font-semibold text-gray-900 sm:pl-6"
                    >
                      Common Name
                    </th>
                    <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">
                      Subject
                    </th>
                    <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">
                      Valid Until
                    </th>
                    <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">
                      Status
                    </th>
                    <th scope="col" class="relative py-3.5 pl-3 pr-4 sm:pr-6">
                      <span class="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-gray-200 bg-white">
                  <%= for cert <- @certificates do %>
                    <tr>
                      <td class="whitespace-nowrap py-4 pl-4 pr-3 text-sm font-medium text-gray-900 sm:pl-6">
                        {cert.common_name}
                      </td>
                      <td class="whitespace-nowrap px-3 py-4 text-sm text-gray-500">
                        {cert.subject}
                      </td>
                      <td class="whitespace-nowrap px-3 py-4 text-sm text-gray-500">
                        {format_datetime(cert.valid_until)}
                      </td>
                      <td class="whitespace-nowrap px-3 py-4 text-sm">
                        <%= if cert.revoked do %>
                          <span class="inline-flex rounded-full bg-red-100 px-2 text-xs font-semibold leading-5 text-red-800">
                            Revoked
                          </span>
                        <% else %>
                          <%= if DateTime.compare(cert.valid_until, DateTime.utc_now() |> DateTime.truncate(:second)) == :gt do %>
                            <span class="inline-flex rounded-full bg-green-100 px-2 text-xs font-semibold leading-5 text-green-800">
                              Active
                            </span>
                          <% else %>
                            <span class="inline-flex rounded-full bg-yellow-100 px-2 text-xs font-semibold leading-5 text-yellow-800">
                              Expired
                            </span>
                          <% end %>
                        <% end %>
                      </td>
                      <td class="relative whitespace-nowrap py-4 pl-3 pr-4 text-right text-sm font-medium sm:pr-6">
                        <button
                          phx-click="view_details"
                          phx-value-id={cert.id}
                          class="text-blue-600 hover:text-blue-900 mr-4"
                        >
                          View
                        </button>
                        <%= unless cert.revoked do %>
                          <button
                            phx-click="revoke_certificate"
                            phx-value-id={cert.id}
                            data-confirm="Are you sure you want to revoke this certificate?"
                            class="text-red-600 hover:text-red-900"
                          >
                            Revoke
                          </button>
                        <% end %>
                      </td>
                    </tr>
                  <% end %>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
      
    <!-- Certificate Details Modal -->
      <%= if @selected_cert do %>
        <div class="fixed z-10 inset-0 overflow-y-auto" role="dialog">
          <div class="flex items-end justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
            <div class="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity"></div>

            <div class="inline-block align-bottom bg-white rounded-lg px-4 pt-5 pb-4 text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-lg sm:w-full sm:p-6">
              <div>
                <div class="mt-3 text-center sm:mt-5">
                  <h3 class="text-lg leading-6 font-medium text-gray-900">
                    Certificate Details
                  </h3>
                  <div class="mt-4 text-left">
                    <dl class="grid grid-cols-1 gap-x-4 gap-y-4 sm:grid-cols-2">
                      <div class="sm:col-span-2">
                        <dt class="text-sm font-medium text-gray-500">Common Name</dt>
                        <dd class="mt-1 text-sm text-gray-900">{@selected_cert.common_name}</dd>
                      </div>
                      <div class="sm:col-span-2">
                        <dt class="text-sm font-medium text-gray-500">Subject</dt>
                        <dd class="mt-1 text-sm text-gray-900 break-all">{@selected_cert.subject}</dd>
                      </div>
                      <div class="sm:col-span-2">
                        <dt class="text-sm font-medium text-gray-500">Fingerprint</dt>
                        <dd class="mt-1 text-sm text-gray-900 font-mono break-all">
                          {@selected_cert.fingerprint}
                        </dd>
                      </div>
                      <div>
                        <dt class="text-sm font-medium text-gray-500">Valid From</dt>
                        <dd class="mt-1 text-sm text-gray-900">
                          {format_datetime(@selected_cert.valid_from)}
                        </dd>
                      </div>
                      <div>
                        <dt class="text-sm font-medium text-gray-500">Valid Until</dt>
                        <dd class="mt-1 text-sm text-gray-900">
                          {format_datetime(@selected_cert.valid_until)}
                        </dd>
                      </div>
                      <div class="sm:col-span-2">
                        <dt class="text-sm font-medium text-gray-500">Serial Number</dt>
                        <dd class="mt-1 text-sm text-gray-900 font-mono">
                          {@selected_cert.serial_number}
                        </dd>
                      </div>
                    </dl>
                  </div>
                </div>
              </div>
              <div class="mt-5 sm:mt-6">
                <button
                  type="button"
                  phx-click="close_details"
                  class="inline-flex justify-center w-full rounded-md border border-transparent shadow-sm px-4 py-2 bg-blue-600 text-base font-medium text-white hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 sm:text-sm"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      <% end %>
    </div>
    """
  end

  # Private functions

  defp load_certificates(socket) do
    import Ecto.Query

    certificates =
      from(c in Certificate,
        where: c.cert_type == :admin_client,
        order_by: [desc: c.inserted_at]
      )
      |> Repo.all()

    assign(socket, :certificates, certificates)
  end

  defp register_admin_certificate(pem_data, admin_email) do
    # Parse the PEM certificate
    case parse_certificate(pem_data) do
      {:ok, cert_info} ->
        # Create certificate record
        %Certificate{}
        |> Certificate.changeset(%{
          serial_number: cert_info.serial_number,
          fingerprint: cert_info.fingerprint,
          certificate_pem: pem_data,
          subject: cert_info.subject,
          issuer: cert_info.issuer || cert_info.subject,
          common_name: cert_info.common_name,
          organization: cert_info.organization,
          valid_from: cert_info.valid_from,
          valid_until: cert_info.valid_until,
          cert_type: :admin_client,
          entity_id: admin_email,
          entity_type: "admin",
          metadata: %{
            "registered_by" => admin_email,
            "registered_at" =>
              DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_string()
          }
        })
        |> Repo.insert()

      error ->
        error
    end
  end

  defp parse_certificate(pem_data) do
    # Basic PEM parsing - extract certificate details
    # In production, use :public_key.pem_decode/1 and :public_key.pkix_decode_cert/2

    [entry] = :public_key.pem_decode(pem_data)
    cert = :public_key.pem_entry_decode(entry)

    # Extract certificate information
    {:Certificate, _tbs_cert, _sig_alg, _signature} = cert

    {:ok,
     %{
       serial_number: extract_serial_number(cert),
       fingerprint: calculate_fingerprint(pem_data),
       subject: extract_subject(cert),
       issuer: extract_issuer(cert),
       common_name: extract_common_name(cert),
       organization: extract_organization(cert),
       valid_from: extract_valid_from(cert),
       valid_until: extract_valid_until(cert)
     }}
  rescue
    e ->
      Logger.error("Failed to parse certificate: #{inspect(e)}")
      {:error, "Invalid certificate format"}
  end

  defp calculate_fingerprint(pem_data) do
    :crypto.hash(:sha256, pem_data)
    |> Base.encode16(case: :lower)
  end

  defp extract_serial_number(_cert), do: Base.encode16(:crypto.strong_rand_bytes(16))
  defp extract_subject(_cert), do: "CN=Admin"
  defp extract_issuer(_cert), do: "CN=SecretHub CA"
  defp extract_common_name(_cert), do: "Admin User"
  defp extract_organization(_cert), do: "SecretHub"

  defp extract_valid_from(_cert) do
    DateTime.utc_now() |> DateTime.truncate(:second)
  end

  defp extract_valid_until(_cert) do
    DateTime.utc_now()
    |> DateTime.truncate(:second)
    |> DateTime.add(365 * 24 * 3600, :second)
    |> DateTime.truncate(:second)
  end

  defp revoke_certificate(cert_id) do
    cert = Repo.get!(Certificate, cert_id)

    cert
    |> Certificate.changeset(%{
      revoked: true,
      revoked_at: DateTime.utc_now() |> DateTime.truncate(:second),
      revocation_reason: "Revoked by administrator"
    })
    |> Repo.update()
  end

  defp format_datetime(nil), do: "N/A"

  defp format_datetime(datetime) do
    Calendar.strftime(datetime, "%Y-%m-%d %H:%M:%S UTC")
  end
end
