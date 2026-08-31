defmodule SecretHub.Web.ClientAuthLive do
  @moduledoc """
  LiveView for managing Client Authentication PKI (Authority, Client Identities, Certificates, and Agent Receipts).
  """

  use SecretHub.Web, :live_view
  require Logger

  alias SecretHub.Core.PKI.ClientAuth

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      SecretHub.Core.PKI.ClientAuth.Notifier.subscribe()
    end

    socket =
      socket
      |> assign(:page_title, "Client Auth PKI")
      |> assign(:active_tab, "overview")
      |> assign(:authority, nil)
      |> assign(:status_data, nil)
      |> assign(:identities, [])
      |> assign(:certificates, [])
      |> assign(:receipts, [])
      |> assign(:show_init_modal, false)
      |> assign(:show_identity_modal, false)
      |> assign(:show_issue_modal, false)
      |> assign(:show_revoke_modal, false)
      |> assign(:issued_cert_result, nil)
      |> assign(:issue_request_id, nil)
      |> assign(:init_form, %{
        "name" => "SecretHub Client Authentication Root CA",
        "key_algorithm" => "ecdsa_p384",
        "default_ttl_days" => 30,
        "max_ttl_days" => 90
      })
      |> assign(:identity_form, %{"name" => "", "description" => ""})
      |> assign(:issue_form, %{"identity_id" => "", "csr_pem" => "", "ttl_days" => 30})
      |> assign(:selected_cert, nil)
      |> assign(:revoke_reason, "keyCompromise")
      |> assign(:action_error, nil)
      |> assign(:action_success, nil)
      |> load_data()

    {:ok, socket}
  end

  @impl true
  def handle_params(params, _uri, socket) do
    tab = Map.get(params, "tab", "overview")
    {:noreply, assign(socket, :active_tab, tab)}
  end

  @impl true
  def handle_event("switch_tab", %{"tab" => tab}, socket) do
    {:noreply, assign(socket, :active_tab, tab)}
  end

  def handle_event("open_init_modal", _params, socket) do
    {:noreply, assign(socket, show_init_modal: true, action_error: nil)}
  end

  def handle_event("close_init_modal", _params, socket) do
    {:noreply, assign(socket, :show_init_modal, false)}
  end

  def handle_event("init_authority", %{"init" => params}, socket) do
    ttl_seconds = String.to_integer(params["default_ttl_days"] || "30") * 86_400
    max_ttl_seconds = String.to_integer(params["max_ttl_days"] || "90") * 86_400

    attrs = %{
      "name" => params["name"],
      "key_algorithm" => params["key_algorithm"],
      "default_ttl_seconds" => ttl_seconds,
      "max_ttl_seconds" => max_ttl_seconds
    }

    case ClientAuth.init_authority(attrs) do
      {:ok, _auth} ->
        socket =
          socket
          |> assign(:show_init_modal, false)
          |> assign(:action_success, "Client Auth Authority successfully initialized!")
          |> assign(:action_error, nil)
          |> load_data()

        {:noreply, socket}

      {:error, reason} ->
        {:noreply,
         assign(socket, :action_error, "Failed to initialize authority: #{inspect(reason)}")}
    end
  end

  def handle_event("force_crl_refresh", _params, socket) do
    case ClientAuth.force_refresh_crl() do
      {:ok, crl} ->
        socket =
          socket
          |> assign(
            :action_success,
            "CRL successfully refreshed to Generation #{crl.generation}, CRL ##{crl.crl_number}"
          )
          |> assign(:action_error, nil)
          |> load_data()

        {:noreply, socket}

      {:error, reason} ->
        {:noreply, assign(socket, :action_error, "Failed to refresh CRL: #{inspect(reason)}")}
    end
  end

  def handle_event("open_identity_modal", _params, socket) do
    {:noreply, assign(socket, show_identity_modal: true, action_error: nil)}
  end

  def handle_event("close_identity_modal", _params, socket) do
    {:noreply, assign(socket, :show_identity_modal, false)}
  end

  def handle_event("create_identity", %{"identity" => params}, socket) do
    attrs = %{
      "name" => params["name"],
      "metadata" => %{"description" => params["description"]}
    }

    case ClientAuth.create_identity(attrs) do
      {:ok, identity} ->
        socket =
          socket
          |> assign(:show_identity_modal, false)
          |> assign(
            :action_success,
            "Identity '#{identity.name}' (#{identity.id}) created successfully"
          )
          |> assign(:action_error, nil)
          |> load_data()

        {:noreply, socket}

      {:error, reason} ->
        {:noreply, assign(socket, :action_error, "Failed to create identity: #{inspect(reason)}")}
    end
  end

  def handle_event("disable_identity", %{"id" => id}, socket) do
    case ClientAuth.disable_identity(id, %{"reason" => "identity_disabled"}) do
      {:ok, identity} ->
        socket =
          socket
          |> assign(
            :action_success,
            "Identity '#{identity.name}' disabled and active certificates revoked"
          )
          |> assign(:action_error, nil)
          |> load_data()

        {:noreply, socket}

      {:error, reason} ->
        {:noreply,
         assign(socket, :action_error, "Failed to disable identity: #{inspect(reason)}")}
    end
  end

  def handle_event("open_issue_modal", params, socket) do
    identity_id = Map.get(params, "identity_id", "")
    issue_form = Map.put(socket.assigns.issue_form, "identity_id", identity_id)
    request_id = Ecto.UUID.generate()

    {:noreply,
     assign(socket,
       show_issue_modal: true,
       issue_form: issue_form,
       issue_request_id: request_id,
       issued_cert_result: nil,
       action_error: nil
     )}
  end

  def handle_event("close_issue_modal", _params, socket) do
    {:noreply,
     assign(socket, show_issue_modal: false, issued_cert_result: nil, issue_request_id: nil)}
  end

  def handle_event("issue_certificate", %{"issue" => params}, socket) do
    ttl_seconds = String.to_integer(params["ttl_days"] || "30") * 86_400
    request_id = socket.assigns.issue_request_id || Ecto.UUID.generate()

    attrs = %{
      "identity_id" => params["identity_id"],
      "csr_pem" => params["csr_pem"],
      "ttl_seconds" => ttl_seconds,
      "request_id" => request_id
    }

    case ClientAuth.issue_certificate(attrs) do
      {:ok, result} ->
        socket =
          socket
          |> assign(:issued_cert_result, result)
          |> assign(
            :action_success,
            "Certificate issued successfully! Copy or download the PEM below."
          )
          |> assign(:action_error, nil)
          |> load_data()

        {:noreply, socket}

      {:error, reason} ->
        {:noreply,
         assign(socket, :action_error, "Failed to issue certificate: #{inspect(reason)}")}
    end
  end

  def handle_event("open_revoke_modal", %{"id" => id}, socket) do
    case ClientAuth.get_certificate(id) do
      {:ok, cert} ->
        {:noreply,
         assign(socket, show_revoke_modal: true, selected_cert: cert, action_error: nil)}

      {:error, _} ->
        {:noreply, assign(socket, :action_error, "Certificate not found")}
    end
  end

  def handle_event("close_revoke_modal", _params, socket) do
    {:noreply, assign(socket, show_revoke_modal: false, selected_cert: nil)}
  end

  def handle_event("revoke_certificate", %{"revoke" => params}, socket) do
    cert_id = socket.assigns.selected_cert.id
    reason = params["reason"] || "keyCompromise"

    case ClientAuth.revoke_certificate(cert_id, %{"reason" => reason}) do
      {:ok, _cert} ->
        socket =
          socket
          |> assign(:show_revoke_modal, false)
          |> assign(:selected_cert, nil)
          |> assign(:action_success, "Certificate revoked successfully and CRL updated")
          |> assign(:action_error, nil)
          |> load_data()

        {:noreply, socket}

      {:error, reason} ->
        {:noreply,
         assign(socket, :action_error, "Failed to revoke certificate: #{inspect(reason)}")}
    end
  end

  @impl true
  def handle_info({:client_auth_bundle_updated, _payload}, socket) do
    {:noreply, load_data(socket)}
  end

  # Data Loader

  defp load_data(socket) do
    status_data =
      case ClientAuth.authority_status() do
        {:ok, data} -> data
        _ -> nil
      end

    identities = ClientAuth.list_identities()
    certificates = ClientAuth.list_certificates()
    receipts = ClientAuth.list_bundle_receipts()

    socket
    |> assign(:status_data, status_data)
    |> assign(:identities, identities)
    |> assign(:certificates, certificates)
    |> assign(:receipts, receipts)
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="space-y-6">
      <div class="flex items-center justify-between">
        <div>
          <h1 class="text-2xl font-bold tracking-tight text-base-content">Client Auth PKI</h1>
          <p class="text-sm text-base-content/70 mt-1">
            Dedicated Machine-to-Machine Certificate Authority for external client authentication.
          </p>
        </div>
        <div class="flex space-x-3">
          <%= if is_nil(@status_data) do %>
            <button
              phx-click="open_init_modal"
              class="btn btn-primary btn-sm"
            >
              Initialize Authority
            </button>
          <% else %>
            <button
              phx-click="force_crl_refresh"
              class="btn btn-secondary btn-sm"
            >
              Force CRL Refresh
            </button>
            <button
              phx-click="open_identity_modal"
              class="btn btn-primary btn-sm"
            >
              New Client Identity
            </button>
          <% end %>
        </div>
      </div>

      <%= if @action_success do %>
        <div class="alert alert-success shadow-lg">
          <div>
            <span>{@action_success}</span>
          </div>
        </div>
      <% end %>

      <%= if @action_error do %>
        <div class="alert alert-error shadow-lg">
          <div>
            <span>{@action_error}</span>
          </div>
        </div>
      <% end %>

      <!-- Overview Stats Cards -->
      <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div class="card bg-base-200 shadow">
          <div class="card-body p-4">
            <div class="text-xs uppercase font-semibold text-base-content/60">Authority Status</div>
            <div class="text-xl font-bold mt-1 flex items-center gap-2">
              <%= if @status_data do %>
                <span class="badge badge-success">{@status_data.status}</span>
                <span class="text-xs text-base-content/60">Gen {@status_data.current_generation}</span>
              <% else %>
                <span class="badge badge-warning">Uninitialized</span>
              <% end %>
            </div>
          </div>
        </div>

        <div class="card bg-base-200 shadow">
          <div class="card-body p-4">
            <div class="text-xs uppercase font-semibold text-base-content/60">Active Identities</div>
            <div class="text-xl font-bold mt-1">
              {Enum.count(@identities, &(&1.status == "active"))}
              <span class="text-xs font-normal text-base-content/60">/ {length(@identities)} total</span>
            </div>
          </div>
        </div>

        <div class="card bg-base-200 shadow">
          <div class="card-body p-4">
            <div class="text-xs uppercase font-semibold text-base-content/60">
              Active Certificates
            </div>
            <div class="text-xl font-bold mt-1 text-primary">
              {Enum.count(@certificates, &(!&1.revoked))}
              <span class="text-xs font-normal text-base-content/60">/ {length(@certificates)} total</span>
            </div>
          </div>
        </div>

        <div class="card bg-base-200 shadow">
          <div class="card-body p-4">
            <div class="text-xs uppercase font-semibold text-base-content/60">
              Agent Fleet Receipts
            </div>
            <div class="text-xl font-bold mt-1">
              {Enum.count(@receipts, &(&1.status == "applied"))}
              <span class="text-xs font-normal text-base-content/60">applied</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Navigation Tabs -->
      <div class="tabs tabs-bordered">
        <button
          class={"tab #{if @active_tab == "overview", do: "tab-active"}"}
          phx-click="switch_tab"
          phx-value-tab="overview"
        >
          Overview & Authority
        </button>
        <button
          class={"tab #{if @active_tab == "identities", do: "tab-active"}"}
          phx-click="switch_tab"
          phx-value-tab="identities"
        >
          Client Identities ({length(@identities)})
        </button>
        <button
          class={"tab #{if @active_tab == "certificates", do: "tab-active"}"}
          phx-click="switch_tab"
          phx-value-tab="certificates"
        >
          Certificates ({length(@certificates)})
        </button>
        <button
          class={"tab #{if @active_tab == "receipts", do: "tab-active"}"}
          phx-click="switch_tab"
          phx-value-tab="receipts"
        >
          Agent Receipts ({length(@receipts)})
        </button>
      </div>

      <!-- Tab Contents -->
      <%= if @active_tab == "overview" do %>
        <div class="space-y-4">
          <%= if @status_data do %>
            <div class="card bg-base-100 shadow border border-base-200">
              <div class="card-body">
                <h2 class="card-title text-base">Authority Details</h2>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mt-2 text-sm">
                  <div>
                    <span class="font-medium text-base-content/70">Slug:</span>
                    <code class="ml-2 bg-base-200 px-2 py-1 rounded">{@status_data.slug}</code>
                  </div>
                  <div>
                    <span class="font-medium text-base-content/70">Key Algorithm:</span>
                    <span class="ml-2 font-semibold">{@status_data.key_algorithm}</span>
                  </div>
                  <div>
                    <span class="font-medium text-base-content/70">Current Generation:</span>
                    <span class="ml-2 font-semibold">{@status_data.current_generation}</span>
                  </div>
                  <div>
                    <span class="font-medium text-base-content/70">Current CRL Number:</span>
                    <span class="ml-2 font-semibold">{@status_data.current_crl_number}</span>
                  </div>
                  <%= if @status_data.ca do %>
                    <div class="md:col-span-2">
                      <span class="font-medium text-base-content/70">CA Fingerprint:</span>
                      <code class="ml-2 text-xs bg-base-200 px-2 py-1 rounded break-all">{@status_data.ca.canonical_fingerprint}</code>
                    </div>
                  <% end %>
                  <%= if @status_data.crl do %>
                    <div class="md:col-span-2">
                      <span class="font-medium text-base-content/70">Current CRL SHA-256:</span>
                      <code class="ml-2 text-xs bg-base-200 px-2 py-1 rounded break-all">{@status_data.crl.crl_der_sha256}</code>
                    </div>
                  <% end %>
                </div>
              </div>
            </div>
          <% else %>
            <div class="card bg-base-100 shadow p-8 text-center">
              <h3 class="font-bold text-lg">No Client Auth Authority Initialized</h3>
              <p class="text-sm text-base-content/70 mt-1">
                Initialize the dedicated Client Auth CA to begin issuing client certificates and distributing CRLs.
              </p>
              <div class="mt-4">
                <button phx-click="open_init_modal" class="btn btn-primary">Initialize CA Authority</button>
              </div>
            </div>
          <% end %>
        </div>
      <% end %>

      <%= if @active_tab == "identities" do %>
        <div class="space-y-4">
          <div class="flex justify-between items-center">
            <h2 class="text-lg font-bold">Managed Client Identities</h2>
            <button phx-click="open_identity_modal" class="btn btn-primary btn-sm">Create Identity</button>
          </div>

          <div class="overflow-x-auto">
            <table class="table w-full bg-base-100 shadow rounded-box">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Client UUID (CN)</th>
                  <th>Status</th>
                  <th>Created At</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                <%= for id <- @identities do %>
                  <tr>
                    <td class="font-bold">{id.name}</td>
                    <td><code class="text-xs bg-base-200 px-2 py-1 rounded">{id.id}</code></td>
                    <td>
                      <span class={"badge #{if id.status == "active", do: "badge-success", else: "badge-error"}"}>
                        {id.status}
                      </span>
                    </td>
                    <td class="text-sm text-base-content/70">{id.inserted_at}</td>
                    <td class="space-x-2">
                      <%= if id.status == "active" do %>
                        <button
                          phx-click="open_issue_modal"
                          phx-value-identity_id={id.id}
                          class="btn btn-xs btn-outline btn-primary"
                        >
                          Issue Cert
                        </button>
                        <button
                          phx-click="disable_identity"
                          phx-value-id={id.id}
                          data-confirm="Disabling this identity will revoke ALL its certificates and update the CRL. Proceed?"
                          class="btn btn-xs btn-outline btn-error"
                        >
                          Disable
                        </button>
                      <% else %>
                        <span class="text-xs text-base-content/40">Disabled</span>
                      <% end %>
                    </td>
                  </tr>
                <% end %>
              </tbody>
            </table>
          </div>
        </div>
      <% end %>

      <%= if @active_tab == "certificates" do %>
        <div class="space-y-4">
          <div class="flex justify-between items-center">
            <h2 class="text-lg font-bold">Issued Certificates</h2>
            <button phx-click="open_issue_modal" class="btn btn-primary btn-sm">Issue Certificate</button>
          </div>

          <div class="overflow-x-auto">
            <table class="table w-full bg-base-100 shadow rounded-box">
              <thead>
                <tr>
                  <th>Common Name (Identity)</th>
                  <th>Serial Number</th>
                  <th>SAN URIs</th>
                  <th>Valid Until</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                <%= for cert <- @certificates do %>
                  <tr>
                    <td class="font-medium">{cert.common_name}</td>
                    <td>
                      <code class="text-xs bg-base-200 px-2 py-1 rounded">{cert.serial_number}</code>
                    </td>
                    <td>
                      <%= for uri <- (cert.metadata && cert.metadata["san_uri"]) || [] do %>
                        <span class="badge badge-sm badge-ghost text-xs">{uri}</span>
                      <% end %>
                    </td>
                    <td class="text-sm text-base-content/70">{cert.valid_until}</td>
                    <td>
                      <%= if cert.revoked do %>
                        <span class="badge badge-error">Revoked ({cert.revocation_reason})</span>
                      <% else %>
                        <span class="badge badge-success">Active</span>
                      <% end %>
                    </td>
                    <td>
                      <%= if !cert.revoked do %>
                        <button
                          phx-click="open_revoke_modal"
                          phx-value-id={cert.id}
                          class="btn btn-xs btn-outline btn-error"
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
      <% end %>

      <%= if @active_tab == "receipts" do %>
        <div class="space-y-4">
          <div class="flex justify-between items-center">
            <h2 class="text-lg font-bold">Agent Convergence Status</h2>
          </div>

          <div class="overflow-x-auto">
            <table class="table w-full bg-base-100 shadow rounded-box">
              <thead>
                <tr>
                  <th>Agent ID</th>
                  <th>Generation</th>
                  <th>CRL Number</th>
                  <th>Status</th>
                  <th>Applied At</th>
                  <th>Last Error</th>
                </tr>
              </thead>
              <tbody>
                <%= for r <- @receipts do %>
                  <tr>
                    <td class="font-bold">{r.agent_id}</td>
                    <td><span class="badge badge-ghost">Gen {r.generation}</span></td>
                    <td>#{r.crl_number}</td>
                    <td>
                      <span class={"badge #{if r.status == "applied", do: "badge-success", else: "badge-error"}"}>
                        {r.status}
                      </span>
                    </td>
                    <td class="text-sm text-base-content/70">{r.applied_at}</td>
                    <td class="text-xs text-error">{r.last_error_detail || "-"}</td>
                  </tr>
                <% end %>
              </tbody>
            </table>
          </div>
        </div>
      <% end %>

      <!-- Initialize CA Modal -->
      <%= if @show_init_modal do %>
        <div class="modal modal-open">
          <div class="modal-box">
            <h3 class="font-bold text-lg">Initialize Client Auth Authority</h3>
            <form phx-submit="init_authority" class="space-y-4 mt-4">
              <div class="form-control">
                <label class="label"><span class="label-text">Authority Name</span></label>
                <input
                  type="text"
                  name="init[name]"
                  value={@init_form["name"]}
                  required
                  class="input input-bordered w-full"
                />
              </div>
              <div class="form-control">
                <label class="label"><span class="label-text">Key Algorithm</span></label>
                <select name="init[key_algorithm]" class="select select-bordered w-full">
                  <option value="ecdsa_p384">ECDSA P-384 (Recommended)</option>
                  <option value="rsa_4096">RSA 4096</option>
                </select>
              </div>
              <div class="grid grid-cols-2 gap-4">
                <div class="form-control">
                  <label class="label"><span class="label-text">Default TTL (Days)</span></label>
                  <input
                    type="number"
                    name="init[default_ttl_days]"
                    value={@init_form["default_ttl_days"]}
                    class="input input-bordered w-full"
                  />
                </div>
                <div class="form-control">
                  <label class="label"><span class="label-text">Max TTL (Days)</span></label>
                  <input
                    type="number"
                    name="init[max_ttl_days]"
                    value={@init_form["max_ttl_days"]}
                    class="input input-bordered w-full"
                  />
                </div>
              </div>
              <div class="modal-action">
                <button type="button" phx-click="close_init_modal" class="btn btn-ghost">Cancel</button>
                <button type="submit" class="btn btn-primary">Initialize CA</button>
              </div>
            </form>
          </div>
        </div>
      <% end %>

      <!-- Create Identity Modal -->
      <%= if @show_identity_modal do %>
        <div class="modal modal-open">
          <div class="modal-box">
            <h3 class="font-bold text-lg">Create Client Identity</h3>
            <form phx-submit="create_identity" class="space-y-4 mt-4">
              <div class="form-control">
                <label class="label"><span class="label-text">Identity Name</span></label>
                <input
                  type="text"
                  name="identity[name]"
                  placeholder="e.g. backend-worker-prod-01"
                  required
                  class="input input-bordered w-full"
                />
              </div>
              <div class="form-control">
                <label class="label"><span class="label-text">Description</span></label>
                <textarea
                  name="identity[description]"
                  placeholder="Purpose / owner metadata"
                  class="textarea textarea-bordered w-full"
                ></textarea>
              </div>
              <div class="modal-action">
                <button type="button" phx-click="close_identity_modal" class="btn btn-ghost">Cancel</button>
                <button type="submit" class="btn btn-primary">Create</button>
              </div>
            </form>
          </div>
        </div>
      <% end %>

      <!-- Issue Certificate Modal -->
      <%= if @show_issue_modal do %>
        <div class="modal modal-open">
          <div class="modal-box max-w-3xl">
            <h3 class="font-bold text-lg">
              <%= if @issued_cert_result do %>
                Certificate Issued Successfully
              <% else %>
                Issue Client Certificate
              <% end %>
            </h3>

            <%= if @issued_cert_result do %>
              <div class="space-y-4 mt-4">
                <div class="alert alert-success text-sm">
                  <span>Certificate was generated and signed by the Client CA. Copy or download your credentials now.</span>
                </div>

                <div class="form-control">
                  <div class="flex justify-between items-center mb-1">
                    <label class="label-text font-medium">Client Certificate PEM</label>
                    <button
                      type="button"
                      id="copy-cert-btn"
                      onclick="navigator.clipboard.writeText(document.getElementById('issued-cert-pem').value)"
                      class="btn btn-xs btn-outline"
                    >
                      Copy Certificate
                    </button>
                  </div>
                  <textarea
                    id="issued-cert-pem"
                    readonly
                    rows="8"
                    class="textarea textarea-bordered font-mono text-xs w-full bg-base-200"
                  ><%= @issued_cert_result.certificate %></textarea>
                </div>

                <div class="form-control">
                  <div class="flex justify-between items-center mb-1">
                    <label class="label-text font-medium">CA Bundle PEM</label>
                    <button
                      type="button"
                      id="copy-ca-btn"
                      onclick="navigator.clipboard.writeText(document.getElementById('issued-ca-pem').value)"
                      class="btn btn-xs btn-outline"
                    >
                      Copy CA Chain
                    </button>
                  </div>
                  <textarea
                    id="issued-ca-pem"
                    readonly
                    rows="6"
                    class="textarea textarea-bordered font-mono text-xs w-full bg-base-200"
                  ><%= @issued_cert_result.ca_bundle_pem %></textarea>
                </div>

                <div class="modal-action flex justify-between items-center">
                  <a
                    href={"data:application/x-pem-file;charset=utf-8," <> URI.encode_www_form(@issued_cert_result.certificate)}
                    download="client.crt"
                    class="btn btn-secondary btn-sm"
                  >
                    Download Certificate (.crt)
                  </a>
                  <button type="button" phx-click="close_issue_modal" class="btn btn-primary">Done</button>
                </div>
              </div>
            <% else %>
              <form phx-submit="issue_certificate" class="space-y-4 mt-4">
                <div class="form-control">
                  <label class="label"><span class="label-text">Identity ID (UUID)</span></label>
                  <select name="issue[identity_id]" class="select select-bordered w-full" required>
                    <option value="">Select Identity...</option>
                    <%= for id <- @identities do %>
                      <option
                        value={id.id}
                        selected={id.id == @issue_form["identity_id"]}
                        disabled={id.status != "active"}
                      >
                        {id.name} ({id.id}) {if id.status != "active", do: "- DISABLED"}
                      </option>
                    <% end %>
                  </select>
                </div>
                <div class="form-control">
                  <label class="label"><span class="label-text">Certificate Signing Request (CSR PEM)</span></label>
                  <textarea
                    name="issue[csr_pem]"
                    rows="6"
                    placeholder="-----BEGIN CERTIFICATE REQUEST-----..."
                    required
                    class="textarea textarea-bordered font-mono text-xs w-full"
                  ></textarea>
                </div>
                <div class="form-control">
                  <label class="label"><span class="label-text">TTL (Days)</span></label>
                  <input
                    type="number"
                    name="issue[ttl_days]"
                    value={@issue_form["ttl_days"]}
                    class="input input-bordered w-full"
                  />
                </div>
                <div class="modal-action">
                  <button type="button" phx-click="close_issue_modal" class="btn btn-ghost">Cancel</button>
                  <button type="submit" class="btn btn-primary">Sign & Issue</button>
                </div>
              </form>
            <% end %>
          </div>
        </div>
      <% end %>

      <!-- Revoke Certificate Modal -->
      <%= if @show_revoke_modal and @selected_cert do %>
        <div class="modal modal-open">
          <div class="modal-box">
            <h3 class="font-bold text-lg text-error">Revoke Client Certificate</h3>
            <p class="text-sm text-base-content/70 mt-2">
              Are you sure you want to revoke certificate for common name <strong><%= @selected_cert.common_name %></strong>?
              A new signed CRL will be published immediately.
            </p>
            <form phx-submit="revoke_certificate" class="space-y-4 mt-4">
              <div class="form-control">
                <label class="label"><span class="label-text">Revocation Reason</span></label>
                <select name="revoke[reason]" class="select select-bordered w-full">
                  <option value="keyCompromise">Key Compromise (keyCompromise)</option>
                  <option value="superseded">Superseded (superseded)</option>
                  <option value="cessationOfOperation">
                    Cessation of Operation (cessationOfOperation)
                  </option>
                  <option value="privilegeWithdrawn">Privilege Withdrawn (privilegeWithdrawn)</option>
                </select>
              </div>
              <div class="modal-action">
                <button type="button" phx-click="close_revoke_modal" class="btn btn-ghost">Cancel</button>
                <button type="submit" class="btn btn-error">Revoke Certificate</button>
              </div>
            </form>
          </div>
        </div>
      <% end %>
    </div>
    """
  end
end
