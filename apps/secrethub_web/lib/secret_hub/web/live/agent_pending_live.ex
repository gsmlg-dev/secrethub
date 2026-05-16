defmodule SecretHub.Web.AgentPendingLive do
  @moduledoc """
  Admin review page for pending Agent enrollments.
  """

  use SecretHub.Web, :live_view

  alias SecretHub.Core.Agents.Enrollment

  @impl true
  def mount(_params, _session, socket) do
    {:ok, assign(socket, enrollments: [], selected: nil)}
  end

  @impl true
  def handle_params(%{"id" => id}, _uri, socket) do
    {:noreply,
     assign(socket,
       enrollments: Enrollment.list_pending(),
       selected: Enrollment.get_enrollment(id)
     )}
  end

  def handle_params(_params, _uri, socket) do
    {:noreply, assign(socket, enrollments: Enrollment.list_pending(), selected: nil)}
  end

  @impl true
  def handle_event("approve", %{"id" => id}, socket) do
    case Enrollment.approve(id, "admin") do
      {:ok, _enrollment} ->
        {:noreply, reload(socket) |> put_flash(:info, "Agent approved")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Approve failed: #{inspect(reason)}")}
    end
  end

  def handle_event("reject", %{"id" => id}, socket) do
    case Enrollment.reject(id, "admin") do
      {:ok, _enrollment} ->
        {:noreply, reload(socket) |> put_flash(:info, "Agent rejected")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Reject failed: #{inspect(reason)}")}
    end
  end

  def handle_event("expire", %{"id" => id}, socket) do
    case Enrollment.expire(id) do
      {:ok, _enrollment} ->
        {:noreply, reload(socket) |> put_flash(:info, "Enrollment expired")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Expire failed: #{inspect(reason)}")}
    end
  end

  def handle_event("reset", %{"id" => id}, socket) do
    case Enrollment.reset(id) do
      {:ok, _enrollment} ->
        {:noreply, reload(socket) |> put_flash(:info, "Enrollment reset")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Reset failed: #{inspect(reason)}")}
    end
  end

  def handle_event("select", %{"id" => id}, socket) do
    {:noreply, push_patch(socket, to: ~p"/admin/agents/pending/#{id}")}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="space-y-6">
      <div class="flex items-center justify-between">
        <div>
          <h2 class="text-xl font-semibold text-on-surface">Pending Agents</h2>
          <p class="text-sm text-on-surface-variant">
            Review host identity before certificate issuance.
          </p>
        </div>
        <.link navigate={~p"/admin/agents"} class="btn-secondary">Active Agents</.link>
      </div>

      <div class="overflow-x-auto bg-surface-container rounded-lg shadow">
        <table class="min-w-full divide-y divide-outline-variant">
          <thead class="bg-surface-container-low">
            <tr>
              <th class="px-4 py-3 text-left text-xs font-medium uppercase">Status</th>
              <th class="px-4 py-3 text-left text-xs font-medium uppercase">Hostname</th>
              <th class="px-4 py-3 text-left text-xs font-medium uppercase">Machine ID</th>
              <th class="px-4 py-3 text-left text-xs font-medium uppercase">SSH Key</th>
              <th class="px-4 py-3 text-left text-xs font-medium uppercase">Source IP</th>
              <th class="px-4 py-3 text-left text-xs font-medium uppercase">Agent Version</th>
              <th class="px-4 py-3 text-left text-xs font-medium uppercase">Submitted</th>
              <th class="px-4 py-3 text-left text-xs font-medium uppercase">Actions</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-outline-variant">
            <%= for enrollment <- @enrollments do %>
              <tr class="hover:bg-surface-container-low">
                <td class="px-4 py-3 text-sm">{enrollment.status}</td>
                <td class="px-4 py-3 text-sm">{enrollment.hostname || "-"}</td>
                <td class="px-4 py-3 text-sm font-mono">{enrollment.machine_id || "-"}</td>
                <td class="px-4 py-3 text-xs font-mono">
                  {enrollment.ssh_host_key_algorithm}:{enrollment.ssh_host_key_fingerprint}
                </td>
                <td class="px-4 py-3 text-sm">{enrollment.source_ip || "-"}</td>
                <td class="px-4 py-3 text-sm">{enrollment.agent_version || "-"}</td>
                <td class="px-4 py-3 text-sm">{format_dt(enrollment.inserted_at)}</td>
                <td class="px-4 py-3 text-sm">
                  <div class="flex gap-2">
                    <button
                      class="btn-primary btn-sm"
                      phx-click="approve"
                      phx-value-id={enrollment.id}
                    >
                      Approve
                    </button>
                    <button
                      class="btn-secondary btn-sm"
                      phx-click="select"
                      phx-value-id={enrollment.id}
                    >
                      Details
                    </button>
                    <button class="btn-danger btn-sm" phx-click="reject" phx-value-id={enrollment.id}>
                      Reject
                    </button>
                  </div>
                </td>
              </tr>
            <% end %>
          </tbody>
        </table>
      </div>

      <%= if @selected do %>
        <div class="bg-surface-container rounded-lg shadow p-6 space-y-4">
          <div class="flex items-center justify-between">
            <h3 class="text-lg font-semibold text-on-surface">
              {@selected.hostname || @selected.id}
            </h3>
            <div class="flex gap-2">
              <button class="btn-secondary btn-sm" phx-click="reset" phx-value-id={@selected.id}>
                Reset Enrollment
              </button>
              <button class="btn-secondary btn-sm" phx-click="expire" phx-value-id={@selected.id}>
                Expire
              </button>
            </div>
          </div>

          <div class="grid grid-cols-1 lg:grid-cols-2 gap-4 text-sm">
            <pre class="overflow-auto bg-surface-container-low p-4 rounded"><%= inspect(details(@selected), pretty: true) %></pre>
            <pre class="overflow-auto bg-surface-container-low p-4 rounded"><%= inspect(artifacts(@selected), pretty: true) %></pre>
          </div>
        </div>
      <% end %>
    </div>
    """
  end

  defp reload(socket), do: assign(socket, enrollments: Enrollment.list_pending())

  defp details(enrollment) do
    Map.take(enrollment, [
      :id,
      :agent_id,
      :status,
      :hostname,
      :fqdn,
      :machine_id,
      :os,
      :arch,
      :source_ip,
      :last_error,
      :approved_by,
      :approved_at
    ])
  end

  defp artifacts(enrollment) do
    %{
      required_csr_fields: enrollment.required_csr_fields,
      csr_pem: enrollment.csr_pem,
      trusted_endpoint_error: enrollment.last_error
    }
  end

  defp format_dt(nil), do: "-"
  defp format_dt(dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S")
end
