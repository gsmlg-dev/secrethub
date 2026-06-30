defmodule SecretHub.Web.CliAccessLive do
  @moduledoc """
  Admin approval page for pending CLI login requests.
  """

  use SecretHub.Web, :live_view

  alias SecretHub.Core.Auth.{AppRole, CliAccess}

  @refresh_interval_ms 2_500

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: schedule_refresh()

    {:ok, assign(socket, requests: [], roles: [])}
  end

  @impl true
  def handle_params(_params, _uri, socket) do
    {:noreply, reload(socket)}
  end

  @impl true
  def handle_event("approve_cli_access", %{"id" => id, "role_id" => role_id}, socket) do
    case CliAccess.approve_request(id, role_id, "admin") do
      {:ok, _request} ->
        {:noreply, reload(socket) |> put_flash(:info, "CLI access approved")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Approve failed: #{inspect(reason)}")}
    end
  end

  def handle_event("reject_cli_access", %{"id" => id}, socket) do
    case CliAccess.reject_request(id, "admin") do
      {:ok, _request} ->
        {:noreply, reload(socket) |> put_flash(:info, "CLI access rejected")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Reject failed: #{inspect(reason)}")}
    end
  end

  def handle_event("revoke_cli_access", %{"id" => id}, socket) do
    case CliAccess.revoke_request(id, "admin") do
      {:ok, _request} ->
        {:noreply, reload(socket) |> put_flash(:info, "CLI access revoked")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Revoke failed: #{inspect(reason)}")}
    end
  end

  @impl true
  def handle_info(:refresh_cli_access, socket) do
    schedule_refresh()
    {:noreply, reload(socket)}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="space-y-6">
      <div class="flex items-center justify-between gap-4">
        <div>
          <h2 class="text-xl font-semibold text-on-surface">CLI Access</h2>
          <p class="text-sm text-on-surface-variant">
            Approve pending CLI logins and bind them to an AppRole.
          </p>
        </div>
      </div>

      <div class="overflow-x-auto rounded-lg bg-surface-container shadow">
        <table class="min-w-full divide-y divide-outline-variant">
          <thead class="bg-surface-container-low">
            <tr>
              <th class="px-4 py-3 text-left text-xs font-medium uppercase">Code</th>
              <th class="px-4 py-3 text-left text-xs font-medium uppercase">Client</th>
              <th class="px-4 py-3 text-left text-xs font-medium uppercase">Version</th>
              <th class="px-4 py-3 text-left text-xs font-medium uppercase">Source IP</th>
              <th class="px-4 py-3 text-left text-xs font-medium uppercase">Status</th>
              <th class="px-4 py-3 text-left text-xs font-medium uppercase">Submitted</th>
              <th class="px-4 py-3 text-left text-xs font-medium uppercase">Expires</th>
              <th class="px-4 py-3 text-left text-xs font-medium uppercase">Role</th>
              <th class="px-4 py-3 text-left text-xs font-medium uppercase">Actions</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-outline-variant">
            <%= if Enum.empty?(@requests) do %>
              <tr>
                <td colspan="9" class="px-4 py-6 text-center text-sm text-on-surface-variant">
                  No CLI access requests
                </td>
              </tr>
            <% end %>

            <%= for request <- @requests do %>
              <tr class="hover:bg-surface-container-low">
                <td class="px-4 py-3 font-mono text-lg font-semibold tracking-widest text-on-surface">
                  {request.user_code}
                </td>
                <td class="px-4 py-3 text-sm">{metadata_value(request, "client_name")}</td>
                <td class="px-4 py-3 text-sm">{metadata_value(request, "cli_version")}</td>
                <td class="px-4 py-3 text-sm">{request.source_ip || "-"}</td>
                <td class="px-4 py-3 text-sm">
                  <span class={status_badge_class(request.status)}>
                    {status_label(request.status)}
                  </span>
                </td>
                <td class="px-4 py-3 text-sm">{format_dt(request.inserted_at)}</td>
                <td class="px-4 py-3 text-sm">{format_dt(request.expires_at)}</td>
                <td class="px-4 py-3 text-sm">
                  <%= if request.status == :pending do %>
                    <form
                      id={"approve-cli-access-#{request.id}"}
                      phx-submit="approve_cli_access"
                      phx-value-id={request.id}
                      class="flex min-w-64 items-center gap-2"
                    >
                      <select
                        name="role_id"
                        class="min-w-48 rounded-md border border-outline-variant bg-surface-container px-3 py-2 text-sm text-on-surface focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary"
                        disabled={Enum.empty?(@roles)}
                      >
                        <%= for role <- @roles do %>
                          <option value={role.role_id}>{role.role_name}</option>
                        <% end %>
                      </select>
                    </form>
                  <% else %>
                    {role_name_for(@roles, request.role_id)}
                  <% end %>
                </td>
                <td class="px-4 py-3 text-sm">
                  <%= if request.status == :pending do %>
                    <div class="flex gap-2">
                      <button
                        type="submit"
                        form={"approve-cli-access-#{request.id}"}
                        class="btn btn-primary btn-sm"
                        disabled={Enum.empty?(@roles)}
                      >
                        Approve
                      </button>
                      <button
                        type="button"
                        class="btn btn-secondary btn-sm"
                        phx-click="reject_cli_access"
                        phx-value-id={request.id}
                      >
                        Reject
                      </button>
                    </div>
                  <% else %>
                    <%= if request.status == :approved do %>
                      <button
                        type="button"
                        class="btn btn-secondary btn-sm"
                        phx-click="revoke_cli_access"
                        phx-value-id={request.id}
                      >
                        Revoke
                      </button>
                    <% else %>
                      <span class="text-on-surface-variant">-</span>
                    <% end %>
                  <% end %>
                </td>
              </tr>
            <% end %>
          </tbody>
        </table>
      </div>
    </div>
    """
  end

  defp reload(socket) do
    assign(socket, requests: CliAccess.list_visible(), roles: AppRole.list_roles())
  end

  defp schedule_refresh do
    Process.send_after(self(), :refresh_cli_access, @refresh_interval_ms)
  end

  defp metadata_value(%{metadata: metadata}, key) when is_map(metadata) do
    case Map.get(metadata, key) do
      value when is_binary(value) and value != "" -> value
      _ -> "-"
    end
  end

  defp metadata_value(_request, _key), do: "-"

  defp role_name_for(_roles, nil), do: "-"

  defp role_name_for(roles, role_id) do
    case Enum.find(roles, &(&1.role_id == role_id)) do
      nil -> role_id || "-"
      role -> role.role_name
    end
  end

  defp status_label(:pending), do: "Pending"
  defp status_label(:approved), do: "Approved"
  defp status_label(:revoked), do: "Revoked"
  defp status_label(:rejected), do: "Rejected"
  defp status_label(:expired), do: "Expired"
  defp status_label(:consumed), do: "Consumed"
  defp status_label(status), do: status |> to_string() |> String.capitalize()

  defp status_badge_class(:pending),
    do: badge_class("bg-warning-container text-on-warning-container")

  defp status_badge_class(:approved),
    do: badge_class("bg-primary-container text-on-primary-container")

  defp status_badge_class(:revoked), do: badge_class("bg-error-container text-on-error-container")
  defp status_badge_class(_status), do: badge_class("bg-surface-container-high text-on-surface")

  defp badge_class(extra_classes) do
    "inline-flex rounded-full px-2 py-1 text-xs font-medium #{extra_classes}"
  end

  defp format_dt(nil), do: "-"
  defp format_dt(dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S")
end
