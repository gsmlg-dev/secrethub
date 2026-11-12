defmodule SecretHub.Web.SSHAccess.Identities do
  @moduledoc "Identities tab: Agent-held and external SSH identities with rotation state."
  use Phoenix.Component
  use PhoenixDuskmoon.Component
  alias SecretHub.Core.SSH.Identities, as: Lifecycle

  attr :inventory, :map, required: true

  def tab(assigns) do
    assigns = assign(assigns, :now, DateTime.utc_now())

    ~H"""
    <div id="identities-tab" class="space-y-6">
      <.dm_card id="ssh-identities">
        <:title>Identities</:title>
        <p :if={@inventory.identities == []} class="text-sm text-on-surface-variant">
          No identities. Agents enroll one per local user on first signing use; add external keys below.
        </p>
        <%!-- Native table: dm_table columns cannot hold a per-row rotation form. --%>
        <div :if={@inventory.identities != []} class="overflow-auto">
          <table class="w-full text-sm">
            <thead>
              <tr class="text-left text-on-surface-variant">
                <th>Identity</th>
                <th>Origin</th>
                <th>Fingerprint</th>
                <th>Status</th>
                <th>Rotation</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              <tr
                :for={identity <- @inventory.identities}
                id={"identity-" <> identity.id}
                class="border-t border-outline-variant"
              >
                <td class="py-2 font-medium">{identity.name}</td>
                <td>{if identity.origin == "agent", do: "Agent", else: "External"}</td>
                <td class="font-mono text-xs">{current_fingerprint(identity)}</td>
                <td>
                  <.dm_badge variant={status_variant(identity)} size="sm">
                    {status(identity, @now)}
                  </.dm_badge>
                </td>
                <td>
                  <.form
                    for={%{}}
                    id={"rotation-" <> identity.id}
                    phx-submit="identity_rotation"
                    class="flex gap-1 items-center"
                  >
                    <input type="hidden" name="rotation[id]" value={identity.id} />
                    <.dm_input
                      name="rotation[days]"
                      value={identity.rotation_days}
                      size="sm"
                      class="w-16"
                      aria-label="Rotation days"
                    />
                    <span class="text-xs text-on-surface-variant">days · {due(identity)}</span>
                  </.form>
                </td>
                <td class="py-2">
                  <span class="flex gap-1">
                    <.dm_btn
                      :if={identity.status == "pending"}
                      id={"approve-" <> identity.id}
                      size="sm"
                      variant="primary"
                      phx-click="identity"
                      phx-value-op="identity_approve"
                      phx-value-id={identity.id}
                    >
                      Approve
                    </.dm_btn>
                    <.dm_btn
                      :if={identity.status == "active" and identity.origin == "agent"}
                      id={"rotate-" <> identity.id}
                      size="sm"
                      variant="secondary"
                      phx-click="identity"
                      phx-value-op="identity_rotate"
                      phx-value-id={identity.id}
                    >
                      Rotate now
                    </.dm_btn>
                    <.dm_btn
                      :if={identity.status != "retired"}
                      id={"revoke-" <> identity.id}
                      size="sm"
                      variant="error"
                      phx-click="identity"
                      phx-value-op="identity_revoke"
                      phx-value-id={identity.id}
                    >
                      Revoke
                    </.dm_btn>
                    <.dm_btn
                      :if={identity.status in ["pending", "retired"]}
                      id={"delete-" <> identity.id}
                      size="sm"
                      variant="ghost"
                      phx-click="identity"
                      phx-value-op="identity_delete"
                      phx-value-id={identity.id}
                    >
                      Delete
                    </.dm_btn>
                  </span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </.dm_card>

      <div class="grid gap-6 md:grid-cols-2">
        <.dm_card>
          <:title>Add external public key</:title>
          <.form for={%{}} id="external-form" phx-submit="external_add" class="space-y-3">
            <.dm_input id="external-name" name="external[name]" label="Name" value="" />
            <.dm_textarea
              id="external-key"
              name="external[public_key]"
              label="OpenSSH public key"
              value=""
            />
            <.dm_input
              id="external-rotation"
              name="external[rotation_days]"
              label="Remind to rotate after (days)"
              value="90"
            />
            <.dm_btn type="submit" variant="primary">Preview</.dm_btn>
          </.form>
        </.dm_card>
        <.dm_card :if={externals(@inventory) != []}>
          <:title>Replace external public key</:title>
          <.form for={%{}} id="replace-form" phx-submit="external_replace" class="space-y-3">
            <.dm_select
              id="replace-id"
              name="replace[id]"
              label="Identity"
              options={Enum.map(externals(@inventory), &{&1.id, &1.name})}
            />
            <.dm_textarea
              id="replace-key"
              name="replace[public_key]"
              label="New OpenSSH public key"
              value=""
            />
            <.dm_btn type="submit" variant="secondary">Preview</.dm_btn>
          </.form>
        </.dm_card>
      </div>
    </div>
    """
  end

  defp externals(inventory),
    do: Enum.filter(inventory.identities, &(&1.origin == "external" and &1.status == "active"))

  defp current_fingerprint(identity),
    do:
      identity.keys
      |> Enum.max_by(& &1.generation, fn -> %{fingerprint: "—"} end)
      |> Map.get(:fingerprint)

  defp status(identity, now) do
    valid = length(Lifecycle.valid_keys(identity, now))

    cond do
      identity.rotation_overdue ->
        "rotation overdue"

      identity.status == "active" and
          identity.requested_generation > Lifecycle.current_generation(identity) ->
        "waiting for device"

      identity.status == "active" and valid > 1 ->
        "rotating (#{valid} keys valid)"

      true ->
        identity.status
    end
  end

  defp status_variant(%{rotation_overdue: true}), do: "warning"
  defp status_variant(%{status: "pending"}), do: "warning"
  defp status_variant(%{status: "active"}), do: "success"
  defp status_variant(_), do: "neutral"

  defp due(%{next_rotation_at: nil}), do: "off"
  defp due(%{next_rotation_at: at}), do: "next " <> Calendar.strftime(at, "%Y-%m-%d")
end
