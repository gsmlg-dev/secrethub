defmodule SecretHub.Web.SSHAccess.Devices do
  @moduledoc "Devices tab: pending host keys and one card per Agent as SSH target and source."
  use Phoenix.Component
  use PhoenixDuskmoon.Component
  alias SecretHub.Shared.SSH.Key

  attr :inventory, :map, required: true
  attr :profile, :map, default: nil

  def tab(assigns) do
    assigns =
      assign(
        assigns,
        :devices,
        Enum.map(assigns.inventory.agents, &device(assigns.inventory, &1))
      )

    ~H"""
    <div class="space-y-6 pt-4">
      <div class="grid gap-4 md:grid-cols-2">
        <.dm_card :for={device <- @devices} id={"device-" <> device.agent.agent_id}>
          <:title>
            <span class="flex items-center justify-between w-full">
              <span>{device.agent.name || device.agent.agent_id}</span>
              <.dm_badge variant={
                if device.agent.status == :trusted_connected, do: "success", else: "neutral"
              }>
                {device.agent.status}
              </.dm_badge>
            </span>
          </:title>
          <div
            :if={device.candidates != []}
            id={"pending-host-" <> device.agent.agent_id}
            class="border border-dashed border-warning rounded p-2 mb-3 text-sm"
          >
            <p class="font-semibold">
              {if device.endpoint.host_keys == [],
                do: "New host keys reported",
                else: "Host keys changed"}
            </p>
            <p :for={key <- device.candidates} class="font-mono text-xs break-all">
              {fingerprint(key)}
            </p>
            <p
              :for={key <- device.endpoint.host_keys -- device.candidates}
              class="font-mono text-xs break-all line-through"
            >
              {fingerprint(key)}
            </p>
          </div>

          <section :if={"ssh_lookup_v1" in device.agent.runtime_capabilities} class="space-y-2">
            <h4 class="text-sm text-on-surface-variant">As target</h4>
            <.form
              for={%{}}
              id={"endpoint-form-" <> device.agent.agent_id}
              phx-submit="endpoint"
              class="grid grid-cols-3 gap-2 items-end"
            >
              <input type="hidden" name="endpoint[agent_id]" value={device.agent.agent_id} />
              <div class="col-span-2">
                <.dm_input
                  id={"aliases-" <> device.agent.agent_id}
                  name="endpoint[aliases]"
                  label="Aliases"
                  value={Enum.join((device.endpoint && device.endpoint.aliases) || [], " ")}
                />
              </div>
              <.dm_input
                id={"port-" <> device.agent.agent_id}
                name="endpoint[port]"
                type="number"
                label="Port"
                min="1"
                max="65535"
                value={(device.endpoint && device.endpoint.port) || 22}
              />
              <div class="col-span-3 flex gap-2">
                <.dm_btn
                  :if={device.candidates != []}
                  id={"trust-" <> device.agent.agent_id}
                  type="submit"
                  name="trust"
                  value="candidates"
                  variant="primary"
                >
                  Trust reported keys
                </.dm_btn>
                <.dm_btn
                  :if={device.candidates == [] or device.trusted?}
                  id={"keep-" <> device.agent.agent_id}
                  type="submit"
                  name="trust"
                  value="keep"
                  variant="ghost"
                >
                  {if device.candidates != [], do: "Keep current keys", else: "Save"}
                </.dm_btn>
              </div>
            </.form>
            <p class="text-xs">Logins: {device.logins}</p>
          </section>
          <p
            :if={"ssh_lookup_v1" not in device.agent.runtime_capabilities}
            class="text-xs text-on-surface-variant"
          >
            Not an SSH target (lookup capability not enabled).
          </p>

          <section class="space-y-1 mt-3">
            <h4 class="text-sm text-on-surface-variant">As source</h4>
            <p :for={identity <- device.identities} class="text-xs">
              {identity.name} · {identity.status} · {next_rotation(identity)}
            </p>
            <p :if={device.identities == []} class="text-xs text-on-surface-variant">
              No identities yet. A local user's first use of the signing socket enrolls one.
            </p>
          </section>
        </.dm_card>
      </div>

      <.dm_card id="ssh-profiles">
        <:title>Generate managed OpenSSH profiles</:title>
        <p class="text-sm text-on-surface-variant">
          Use a root-owned release path. Validate effective configuration before installation; earlier Match blocks can take precedence. Existing sessions continue after policy revocation.
        </p>
        <.form
          for={%{}}
          id="ssh-profile-form"
          phx-submit="profiles"
          class="grid gap-4 mt-4 sm:grid-cols-2"
        >
          <.dm_input
            id="ssh-profile-base"
            name="profile[base]"
            label="Release base"
            value="/opt/secrethub-agent"
          />
          <.dm_input
            id="ssh-profile-hosts"
            name="profile[hosts]"
            label="Managed destination aliases / IPs"
            value={
              @inventory.endpoints
              |> Enum.filter(& &1.approved)
              |> Enum.flat_map(& &1.aliases)
              |> Enum.uniq()
              |> Enum.join(" ")
            }
            required
          />
          <.dm_input
            id="ssh-profile-users"
            name="profile[users]"
            label="Managed destination Unix users"
            placeholder="deploy builder"
          />
          <.dm_input
            id="ssh-profile-lookup"
            name="profile[lookup_socket]"
            label="Lookup socket"
            value="/run/secrethub-ssh/lookup.sock"
          />
          <.dm_input
            id="ssh-profile-signing"
            name="profile[signing_socket]"
            label="Signing socket"
            value="/run/secrethub-ssh-signing/agent.sock"
          />
          <.dm_btn type="submit" variant="secondary">Generate profiles</.dm_btn>
        </.form>
        <div :if={@profile} class="grid gap-4 mt-4 lg:grid-cols-2">
          <.dm_textarea
            id="ssh-client-profile"
            name="client_profile"
            value={@profile.client}
            label="Dedicated ssh -F client profile"
            rows={12}
            readonly
          />
          <.dm_textarea
            id="ssh-server-profile"
            name="server_profile"
            value={@profile.server}
            label="sshd managed account include"
            rows={12}
            readonly
          />
        </div>
      </.dm_card>
    </div>
    """
  end

  defp device(inventory, agent) do
    endpoint = Enum.find(inventory.endpoints, &(&1.agent_id == agent.agent_id))
    # Only lookup-capable Agents are SSH targets; source-only host keys need no trust.
    target? = "ssh_lookup_v1" in agent.runtime_capabilities

    %{
      agent: agent,
      endpoint: endpoint,
      trusted?: endpoint != nil and endpoint.approved and endpoint.host_keys != [],
      candidates: if(target?, do: pending_keys(endpoint), else: []),
      identities: Enum.filter(inventory.identities, &(&1.agent_id == agent.agent_id)),
      logins: logins(inventory, agent.agent_id)
    }
  end

  defp pending_keys(nil), do: []

  defp pending_keys(endpoint) do
    candidates = Map.get(endpoint, :candidate_host_keys, [])
    if candidates == endpoint.host_keys, do: [], else: candidates
  end

  defp logins(inventory, agent_id) do
    inventory.edges
    |> Enum.filter(&(&1.destination_agent_id == agent_id))
    |> Enum.map(fn edge ->
      name =
        Enum.find_value(
          inventory.identities,
          edge.identity_id,
          &(&1.id == edge.identity_id && &1.name)
        )

      "#{name} → #{edge.destination_user}"
    end)
    |> case do
      [] -> "none"
      list -> Enum.join(list, ", ")
    end
  end

  defp next_rotation(%{next_rotation_at: nil}), do: "no scheduled rotation"

  defp next_rotation(%{next_rotation_at: at}),
    do: "rotates #{Calendar.strftime(at, "%Y-%m-%d")}"

  defp fingerprint(key) do
    case Key.decode_public(key) do
      {:ok, public} -> public.fingerprint
      _ -> "invalid key"
    end
  end
end
