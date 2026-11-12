defmodule SecretHub.Web.SSHAccessLive do
  @moduledoc "SSH devices, identities and access with revisioned, readable batch previews."
  # Events may carry key material. Disable LiveView parameter logging.
  use Phoenix.LiveView, layout: {SecretHub.Web.Layouts, :app}, log: false
  use PhoenixDuskmoon.Component
  use SecretHub.Web, :verified_routes
  alias Phoenix.LiveView.JS
  alias SecretHub.Core.SSH
  alias SecretHub.Shared.SSH.Profiles
  alias SecretHub.Web.SSHAccess.{Access, Devices, Identities, Preview}

  defmodule Pending do
    @moduledoc false
    @derive {Inspect, except: [:changes]}
    defstruct [:changes, :preview, :revision]
  end

  @tabs [{"devices", "Devices"}, {"identities", "Identities"}, {"access", "Access"}]
  @tab_names Enum.map(@tabs, &elem(&1, 0))

  @impl true
  def mount(_, _, socket) do
    if connected?(socket), do: Phoenix.PubSub.subscribe(SecretHub.Web.PubSub, "ssh:policy")

    {:ok,
     socket
     |> assign(
       page_title: "SSH Access",
       tabs: @tabs,
       tab: "devices",
       pending: nil,
       message: nil,
       editing_group: nil,
       profile: nil
     )
     |> reload()}
  end

  @impl true
  def handle_event("tab", %{"tab" => tab}, socket) when tab in @tab_names,
    do: {:noreply, assign(socket, tab: tab)}

  def handle_event("endpoint", %{"endpoint" => %{"agent_id" => id} = attrs} = params, socket) do
    endpoint = Enum.find(socket.assigns.inventory.endpoints, &(&1.agent_id == id)) || %{}

    keys =
      if params["trust"] == "candidates",
        do: Map.get(endpoint, :candidate_host_keys, []),
        else: Map.get(endpoint, :host_keys, [])

    stage(socket, [
      %{
        "op" => "endpoint_upsert",
        "agent_id" => id,
        "aliases" => words(attrs["aliases"]),
        "port" => integer(attrs["port"]),
        "host_keys" => keys,
        "approved" => keys != []
      }
    ])
  end

  def handle_event("endpoint_delete", %{"agent_id" => id}, socket),
    do: stage(socket, [%{"op" => "endpoint_delete", "agent_id" => id}])

  def handle_event("identity", %{"op" => op, "id" => id}, socket)
      when op in ~w(identity_approve identity_revoke identity_rotate identity_delete),
      do: stage(socket, [%{"op" => op, "id" => id}])

  def handle_event("identity_rotation", %{"rotation" => %{"id" => id, "days" => days}}, socket),
    do:
      stage(socket, [
        %{"op" => "identity_rotation", "id" => id, "rotation_days" => rotation_days(days)}
      ])

  def handle_event("external_add", %{"external" => attrs}, socket),
    do:
      stage(socket, [
        %{
          "op" => "identity_external_add",
          "name" => String.trim(attrs["name"] || ""),
          "public_key" => String.trim(attrs["public_key"] || ""),
          "rotation_days" => rotation_days(attrs["rotation_days"])
        }
      ])

  def handle_event(
        "external_replace",
        %{"replace" => %{"id" => id, "public_key" => key}},
        socket
      ),
      do:
        stage(socket, [
          %{"op" => "identity_external_replace", "id" => id, "public_key" => String.trim(key)}
        ])

  def handle_event("cell", %{"cell" => attrs}, socket) do
    case Access.cell_changes(socket.assigns.inventory, attrs) do
      {:ok, changes} -> stage(socket, changes)
      {:error, reason} -> {:noreply, assign(socket, pending: nil, message: error_message(reason))}
    end
  end

  def handle_event("group_edit", %{"id" => id}, socket),
    do:
      {:noreply,
       assign(socket,
         editing_group: Enum.find(socket.assigns.inventory.groups, &(&1.id == id))
       )}

  def handle_event("group_new", %{"kind" => kind}, socket) when kind in ["host", "identity"],
    do: {:noreply, assign(socket, editing_group: %{id: nil, name: "", kind: kind})}

  def handle_event("group_close", _, socket), do: {:noreply, assign(socket, editing_group: nil)}

  def handle_event("group_save", %{"group" => attrs}, socket) do
    id = if attrs["id"] in [nil, ""], do: Ecto.UUID.generate(), else: attrs["id"]

    stage(socket, [
      %{"op" => "group_upsert", "id" => id, "name" => attrs["name"], "kind" => attrs["kind"]},
      %{
        "op" => "group_members",
        "group_id" => id,
        "member_ids" => List.wrap(attrs["member_ids"])
      }
    ])
  end

  def handle_event("group_delete", %{"id" => id}, socket),
    do: stage(socket, [%{"op" => "group_delete", "id" => id}])

  def handle_event("cancel", _, socket),
    do: {:noreply, assign(socket, pending: nil, message: nil)}

  def handle_event("refresh", _, socket),
    do: {:noreply, reload(socket) |> assign(pending: nil, message: nil)}

  def handle_event("confirm", _, %{assigns: %{pending: %Pending{} = pending}} = socket) do
    case SSH.apply_changes(pending.changes, pending.revision) do
      {:ok, _} ->
        {:noreply,
         socket
         |> assign(pending: nil, editing_group: nil, message: "SSH changes saved.")
         |> reload()}

      {:error, reason} ->
        {:noreply, socket |> assign(pending: nil, message: error_message(reason)) |> reload()}
    end
  rescue
    _ -> {:noreply, assign(socket, pending: nil, message: "SSH changes could not be saved.")}
  end

  def handle_event("profiles", %{"profile" => attrs}, socket) do
    opts = [
      base: attrs["base"],
      hosts: words(attrs["hosts"]),
      lookup_socket: attrs["lookup_socket"],
      signing_socket: attrs["signing_socket"],
      users: words(attrs["users"])
    ]

    with {:ok, client} <- Profiles.client(opts), {:ok, server} <- Profiles.server(opts) do
      {:noreply, assign(socket, :profile, %{client: client, server: server})}
    else
      _ ->
        {:noreply,
         assign(socket,
           message: "Use absolute paths without spaces and explicit Unix usernames.",
           profile: nil
         )}
    end
  end

  def handle_event(_, _, socket), do: {:noreply, socket}

  @impl true
  def handle_info({:ssh_policy_changed, _}, socket),
    do: {:noreply, socket |> reload() |> refresh_editing_group()}

  defp stage(socket, changes) when changes == [] or length(changes) > 500,
    do: {:noreply, assign(socket, pending: nil, message: "Select between 1 and 500 changes.")}

  defp stage(socket, changes) do
    revision = socket.assigns.inventory.revision

    case SSH.preview(changes, revision) do
      {:ok, preview} ->
        {:noreply,
         assign(socket,
           pending: %Pending{changes: changes, preview: preview, revision: revision},
           message: nil
         )}

      {:error, reason} ->
        {:noreply, socket |> assign(pending: nil, message: error_message(reason)) |> reload()}
    end
  rescue
    _ ->
      {:noreply,
       assign(socket, pending: nil, message: "SSH changes are invalid or Core is unavailable.")}
  end

  defp reload(socket) do
    case SSH.snapshot() do
      %{revision: _} = inventory ->
        assign(socket, inventory: inventory, counts: counts(inventory))

      _ ->
        assign(socket, :message, "SSH inventory is unavailable.")
    end
  end

  # A group being created has no id yet; an edited group follows the reloaded inventory.
  defp refresh_editing_group(%{assigns: %{editing_group: %{id: id}}} = socket)
       when is_binary(id),
       do:
         assign(socket,
           editing_group: Enum.find(socket.assigns.inventory.groups, &(&1.id == id))
         )

  defp refresh_editing_group(socket), do: socket

  # Inventory reports always create an endpoint record holding candidate_host_keys,
  # so counting endpoints also covers Agents that have never been trusted.
  # Only lookup-capable Agents can be SSH targets, so only their host keys need trust.
  defp counts(inventory) do
    lookup_agents =
      for agent <- inventory.agents,
          "ssh_lookup_v1" in agent.runtime_capabilities,
          do: agent.agent_id

    %{
      "devices" =>
        Enum.count(inventory.endpoints, fn endpoint ->
          endpoint.agent_id in lookup_agents and
            Map.get(endpoint, :candidate_host_keys, []) not in [[], endpoint.host_keys]
        end),
      "identities" =>
        Enum.count(inventory.identities, &(&1.status == "pending" or &1.rotation_overdue)),
      "access" => 0
    }
  end

  defp words(value), do: value |> to_string() |> String.split(~r/[\s,]+/, trim: true)

  defp integer(value) when is_integer(value), do: value

  defp integer(value) do
    case Integer.parse(to_string(value)) do
      {number, ""} -> number
      _ -> nil
    end
  end

  # Blank disables scheduled rotation; anything else non-integer reaches Core and is rejected.
  defp rotation_days(value) do
    case String.trim(to_string(value)) do
      "" -> nil
      text -> integer(text) || text
    end
  end

  defp error_message(:stale_revision),
    do: "SSH configuration changed. Review a new preview before saving."

  defp error_message(:sealed), do: "Unseal the Vault before changing SSH configuration."

  defp error_message(:duplicate_key),
    do: "That public key is already used by another identity."

  defp error_message(:invalid_name),
    do: "Use a unique name of letters, digits, '.', '_', '-' or '@'."

  defp error_message(:invalid_public_key), do: "Paste one OpenSSH public key line."

  defp error_message(:invalid_rotation),
    do: "Rotation days must be between 1 and 3650, or blank to disable."

  defp error_message(:endpoint_conflict),
    do: "That endpoint alias and port already belong to another machine."

  defp error_message(:name_taken), do: "That identity name is already used."

  defp error_message(:destination_user_required), do: "Enter a destination user."

  defp error_message(:group_in_use),
    do: "Remove this group's access cells before deleting the group."

  defp error_message(_), do: "SSH changes are invalid or Core is unavailable."

  @impl true
  def render(assigns) do
    ~H"""
    <div class="max-w-7xl mx-auto space-y-6 p-4 text-on-surface">
      <div class="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 class="text-3xl font-bold">SSH Access</h1>
          <p class="text-sm text-on-surface-variant">
            Default deny · matching deny wins · configuration revision {@inventory.revision}
          </p>
        </div>
        <.dm_btn variant="ghost" phx-click="refresh">Refresh</.dm_btn>
      </div>

      <.dm_alert :if={@message} variant="info" id="ssh-message">{@message}</.dm_alert>

      <.dm_card :if={@pending} id="ssh-preview" class="border border-outline">
        <:title>Review changes</:title>
        <p :if={@pending.revision != @inventory.revision} class="text-error">
          Configuration changed. This preview must be regenerated.
        </p>
        <ul class="text-sm list-disc pl-5">
          <li :for={line <- Preview.changes(@pending.changes, @inventory)}>{line}</li>
        </ul>
        <ul class="text-sm mt-2">
          <li
            :for={{kind, line} <- Preview.edges(@pending.preview, @inventory)}
            class={if kind == :gained, do: "text-success", else: "text-error"}
          >
            {if kind == :gained, do: "+ ", else: "− "}{line}
          </li>
        </ul>
        <p class="text-xs text-on-surface-variant mt-2">
          Each runtime request also checks current certificates, capabilities and local user identity.
        </p>
        <:action>
          <.dm_btn variant="ghost" phx-click="cancel">Cancel</.dm_btn>
          <.dm_btn id="ssh-confirm" variant="primary" phx-click="confirm">Confirm changes</.dm_btn>
        </:action>
      </.dm_card>

      <.dm_tab id="ssh-tabs" active_tab_name={@tab}>
        <:tab
          :for={{tab, label} <- @tabs}
          id={"ssh-tab-" <> tab}
          name={tab}
          phx_click={JS.push("tab", value: %{tab: tab})}
        >
          {label}
          <.dm_badge
            :if={@counts[tab] > 0}
            id={"ssh-tab-count-" <> tab}
            variant="warning"
            size="sm"
          >
            {@counts[tab]}
          </.dm_badge>
        </:tab>
        <:tab_content name="devices">
          <Devices.tab inventory={@inventory} profile={@profile} />
        </:tab_content>
        <:tab_content name="identities">
          <Identities.tab inventory={@inventory} />
        </:tab_content>
        <:tab_content name="access">
          <Access.tab inventory={@inventory} editing_group={@editing_group} />
        </:tab_content>
      </.dm_tab>
    </div>
    """
  end
end
