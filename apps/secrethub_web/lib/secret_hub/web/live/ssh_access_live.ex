defmodule SecretHub.Web.SSHAccessLive do
  @moduledoc "Group SSH inventory, directed rules and revisioned batch previews."
  # Import events may contain a private key. Disable LiveView parameter logging.
  use Phoenix.LiveView, layout: {SecretHub.Web.Layouts, :app}, log: false
  use PhoenixDuskmoon.Component
  use SecretHub.Web, :verified_routes
  alias SecretHub.Core.SSH
  alias SecretHub.Core.SSH.Evaluator
  alias SecretHub.Shared.SSH.{Key, Profiles}

  defmodule Pending do
    @moduledoc false
    @derive {Inspect, except: [:changes]}
    defstruct [:changes, :preview, :revision]
  end

  @impl true
  def mount(_, _, socket) do
    if connected?(socket), do: Phoenix.PubSub.subscribe(SecretHub.Web.PubSub, "ssh:policy")

    {:ok,
     socket
     |> assign(
       page_title: "SSH Access",
       pending: nil,
       message: nil,
       import_generation: 0,
       group_form: %{},
       members_form: %{},
       endpoint_form: %{},
       identity_form: %{},
       rule_form: %{},
       filters: %{"source_group" => "", "destination_group" => ""},
       profile: nil
     )
     |> reload()}
  end

  @impl true
  def handle_event("preview_group", %{"group" => attrs}, socket) do
    change = attrs |> Map.take(["id", "name"]) |> omit_empty_id() |> Map.put("op", "group_upsert")
    stage(socket, [change])
  end

  def handle_event("preview_members", %{"members" => attrs}, socket) do
    stage(socket, [
      %{
        "op" => "group_members",
        "group_id" => attrs["group_id"],
        "agent_ids" => List.wrap(attrs["agent_ids"])
      }
    ])
  end

  def handle_event("preview_endpoint", %{"endpoint" => attrs}, socket) do
    stage(socket, [
      %{
        "op" => "endpoint_upsert",
        "agent_id" => attrs["agent_id"],
        "aliases" => words(attrs["aliases"]),
        "host_keys" => lines(attrs["host_keys"]),
        "port" => integer(attrs["port"]),
        "approved" => attrs["approved"] == "true"
      }
    ])
  end

  def handle_event("preview_identity", %{"identity" => attrs}, socket) do
    change =
      attrs
      |> Map.take(["agent_id", "username", "algorithm"])
      |> Map.put("uid", integer(attrs["uid"]))
      |> Map.put("op", "identity_upsert")

    change =
      if String.trim(attrs["private_key"] || "") == "",
        do: change,
        else: Map.put(change, "private_key", attrs["private_key"])

    socket =
      assign(socket, import_generation: socket.assigns.import_generation + 1, identity_form: %{})

    stage(socket, [change])
  end

  def handle_event("preview_rules", %{"rule" => attrs}, socket) do
    sources = List.wrap(attrs["sources"])
    destinations = List.wrap(attrs["destinations"])

    changes =
      for source <- sources, destination <- destinations do
        rule_change(
          source,
          attrs["source_user"],
          destination,
          attrs["destination_user"],
          attrs["effect"],
          attrs["id"]
        )
        |> Map.put("enabled", attrs["enabled"] != "false")
      end

    if attrs["id"] not in [nil, ""] and length(changes) != 1,
      do:
        {:noreply,
         assign(socket,
           pending: nil,
           message: "Edit one rule at a time, or cancel editing to create a batch."
         )},
      else: stage(socket, changes)
  end

  def handle_event("preview_revoke", %{"revoke" => attrs}, socket) do
    stage(socket, for(id <- List.wrap(attrs["ids"]), do: %{"op" => "rule_delete", "id" => id}))
  end

  def handle_event("matrix_batch", attrs, socket) do
    changes =
      for encoded <- List.wrap(attrs["cells"]) do
        case Base.url_decode64(encoded, padding: false) do
          {:ok, json} ->
            case Jason.decode(json) do
              {:ok, [source, user, destination, target_user]}
              when is_binary(source) and is_binary(destination) ->
                rule_change(
                  "agent/" <> source,
                  user,
                  "agent/" <> destination,
                  target_user,
                  attrs["effect"],
                  nil
                )

              _ ->
                %{}
            end

          _ ->
            %{}
        end
      end

    stage(socket, changes)
  end

  def handle_event("preview_delete", %{"kind" => kind, "id" => id}, socket)
      when kind in ["group", "endpoint", "identity", "rule"] do
    operation = if kind == "identity", do: "identity_revoke", else: kind <> "_delete"
    stage(socket, [%{"op" => operation, "id" => id}])
  end

  def handle_event("edit_group", %{"id" => id}, socket) do
    case Enum.find(socket.assigns.inventory.groups, &(&1.id == id)) do
      nil ->
        {:noreply, socket}

      group ->
        {:noreply,
         assign(socket,
           group_form: stringify(Map.take(group, [:id, :name])),
           members_form: %{"group_id" => id, "agent_ids" => group.agent_ids}
         )}
    end
  end

  def handle_event("edit_endpoint", %{"id" => id}, socket) do
    case Enum.find(socket.assigns.inventory.endpoints, &(&1.agent_id == id)) do
      nil ->
        {:noreply, socket}

      endpoint ->
        {:noreply,
         assign(socket, :endpoint_form, %{
           "agent_id" => id,
           "port" => endpoint.port,
           "aliases" => Enum.join(endpoint.aliases, "\n"),
           "host_keys" => Enum.join(endpoint.host_keys, "\n"),
           "approved" => to_string(endpoint.approved)
         })}
    end
  end

  def handle_event("edit_rule", %{"id" => id}, socket) do
    case Enum.find(socket.assigns.inventory.rules, &(&1.id == id)) do
      nil ->
        {:noreply, socket}

      rule ->
        {:noreply,
         assign(socket, :rule_form, %{
           "id" => rule.id,
           "sources" => [rule.source_kind <> "/" <> rule.source_id],
           "destinations" => [rule.destination_kind <> "/" <> rule.destination_id],
           "source_user" => rule.source_user,
           "destination_user" => rule.destination_user,
           "effect" => rule.effect,
           "enabled" => to_string(rule.enabled)
         })}
    end
  end

  def handle_event("filter", %{"filter" => attrs}, socket),
    do: {:noreply, assign(socket, :filters, attrs) |> matrix()}

  def handle_event("cancel_rule_edit", _, socket),
    do: {:noreply, assign(socket, rule_form: %{}, pending: nil, message: nil)}

  def handle_event("cancel", _, socket),
    do: {:noreply, assign(socket, pending: nil, message: nil)}

  def handle_event("refresh", _, socket),
    do: {:noreply, reload(socket) |> assign(pending: nil, message: nil)}

  def handle_event("confirm", _, %{assigns: %{pending: %Pending{} = pending}} = socket) do
    case SSH.apply_changes(pending.changes, pending.revision) do
      {:ok, _} ->
        {:noreply,
         socket
         |> assign(pending: nil, message: "SSH changes saved.", group_form: %{}, rule_form: %{})
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
  def handle_info({:ssh_policy_changed, _}, socket), do: {:noreply, reload(socket)}

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
      %{revision: _} = inventory -> assign(socket, :inventory, inventory) |> matrix()
      _ -> assign(socket, :message, "SSH inventory is unavailable.")
    end
  end

  defp matrix(socket) do
    inventory = socket.assigns.inventory
    rows = for identity <- inventory.identities, do: {identity.agent_id, identity.username}

    rows =
      rows ++
        for rule <- inventory.rules,
            agent <- selected_agents(inventory, rule.source_kind, rule.source_id),
            do: {agent, rule.source_user}

    columns =
      for rule <- inventory.rules,
          agent <- selected_agents(inventory, rule.destination_kind, rule.destination_id),
          do: {agent, rule.destination_user}

    filter = socket.assigns.filters

    rows =
      rows
      |> Enum.uniq()
      |> Enum.sort()
      |> Enum.filter(fn {id, _} -> in_group?(inventory, id, filter["source_group"]) end)

    columns =
      columns
      |> Enum.uniq()
      |> Enum.sort()
      |> Enum.filter(fn {id, _} -> in_group?(inventory, id, filter["destination_group"]) end)

    assign(socket,
      matrix_rows: rows,
      matrix_columns: columns,
      agent_options: Enum.map(inventory.agents, &{&1.agent_id, &1.name || &1.agent_id}),
      group_options: Enum.map(inventory.groups, &{&1.id, &1.name}),
      selector_options:
        Enum.map(
          inventory.agents,
          &{"agent/" <> &1.agent_id, "Machine: " <> (&1.name || &1.agent_id)}
        ) ++
          Enum.map(inventory.groups, &{"group/" <> &1.id, "Group: " <> &1.name})
    )
  end

  defp selected_agents(_, "agent", id), do: [id]

  defp selected_agents(inventory, "group", id) do
    case Enum.find(inventory.groups, &(&1.id == id)) do
      nil -> []
      group -> group.agent_ids
    end
  end

  defp in_group?(_, _, group) when group in [nil, ""], do: true
  defp in_group?(inventory, id, group), do: id in selected_agents(inventory, "group", group)

  defp decision(inventory, {source, user}, {destination, target}),
    do: Evaluator.decision(inventory, source, user, destination, target)

  defp cell_value({source, user}, {destination, target}),
    do: Jason.encode!([source, user, destination, target]) |> Base.url_encode64(padding: false)

  defp label({agent, user}), do: agent <> ":" <> user

  defp fingerprint(key) do
    case Key.decode_public(key) do
      {:ok, public} -> public.fingerprint
      _ -> "Invalid public key"
    end
  end

  defp prerequisites(inventory, agent, username) do
    identity =
      Enum.find(
        inventory.identities,
        &(&1.agent_id == agent and &1.username == username and &1.active)
      )

    machine = Enum.find(inventory.agents, &(&1.agent_id == agent))
    observed = machine && Enum.find(Map.get(machine, :ssh_users, []), &(&1.username == username))

    cond do
      is_nil(identity) ->
        "Source binding missing"

      is_nil(machine) or "ssh_signing_v1" not in machine.runtime_capabilities ->
        "Signing capability unavailable"

      is_nil(Map.get(machine, :ssh_inventory_seen_at)) ->
        "Prerequisites unverified"

      is_nil(observed) or observed.uid != identity.uid or not observed.unambiguous ->
        "Unix user/UID needs confirmation"

      not observed.signing_access or not observed.lookup_access ->
        "Socket group access missing"

      true ->
        "Prerequisites observed; runtime checks still apply"
    end
  end

  defp rule_change(source, user, destination, target, effect, id)
       when is_binary(source) and is_binary(destination) do
    with [source_kind, source_id] <- String.split(source, "/", parts: 2),
         [destination_kind, destination_id] <- String.split(destination, "/", parts: 2) do
      %{
        "op" => "rule_upsert",
        "effect" => effect,
        "enabled" => true,
        "source_kind" => source_kind,
        "source_id" => source_id,
        "source_user" => user,
        "destination_kind" => destination_kind,
        "destination_id" => destination_id,
        "destination_user" => target
      }
      |> then(fn change -> if id in [nil, ""], do: change, else: Map.put(change, "id", id) end)
    else
      _ -> %{}
    end
  end

  defp rule_change(_, _, _, _, _, _), do: %{}

  # TODO(upstream): duskmoon-dev/phoenix-duskmoon-ui#205
  # WORKAROUND(upstream): duskmoon-dev/phoenix-duskmoon-ui#205
  # dm_checkbox currently emits boolean values only. Compose native controls
  # for record selection until the package supports explicit array values.
  attr :id, :string, required: true
  attr :name, :string, required: true
  attr :value, :string, required: true
  attr :label, :string, required: true

  defp selection_checkbox(assigns) do
    ~H"""
    <label for={@id} class="flex items-center gap-2 cursor-pointer"><input
      id={@id}
      type="checkbox"
      name={@name}
      value={@value}
      class="checkbox checkbox-primary"
    /><span>{@label}</span></label>
    """
  end

  defp integer(value) when is_binary(value) do
    case Integer.parse(value) do
      {n, ""} -> n
      _ -> nil
    end
  end

  defp integer(_), do: nil
  defp words(value), do: String.split(value || "", ~r/[\s,]+/, trim: true)
  defp lines(value), do: String.split(value || "", ~r/\r?\n/, trim: true)
  defp omit_empty_id(%{"id" => ""} = attrs), do: Map.delete(attrs, "id")
  defp omit_empty_id(attrs), do: attrs
  defp stringify(attrs), do: Map.new(attrs, fn {key, value} -> {to_string(key), value} end)

  defp error_message(:stale_revision),
    do: "SSH configuration changed. Review a new preview before saving."

  defp error_message(:sealed), do: "Unseal the Vault before changing SSH configuration."

  defp error_message(:duplicate_identity),
    do: "That UID or signing key is already bound to another identity."

  defp error_message(:endpoint_conflict),
    do: "That endpoint alias and port already belong to another machine."

  defp error_message(:group_in_use), do: "Remove this group's rules before deleting the group."
  defp error_message(_), do: "SSH changes are invalid or Core is unavailable."

  @impl true
  def render(assigns) do
    ~H"""
    <div class="max-w-7xl mx-auto space-y-6 p-4 text-on-surface">
      <div class="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 class="text-3xl font-bold">SSH Access</h1><p class="text-sm text-on-surface-variant">
            Default deny · matching deny wins · configuration revision {@inventory.revision}
          </p>
        </div>
        <.dm_btn variant="ghost" phx-click="refresh">Refresh inventory</.dm_btn>
      </div>
      <.dm_alert :if={@message} variant="info" id="ssh-message">{@message}</.dm_alert>

      <.dm_card :if={@pending} id="ssh-preview" class="border border-outline">
        <:title>Review changes at revision {@pending.revision}</:title>
        <p>Gained: {length(@pending.preview.gained)} · Lost: {length(@pending.preview.lost)}</p>
        <p :if={@pending.revision != @inventory.revision} class="text-error">
          Configuration changed. This preview must be regenerated.
        </p>
        <p class="text-sm text-on-surface-variant">
          These are configured grants. Each runtime request also checks current certificates, capabilities and local user identity.
        </p>
        <ul class="text-sm">
          <li :for={edge <- @pending.preview.gained}>
            + {edge.source_agent_id}:{edge.source_user} → {edge.destination_agent_id}:{edge.destination_user}
          </li><li :for={edge <- @pending.preview.lost}>
            − {edge.source_agent_id}:{edge.source_user} → {edge.destination_agent_id}:{edge.destination_user}
          </li>
        </ul>
        <pre class="overflow-auto text-xs mt-3">{Jason.encode!(@pending.preview.changes, pretty: true)}</pre>
        <:action>
          <.dm_btn variant="ghost" phx-click="cancel">Cancel</.dm_btn><.dm_btn
            id="ssh-confirm"
            variant="primary"
            phx-click="confirm"
          >
            Confirm changes
          </.dm_btn>
        </:action>
      </.dm_card>

      <.dm_card id="ssh-matrix">
        <:title>Access matrix</:title>
        <.form for={%{}} id="ssh-filter-form" phx-change="filter" class="grid gap-4 sm:grid-cols-2">
          <.dm_select
            id="ssh-source-filter"
            name="filter[source_group]"
            label="Source group"
            options={[{"", "All groups"} | @group_options]}
            value={@filters["source_group"]}
          />
          <.dm_select
            id="ssh-target-filter"
            name="filter[destination_group]"
            label="Destination group"
            options={[{"", "All groups"} | @group_options]}
            value={@filters["destination_group"]}
          />
        </.form>
        <p :if={@matrix_rows == []} class="py-4 text-on-surface-variant">
          No source identities. Add a machine/user binding and a directed rule below.
        </p>
        <.form for={%{}} id="ssh-matrix-form" phx-submit="matrix_batch" class="mt-4 space-y-4">
          <div class="overflow-auto">
            <.dm_table data={@matrix_rows} zebra hover>
              <:col :let={row} label="Source machine / user">
                <strong>{label(row)}</strong><p class="text-xs text-on-surface-variant">
                  {prerequisites(@inventory, elem(row, 0), elem(row, 1))}
                </p>
              </:col>
              <:col :let={row} :for={column <- @matrix_columns} label={label(column)}>
                <% result = decision(@inventory, row, column) %>
                <.selection_checkbox
                  id={"cell-" <> cell_value(row, column)}
                  name="cells[]"
                  value={cell_value(row, column)}
                  label={if result.allowed, do: "Configured allow", else: "Denied"}
                />
                <p class="text-xs break-all">allow: {Enum.join(result.allow_rules, ", ")}</p><p class="text-xs break-all">
                  deny: {Enum.join(result.deny_rules, ", ")}
                </p>
              </:col>
            </.dm_table>
          </div>
          <.dm_btn type="submit" name="effect" value="allow" variant="secondary">
            Preview allow selected cells
          </.dm_btn>
          <.dm_btn type="submit" name="effect" value="deny" variant="error">
            Preview deny selected cells
          </.dm_btn>
        </.form>
      </.dm_card>

      <div class="grid gap-6 lg:grid-cols-2">
        <.dm_card>
          <:title>Server groups</:title>
          <.form for={%{}} id="ssh-group-form" phx-submit="preview_group" class="space-y-4">
            <.dm_input
              id="ssh-group-id"
              name="group[id]"
              value={@group_form["id"]}
              label="Group ID (blank creates one)"
            />
            <.dm_input
              id="ssh-group-name"
              name="group[name]"
              value={@group_form["name"]}
              label="Group name"
              required
            />
            <.dm_btn type="submit" variant="secondary">Preview group</.dm_btn>
          </.form>
          <ul class="mt-4 space-y-2">
            <li :for={group <- @inventory.groups} class="flex flex-wrap items-center gap-2">
              <strong>{group.name}</strong><span class="text-sm">{length(group.agent_ids)} machines</span><.dm_btn
                size="sm"
                variant="ghost"
                phx-click="edit_group"
                phx-value-id={group.id}
              >
                Edit
              </.dm_btn><.dm_btn
                size="sm"
                variant="ghost"
                phx-click="preview_delete"
                phx-value-kind="group"
                phx-value-id={group.id}
              >
                Delete
              </.dm_btn>
            </li>
          </ul>
          <.form for={%{}} id="ssh-members-form" phx-submit="preview_members" class="mt-6 space-y-4">
            <.dm_select
              id="ssh-member-group"
              name="members[group_id]"
              label="Group membership"
              options={@group_options}
              value={@members_form["group_id"]}
              prompt="Select group"
            />
            <.dm_select
              id="ssh-member-agents"
              name="members[agent_ids][]"
              label="Machines (replaces membership)"
              options={@agent_options}
              value={@members_form["agent_ids"] || []}
              multiple
            />
            <.dm_btn type="submit" variant="secondary">Preview membership change</.dm_btn>
          </.form>
        </.dm_card>

        <.dm_card>
          <:title>SSH endpoints and host-key approval</:title>
          <.form for={%{}} id="ssh-endpoint-form" phx-submit="preview_endpoint" class="space-y-4">
            <.dm_select
              id="ssh-endpoint-agent"
              name="endpoint[agent_id]"
              label="Machine"
              options={@agent_options}
              value={@endpoint_form["agent_id"]}
              prompt="Select machine"
            />
            <.dm_textarea
              id="ssh-aliases"
              name="endpoint[aliases]"
              value={@endpoint_form["aliases"]}
              label="Hostnames / IP aliases"
              rows={2}
            />
            <.dm_input
              id="ssh-port"
              name="endpoint[port]"
              type="number"
              value={@endpoint_form["port"] || 22}
              label="Port"
              min="1"
              max="65535"
            />
            <.dm_textarea
              id="ssh-host-keys"
              name="endpoint[host_keys]"
              value={@endpoint_form["host_keys"]}
              label="Approved public host keys (one per line)"
            />
            <.dm_select
              id="ssh-approved"
              name="endpoint[approved]"
              label="Trust"
              options={[
                {"false", "Pending / not trusted"},
                {"true", "Approve endpoint and listed keys"}
              ]}
              value={@endpoint_form["approved"] || "false"}
            />
            <.dm_btn type="submit" variant="secondary">Preview endpoint</.dm_btn>
          </.form>
          <div
            :for={endpoint <- @inventory.endpoints}
            class="mt-4 border-t border-outline-variant pt-4"
          >
            <strong>{endpoint.agent_id}</strong><.dm_badge variant={
              if endpoint.approved, do: "success", else: "warning"
            }>
              {if endpoint.approved, do: "Approved", else: "Unapproved host keys"}
            </.dm_badge>
            <p class="text-sm">{Enum.join(endpoint.aliases, ", ")}:{endpoint.port}</p>
            <p :for={key <- endpoint.host_keys} class="font-mono text-xs break-all">
              Approved: {fingerprint(key)}
            </p>
            <details :if={Map.get(endpoint, :candidate_host_keys, []) != []}>
              <summary class="text-sm cursor-pointer">Reported candidates (require approval)</summary><div :for={
                key <- endpoint.candidate_host_keys
              }>
                <p class="font-mono text-xs break-all">{fingerprint(key)}</p><pre class="text-xs overflow-auto">{key}</pre>
              </div>
            </details>
            <.dm_btn
              size="sm"
              variant="ghost"
              phx-click="edit_endpoint"
              phx-value-id={endpoint.agent_id}
            >
              Edit / rotate host keys
            </.dm_btn><.dm_btn
              size="sm"
              variant="ghost"
              phx-click="preview_delete"
              phx-value-kind="endpoint"
              phx-value-id={endpoint.agent_id}
            >
              Remove endpoint
            </.dm_btn>
          </div>
        </.dm_card>

        <.dm_card>
          <:title>Source signing identities</:title>
          <.form
            for={%{}}
            id="ssh-identity-form"
            phx-submit="preview_identity"
            autocomplete="off"
            class="space-y-4"
          >
            <.dm_select
              id="ssh-identity-agent"
              name="identity[agent_id]"
              label="Source machine"
              options={@agent_options}
              prompt="Select machine"
            />
            <.dm_input
              id="ssh-identity-user"
              name="identity[username]"
              label="Existing Unix username"
              required
            />
            <.dm_input
              id="ssh-identity-uid"
              name="identity[uid]"
              label="Approved numeric UID"
              type="number"
              min="0"
              required
            />
            <.dm_select
              id="ssh-algorithm"
              name="identity[algorithm]"
              label="Generate key"
              options={[{"ed25519", "Ed25519"}, {"rsa", "RSA 3072"}]}
            />
            <.dm_textarea
              id={"ssh-private-key-#{@import_generation}"}
              name="identity[private_key]"
              value=""
              label="Or import one unencrypted private key"
              helper="Kept encrypted by Core. Replacing an identity revokes the old key immediately."
              maxlength={65536}
            />
            <.dm_btn type="submit" variant="secondary">Preview identity / replacement</.dm_btn>
          </.form>
          <div
            :for={identity <- @inventory.identities}
            class="mt-4 border-t border-outline-variant pt-4"
          >
            <strong>{identity.agent_id}:{identity.username}</strong><p class="text-sm">
              UID {identity.uid} · key revision {identity.key_revision} · {if identity.active,
                do: "Active",
                else: "Revoked"}
            </p><p class="text-xs font-mono break-all">{identity.fingerprint}</p><p class="text-sm">
              {prerequisites(@inventory, identity.agent_id, identity.username)}
            </p>
            <.dm_btn
              :if={identity.active}
              size="sm"
              variant="error"
              phx-click="preview_delete"
              phx-value-kind="identity"
              phx-value-id={identity.id}
            >
              Preview revocation
            </.dm_btn>
          </div>
        </.dm_card>

        <.dm_card>
          <:title>Directed rules and bulk actions</:title>
          <.form for={%{}} id="ssh-rule-form" phx-submit="preview_rules" class="space-y-4">
            <input type="hidden" name="rule[id]" value={@rule_form["id"] || ""} />
            <.dm_select
              id="ssh-rule-sources"
              name="rule[sources][]"
              label="Source machines / groups"
              options={@selector_options}
              value={@rule_form["sources"] || []}
              multiple
            />
            <.dm_input
              id="ssh-rule-user"
              name="rule[source_user]"
              label="Source Unix user"
              value={@rule_form["source_user"]}
              required
            />
            <.dm_select
              id="ssh-rule-destinations"
              name="rule[destinations][]"
              label="Destination machines / groups"
              options={@selector_options}
              value={@rule_form["destinations"] || []}
              multiple
            />
            <.dm_input
              id="ssh-rule-target-user"
              name="rule[destination_user]"
              label="Destination Unix user"
              value={@rule_form["destination_user"]}
              required
            />
            <.dm_select
              id="ssh-rule-effect"
              name="rule[effect]"
              label="Effect"
              options={[{"allow", "Allow"}, {"deny", "Deny (overrides allows)"}]}
              value={@rule_form["effect"] || "allow"}
            />
            <.dm_select
              id="ssh-rule-enabled"
              name="rule[enabled]"
              label="State"
              options={[{"true", "Enabled"}, {"false", "Disabled"}]}
              value={@rule_form["enabled"] || "true"}
            />
            <.dm_btn type="submit" variant="secondary">Preview rules for every selected pair</.dm_btn>
            <.dm_btn
              :if={@rule_form["id"]}
              id="ssh-cancel-rule-edit"
              type="button"
              variant="ghost"
              phx-click="cancel_rule_edit"
            >
              Cancel editing
            </.dm_btn>
          </.form>
          <.form for={%{}} id="ssh-revoke-form" phx-submit="preview_revoke" class="mt-6 space-y-4">
            <div :for={rule <- @inventory.rules} class="border-t border-outline-variant pt-3">
              <.selection_checkbox
                id={"rule-" <> rule.id}
                name="revoke[ids][]"
                value={rule.id}
                label={rule.effect <> ": " <> rule.source_id <> ":" <> rule.source_user <> " → " <> rule.destination_id <> ":" <> rule.destination_user}
              />
              <p class="text-xs break-all">
                {rule.id} · {if rule.enabled, do: "Enabled", else: "Disabled"}
              </p><.dm_btn variant="ghost" size="sm" phx-click="edit_rule" phx-value-id={rule.id}>
                Edit
              </.dm_btn>
            </div>
            <.dm_btn type="submit" variant="error">Preview removal of selected rules</.dm_btn>
          </.form>
        </.dm_card>
      </div>

      <.dm_card>
        <:title>Machine prerequisites</:title>
        <.dm_table data={@inventory.agents} zebra>
          <:col :let={agent} label="Machine">
            {agent.name || agent.agent_id}
            <p class="text-xs">{agent.agent_id}</p>
          </:col>
          <:col :let={agent} label="Runtime">
            {agent.status}
            <p class="text-xs">{Enum.join(agent.runtime_capabilities, ", ")}</p>
          </:col>
          <:col :let={agent} label="Local user inventory">
            {Map.get(agent, :ssh_inventory_seen_at) || "Prerequisites unverified"}
            <p class="text-xs">
              {length(Map.get(agent, :ssh_users, []))} reported users. Core rules do not create Unix users or grant socket access.
            </p>
          </:col>
        </.dm_table>
      </.dm_card>

      <.dm_card>
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
          /><.dm_textarea
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
end
