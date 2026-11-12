defmodule SecretHub.Web.SSHAccess.Access do
  @moduledoc "Access tab: identity × destination matrix and typed group drawer."
  use Phoenix.Component
  use PhoenixDuskmoon.Component

  attr :inventory, :map, required: true
  attr :editing_group, :map, default: nil

  def tab(assigns) do
    assigns = assign(assigns, rows: rows(assigns.inventory), columns: columns(assigns.inventory))

    ~H"""
    <div id="access-tab" class="space-y-6">
      <.dm_card id="ssh-matrix">
        <:title>
          <span class="flex justify-between w-full">
            <span>Access</span>
            <span class="flex gap-2">
              <.dm_btn
                id="new-identity-group"
                size="sm"
                variant="ghost"
                phx-click="group_new"
                phx-value-kind="identity"
              >
                + Identity group
              </.dm_btn>
              <.dm_btn
                id="new-host-group"
                size="sm"
                variant="ghost"
                phx-click="group_new"
                phx-value-kind="host"
              >
                + Host group
              </.dm_btn>
            </span>
          </span>
        </:title>
        <p :if={@rows == [] or @columns == []} class="text-sm text-on-surface-variant">
          Access needs at least one identity and one trusted endpoint or host group.
        </p>
        <%!-- Native table: dm_table columns cannot hold a form per cell. --%>
        <div :if={@rows != [] and @columns != []} class="overflow-auto">
          <table class="text-sm">
            <thead>
              <tr>
                <th class="text-left">Identity \ Destination</th>
                <th :for={{_kind, _id, label} <- @columns} class="px-2">{label}</th>
              </tr>
            </thead>
            <tbody>
              <tr
                :for={{row_kind, row_id, row_label} <- @rows}
                class="border-t border-outline-variant"
              >
                <th class="text-left py-2 pr-3">{row_label}</th>
                <td :for={{col_kind, col_id, _} <- @columns} class="px-2 py-1 align-top">
                  <.cell
                    source={{row_kind, row_id}}
                    destination={{col_kind, col_id}}
                    rules={cell_rules(@inventory, row_kind, row_id, col_kind, col_id)}
                    users={destination_users(@inventory, col_kind, col_id)}
                  />
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </.dm_card>

      <.dm_card id="ssh-groups">
        <:title>Groups</:title>
        <p :if={@inventory.groups == []} class="text-sm text-on-surface-variant">
          No groups yet.
        </p>
        <ul class="text-sm space-y-1">
          <li
            :for={group <- @inventory.groups}
            id={"group-" <> group.id}
            class="flex justify-between"
          >
            <span>
              {group.name}
              <span class="text-on-surface-variant">
                ({group.kind}, {length(members(group))} members)
              </span>
            </span>
            <span class="flex gap-1">
              <.dm_btn size="sm" variant="ghost" phx-click="group_edit" phx-value-id={group.id}>
                Edit
              </.dm_btn>
              <.dm_btn size="sm" variant="error" phx-click="group_delete" phx-value-id={group.id}>
                Delete
              </.dm_btn>
            </span>
          </li>
        </ul>
      </.dm_card>

      <.dm_card :if={@editing_group} id="group-drawer" class="border border-primary">
        <:title>
          {if @editing_group.id, do: "Edit group", else: "New #{@editing_group.kind} group"}
        </:title>
        <.form for={%{}} id="group-form" phx-submit="group_save" class="space-y-3">
          <input type="hidden" name="group[id]" value={@editing_group.id} />
          <input type="hidden" name="group[kind]" value={@editing_group.kind} />
          <.dm_input id="group-name" name="group[name]" label="Name" value={@editing_group.name} />
          <%!--
            TODO(upstream): duskmoon-dev/phoenix-duskmoon-ui#205
            WORKAROUND(upstream): duskmoon-dev/phoenix-duskmoon-ui#205
            dm_checkbox currently emits boolean values only. Compose native controls
            for record selection until the package supports explicit array values.
          --%>
          <fieldset class="space-y-1">
            <legend class="text-sm">Members</legend>
            <label
              :for={{id, label} <- member_options(@inventory, @editing_group.kind)}
              class="flex gap-2 items-center text-sm"
            >
              <input
                type="checkbox"
                name="group[member_ids][]"
                value={id}
                checked={id in members(@editing_group)}
              />
              {label}
            </label>
          </fieldset>
          <span class="flex gap-2">
            <.dm_btn type="submit" variant="primary">Preview</.dm_btn>
            <.dm_btn type="button" variant="ghost" phx-click="group_close">Close</.dm_btn>
          </span>
        </.form>
      </.dm_card>
    </div>
    """
  end

  attr :source, :any, required: true
  attr :destination, :any, required: true
  attr :rules, :list, required: true
  attr :users, :list, required: true

  defp cell(assigns) do
    {source_kind, source_id} = assigns.source
    {destination_kind, destination_id} = assigns.destination

    assigns =
      assign(assigns,
        id: "cell-#{source_kind}-#{source_id}-#{destination_kind}-#{destination_id}",
        source_value: "#{source_kind}/#{source_id}",
        destination_value: "#{destination_kind}/#{destination_id}",
        list_id: "users-#{destination_kind}-#{destination_id}"
      )

    ~H"""
    <.form for={%{}} id={@id} phx-submit="cell" class="space-y-1">
      <input type="hidden" name="cell[source]" value={@source_value} />
      <input type="hidden" name="cell[destination]" value={@destination_value} />
      <p class={["text-xs", summary_class(@rules)]}>{summary(@rules)}</p>
      <input
        name="cell[user]"
        list={@list_id}
        placeholder="user"
        class="w-24 rounded border border-outline bg-surface px-1 text-xs"
        aria-label="Destination user"
      />
      <datalist id={@list_id}>
        <option :for={user <- @users} value={user} />
      </datalist>
      <span class="flex gap-1">
        <.dm_btn native_submit size="xs" variant="ghost" name="cell[effect]" value="allow">
          allow
        </.dm_btn>
        <.dm_btn native_submit size="xs" variant="ghost" name="cell[effect]" value="deny">
          deny
        </.dm_btn>
        <.dm_btn
          :if={@rules != []}
          native_submit
          size="xs"
          variant="ghost"
          name="cell[effect]"
          value="clear"
        >
          clear
        </.dm_btn>
      </span>
    </.form>
    """
  end

  @doc "Translates one matrix cell edit into a rule batch."
  def cell_changes(
        inventory,
        %{"source" => source, "destination" => destination, "effect" => effect} = attrs
      ) do
    with [source_kind, source_id] <- String.split(source, "/", parts: 2),
         [destination_kind, destination_id] <- String.split(destination, "/", parts: 2),
         true <- effect in ["allow", "deny", "clear"] do
      deletes =
        for rule <-
              cell_rules(inventory, source_kind, source_id, destination_kind, destination_id),
            do: %{"op" => "rule_delete", "id" => rule.id}

      user = String.trim(attrs["user"] || "")

      upsert =
        if effect == "clear",
          do: [],
          else: [
            %{
              "op" => "rule_upsert",
              "effect" => effect,
              "enabled" => true,
              "source_kind" => source_kind,
              "source_id" => source_id,
              "destination_kind" => destination_kind,
              "destination_id" => destination_id,
              "destination_user" => user
            }
          ]

      deletes ++ upsert
    else
      _ -> []
    end
  end

  def cell_changes(_, _), do: []

  defp rows(inventory) do
    Enum.map(
      Enum.filter(inventory.groups, &(&1.kind == "identity")),
      &{"identity_group", &1.id, "Group: " <> &1.name}
    ) ++
      for(
        identity <- inventory.identities,
        identity.status != "retired",
        do: {"identity", identity.id, identity.name}
      )
  end

  defp columns(inventory) do
    Enum.map(
      Enum.filter(inventory.groups, &(&1.kind == "host")),
      &{"host_group", &1.id, "Group: " <> &1.name}
    ) ++
      for(
        endpoint <- inventory.endpoints,
        endpoint.approved,
        do: {"endpoint", endpoint.agent_id, agent_name(inventory, endpoint.agent_id)}
      )
  end

  defp cell_rules(inventory, source_kind, source_id, destination_kind, destination_id),
    do:
      Enum.filter(inventory.rules, fn rule ->
        rule.source_kind == source_kind and rule.source_id == source_id and
          rule.destination_kind == destination_kind and rule.destination_id == destination_id
      end)

  defp summary([]), do: "—"

  defp summary(rules) do
    {deny, allow} = Enum.split_with(rules, &(&1.effect == "deny"))

    [
      if(allow != [], do: "allow as " <> Enum.map_join(allow, ", ", & &1.destination_user)),
      if(deny != [], do: "deny " <> Enum.map_join(deny, ", ", & &1.destination_user))
    ]
    |> Enum.reject(&is_nil/1)
    |> Enum.join(" · ")
  end

  defp summary_class(rules) do
    cond do
      Enum.any?(rules, &(&1.effect == "deny")) -> "text-error"
      rules != [] -> "text-success"
      true -> "text-on-surface-variant"
    end
  end

  defp destination_users(inventory, "endpoint", agent_id), do: users_of(inventory, [agent_id])

  defp destination_users(inventory, "host_group", id) do
    group = Enum.find(inventory.groups, &(&1.id == id))
    users_of(inventory, (group && group.agent_ids) || [])
  end

  defp users_of(inventory, agent_ids) do
    inventory.agents
    |> Enum.filter(&(&1.agent_id in agent_ids))
    |> Enum.flat_map(&Map.get(&1, :ssh_users, []))
    |> Enum.filter(& &1.unambiguous)
    |> Enum.map(& &1.username)
    |> Enum.uniq()
    |> Enum.sort()
  end

  defp member_options(inventory, "host"),
    do: Enum.map(inventory.agents, &{&1.agent_id, &1.name || &1.agent_id})

  defp member_options(inventory, "identity"),
    do: for(i <- inventory.identities, i.status != "retired", do: {i.id, i.name})

  defp members(%{kind: "host"} = group), do: Map.get(group, :agent_ids, [])
  defp members(%{kind: "identity"} = group), do: Map.get(group, :identity_ids, [])

  defp agent_name(inventory, id),
    do: Enum.find_value(inventory.agents, id, &(&1.agent_id == id && (&1.name || id)))
end
