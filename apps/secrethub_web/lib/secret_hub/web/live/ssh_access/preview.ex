defmodule SecretHub.Web.SSHAccess.Preview do
  @moduledoc "Human-readable SSH change previews: configuration steps and gained/lost access."

  def edges(preview, inventory) do
    names = Map.merge(identity_names(inventory), Map.get(preview, :identity_names, %{}))

    for {kind, edges} <- [gained: preview.gained, lost: preview.lost],
        {{identity, user}, group} <-
          edges |> Enum.group_by(&{&1.identity_id, &1.destination_user}) |> Enum.sort() do
      hosts =
        group
        |> Enum.map(&agent_name(inventory, &1.destination_agent_id))
        |> Enum.sort()
        |> Enum.join(", ")

      verb = if kind == :gained, do: "can log in", else: "can no longer log in"
      {kind, "#{Map.get(names, identity, identity)} #{verb} as #{user} on #{hosts}"}
    end
  end

  def changes(changes, inventory) do
    {deletes, others} = Enum.split_with(changes, &(&1["op"] == "rule_delete"))
    {upserts, others} = Enum.split_with(others, &(&1["op"] == "rule_upsert"))

    Enum.map(others, &describe(&1, inventory)) ++
      count(upserts, "Set", "access rule") ++ count(deletes, "Remove", "access rule")
  end

  defp describe(%{"op" => "identity_approve", "id" => id}, inv),
    do: "Approve identity #{identity(inv, id)}"

  defp describe(%{"op" => "identity_revoke", "id" => id}, inv),
    do: "Revoke identity #{identity(inv, id)}"

  defp describe(%{"op" => "identity_delete", "id" => id}, inv) do
    rules =
      Enum.filter(
        Map.get(inv, :rules, []),
        &(&1.source_kind == "identity" and &1.source_id == id)
      )

    case rules do
      [] ->
        "Delete identity #{identity(inv, id)}"

      _ ->
        "Delete identity #{identity(inv, id)} and its #{length(rules)} access rule#{plural(rules)}"
    end
  end

  defp describe(%{"op" => "identity_rotate", "id" => id}, inv),
    do: "Rotate identity #{identity(inv, id)} now"

  defp describe(%{"op" => "identity_rotation", "id" => id, "rotation_days" => nil}, inv),
    do: "Disable scheduled rotation for #{identity(inv, id)}"

  defp describe(%{"op" => "identity_rotation", "id" => id, "rotation_days" => days}, inv),
    do: "Rotate #{identity(inv, id)} every #{days} days"

  defp describe(%{"op" => "identity_external_add", "name" => name}, _),
    do: "Add external identity #{name}"

  defp describe(%{"op" => "identity_external_replace", "id" => id}, inv),
    do: "Replace the public key of #{identity(inv, id)}"

  defp describe(%{"op" => "endpoint_upsert", "agent_id" => id, "host_keys" => keys} = op, inv) do
    current = Enum.find(Map.get(inv, :endpoints, []), &(&1.agent_id == id))
    name = agent_name(inv, id)

    cond do
      keys == [] or op["approved"] == false ->
        "Save endpoint #{name} without trusted host keys"

      current && current.approved && Enum.sort(current.host_keys) == Enum.sort(keys) ->
        aliases = Enum.join(op["aliases"] || [], ", ")

        "Save endpoint #{name} (aliases #{if aliases == "", do: "none", else: aliases}, " <>
          "port #{op["port"]}); host keys unchanged"

      true ->
        "Trust #{length(keys)} host key#{plural(keys)} for #{name}"
    end
  end

  defp describe(%{"op" => "endpoint_delete", "agent_id" => id}, inv),
    do: "Remove SSH endpoint #{agent_name(inv, id)}"

  defp describe(%{"op" => "group_upsert", "name" => name}, _), do: "Save group #{name}"

  defp describe(%{"op" => "group_members", "member_ids" => ids}, _),
    do: "Set #{length(ids)} group members"

  defp describe(%{"op" => "group_delete", "id" => id}, inv), do: "Delete group #{group(inv, id)}"
  defp describe(%{"op" => op}, _), do: op

  defp count([], _, _), do: []
  defp count(list, verb, noun), do: ["#{verb} #{length(list)} #{noun}#{plural(list)}"]

  defp plural([_]), do: ""
  defp plural(_), do: "s"

  defp identity_names(inventory), do: Map.new(inventory.identities, &{&1.id, &1.name})
  defp identity(inv, id), do: Map.get(identity_names(inv), id, id)

  defp agent_name(inv, id),
    do: Enum.find_value(inv.agents, id, &(&1.agent_id == id && (&1.name || id)))

  defp group(inv, id), do: Enum.find_value(inv.groups, id, &(&1.id == id && &1.name))
end
