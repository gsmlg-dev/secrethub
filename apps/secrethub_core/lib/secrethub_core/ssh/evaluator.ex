defmodule SecretHub.Core.SSH.Evaluator do
  @moduledoc "Pure directed SSH policy: identity sources to endpoint destinations. Deny overrides allow."
  alias SecretHub.Core.SSH.Identities

  def decision(inventory, identity_id, destination, destination_user) do
    matches =
      Enum.filter(inventory.rules, fn rule ->
        rule.enabled and rule.destination_user == destination_user and
          source?(inventory, rule, identity_id) and destination?(inventory, rule, destination)
      end)

    allow = for rule <- matches, rule.effect == "allow", do: rule.id
    deny = for rule <- matches, rule.effect == "deny", do: rule.id

    %{
      allowed: allow != [] and deny == [],
      allow_rules: Enum.sort(allow),
      deny_rules: Enum.sort(deny)
    }
  end

  def edges(inventory, now \\ DateTime.utc_now()) do
    users = inventory.rules |> Enum.map(& &1.destination_user) |> Enum.uniq()

    for identity <- inventory.identities,
        Identities.usable?(identity, now),
        endpoint <- inventory.endpoints,
        endpoint.approved and endpoint.host_keys != [],
        user <- users,
        decision(inventory, identity.id, endpoint.agent_id, user).allowed do
      %{identity_id: identity.id, destination_agent_id: endpoint.agent_id, destination_user: user}
    end
    |> Enum.uniq()
    |> Enum.sort()
  end

  def diff(before, after_inventory, now \\ DateTime.utc_now()) do
    before_edges = MapSet.new(edges(before, now))
    after_edges = MapSet.new(edges(after_inventory, now))

    %{
      gained: MapSet.difference(after_edges, before_edges) |> Enum.sort(),
      lost: MapSet.difference(before_edges, after_edges) |> Enum.sort()
    }
  end

  def group_members(inventory, kind, id) do
    case Enum.find(inventory.groups, &(&1.id == id and &1.kind == kind)) do
      %{kind: "host", agent_ids: ids} -> ids
      %{kind: "identity", identity_ids: ids} -> ids
      _ -> []
    end
  end

  defp source?(_, %{source_kind: "identity", source_id: id}, identity_id), do: id == identity_id

  defp source?(inventory, %{source_kind: "identity_group", source_id: id}, identity_id),
    do: identity_id in group_members(inventory, "identity", id)

  defp source?(_, _, _), do: false

  defp destination?(_, %{destination_kind: "endpoint", destination_id: id}, agent),
    do: id == agent

  defp destination?(inventory, %{destination_kind: "host_group", destination_id: id}, agent),
    do: agent in group_members(inventory, "host", id)

  defp destination?(_, _, _), do: false
end
