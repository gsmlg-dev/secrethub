defmodule SecretHub.Core.SSH.Evaluator do
  @moduledoc "Pure directed SSH policy evaluation. Every matching deny overrides every allow."

  def decision(inventory, source, source_user, destination, destination_user) do
    matches =
      Enum.filter(inventory.rules, fn rule ->
        rule.enabled and rule.source_user == source_user and
          rule.destination_user == destination_user and
          selected?(inventory, rule.source_kind, rule.source_id, source) and
          selected?(inventory, rule.destination_kind, rule.destination_id, destination)
      end)

    allow = for rule <- matches, rule.effect == "allow", do: rule.id
    deny = for rule <- matches, rule.effect == "deny", do: rule.id

    %{
      allowed: allow != [] and deny == [],
      allow_rules: Enum.sort(allow),
      deny_rules: Enum.sort(deny)
    }
  end

  def edges(inventory) do
    users = inventory.rules |> Enum.map(& &1.destination_user) |> Enum.uniq()

    for identity <- inventory.identities,
        identity.active,
        endpoint <- inventory.endpoints,
        endpoint.approved and endpoint.host_keys != [],
        user <- users,
        decision(inventory, identity.agent_id, identity.username, endpoint.agent_id, user).allowed do
      %{
        source_agent_id: identity.agent_id,
        source_user: identity.username,
        destination_agent_id: endpoint.agent_id,
        destination_user: user
      }
    end
    |> Enum.uniq()
    |> Enum.sort()
  end

  def diff(before, after_inventory) do
    before_edges = MapSet.new(edges(before))
    after_edges = MapSet.new(edges(after_inventory))

    %{
      gained: MapSet.difference(after_edges, before_edges) |> Enum.sort(),
      lost: MapSet.difference(before_edges, after_edges) |> Enum.sort()
    }
  end

  defp selected?(_, "agent", id, agent), do: id == agent

  defp selected?(inventory, "group", id, agent),
    do: Enum.any?(inventory.groups, &(&1.id == id and agent in &1.agent_ids))

  defp selected?(_, _, _, _), do: false
end
