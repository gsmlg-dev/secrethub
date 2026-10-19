defmodule SecretHub.Core.SSH.EvaluatorTest do
  use ExUnit.Case, async: true
  alias SecretHub.Core.SSH.Evaluator

  defp inventory do
    %{
      groups: [%{id: "build", name: "Build", agent_ids: ["source"]}],
      rules: [],
      identities: [%{id: "key", agent_id: "source", username: "deploy", uid: 1000, active: true}],
      endpoints: [
        %{
          agent_id: "target",
          aliases: ["target.example"],
          port: 22,
          approved: true,
          host_keys: ["host"]
        }
      ]
    }
  end

  defp rule(overrides \\ %{}) do
    Map.merge(
      %{
        id: "allow",
        effect: "allow",
        enabled: true,
        source_kind: "group",
        source_id: "build",
        source_user: "deploy",
        destination_kind: "agent",
        destination_id: "target",
        destination_user: "app"
      },
      overrides
    )
  end

  test "default denial, directed exact users and persistent membership" do
    inventory = inventory()

    assert %{allowed: false, allow_rules: [], deny_rules: []} =
             Evaluator.decision(inventory, "source", "deploy", "target", "app")

    inventory = %{inventory | rules: [rule()]}

    assert %{allowed: true, allow_rules: ["allow"]} =
             Evaluator.decision(inventory, "source", "deploy", "target", "app")

    refute Evaluator.decision(inventory, "target", "app", "source", "deploy").allowed
    refute Evaluator.decision(inventory, "source", "root", "target", "app").allowed
    refute Evaluator.decision(inventory, "source", "deploy", "target", "root").allowed
    inventory = %{inventory | groups: [%{id: "build", agent_ids: []}]}
    refute Evaluator.decision(inventory, "source", "deploy", "target", "app").allowed
  end

  test "deny wins regardless of specificity or ordering, and edges deduplicate" do
    allow = rule()
    duplicate = rule(%{id: "second", source_kind: "agent", source_id: "source"})
    inventory = %{inventory() | rules: [allow, duplicate]}

    assert [
             %{
               source_agent_id: "source",
               source_user: "deploy",
               destination_agent_id: "target",
               destination_user: "app"
             }
           ] = Evaluator.edges(inventory)

    deny = rule(%{id: "deny", effect: "deny", source_kind: "agent", source_id: "source"})

    assert %{allowed: false, deny_rules: ["deny"]} =
             Evaluator.decision(
               %{inventory | rules: [deny, allow]},
               "source",
               "deploy",
               "target",
               "app"
             )

    assert [] = Evaluator.edges(%{inventory | rules: [allow, deny]})
  end

  test "edge diff shows concrete gained and lost grants" do
    before = inventory()
    after_inventory = %{before | rules: [rule()]}
    assert %{gained: [edge], lost: []} = Evaluator.diff(before, after_inventory)
    assert %{gained: [], lost: [^edge]} = Evaluator.diff(after_inventory, before)
    assert [] = Evaluator.edges(%{after_inventory | identities: []})

    assert [] =
             Evaluator.edges(%{
               after_inventory
               | endpoints: [%{hd(after_inventory.endpoints) | approved: false}]
             })
  end
end
