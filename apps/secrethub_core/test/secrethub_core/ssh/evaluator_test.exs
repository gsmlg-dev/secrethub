defmodule SecretHub.Core.SSH.EvaluatorTest do
  use ExUnit.Case, async: true
  alias SecretHub.Core.SSH.Evaluator

  @now ~U[2026-11-12 00:00:00Z]

  defp key(generation, not_after \\ nil),
    do: %{
      id: "k#{generation}",
      generation: generation,
      public_key: "ssh-ed25519 K#{generation}",
      fingerprint: "F#{generation}",
      not_after: not_after
    }

  defp inventory(rules) do
    %{
      groups: [
        %{id: "laptops", name: "Laptops", kind: "identity", identity_ids: ["gao"]},
        %{id: "servers", name: "Servers", kind: "host", agent_ids: ["vultr-01", "vultr-02"]}
      ],
      rules: rules,
      identities: [
        %{id: "gao", status: "active", keys: [key(1)]},
        %{id: "ci", status: "active", keys: [key(1, DateTime.add(@now, -1))]},
        %{id: "phone", status: "pending", keys: [key(1)]}
      ],
      endpoints:
        for(
          agent <- ["vultr-01", "vultr-02"],
          do: %{agent_id: agent, aliases: [agent], port: 22, approved: true, host_keys: ["h"]}
        )
    }
  end

  defp rule(overrides),
    do:
      Map.merge(
        %{
          id: "allow",
          effect: "allow",
          enabled: true,
          source_kind: "identity_group",
          source_id: "laptops",
          destination_kind: "host_group",
          destination_id: "servers",
          destination_user: "gao"
        },
        overrides
      )

  test "default deny, groups expand, exact destination user" do
    assert %{allowed: false} = Evaluator.decision(inventory([]), "gao", "vultr-01", "gao")
    inv = inventory([rule(%{})])

    assert %{allowed: true, allow_rules: ["allow"]} =
             Evaluator.decision(inv, "gao", "vultr-02", "gao")

    refute Evaluator.decision(inv, "gao", "vultr-02", "root").allowed
    refute Evaluator.decision(inv, "ci", "vultr-02", "gao").allowed
  end

  test "deny wins and direct selectors work" do
    inv =
      inventory([
        rule(%{}),
        rule(%{
          id: "deny",
          effect: "deny",
          source_kind: "identity",
          source_id: "gao",
          destination_kind: "endpoint",
          destination_id: "vultr-02"
        })
      ])

    assert %{allowed: false, deny_rules: ["deny"]} =
             Evaluator.decision(inv, "gao", "vultr-02", "gao")

    assert Evaluator.decision(inv, "gao", "vultr-01", "gao").allowed
  end

  test "edges include only usable identities and approved endpoints" do
    inv =
      inventory([
        rule(%{}),
        rule(%{id: "ci", source_kind: "identity", source_id: "ci", destination_user: "deploy"}),
        rule(%{id: "phone", source_kind: "identity", source_id: "phone"})
      ])

    assert [
             %{identity_id: "gao", destination_agent_id: "vultr-01", destination_user: "gao"},
             %{identity_id: "gao", destination_agent_id: "vultr-02", destination_user: "gao"}
           ] = Evaluator.edges(inv, @now)
  end

  test "diff reports gained and lost edges" do
    before = inventory([])
    after_inv = inventory([rule(%{})])
    assert %{gained: [_, _], lost: []} = Evaluator.diff(before, after_inv, @now)
    assert %{gained: [], lost: [_, _]} = Evaluator.diff(after_inv, before, @now)
  end
end
