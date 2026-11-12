defmodule SecretHub.Core.SSH.IdentitiesTest do
  use ExUnit.Case, async: true
  alias SecretHub.Core.SSH.Identities
  alias SecretHub.Shared.SSH.Key

  @now ~U[2026-11-12 00:00:00Z]

  defp public do
    {:ok, key} = Key.generate("ed25519")
    key.public.public_line
  end

  defp report(overrides \\ %{}) do
    Map.merge(
      %{
        agent_id: "laptop",
        agent_name: "laptop",
        uid: 1000,
        username: "gao",
        generation: 1,
        public_key: public()
      },
      overrides
    )
  end

  test "first report creates a pending identity that approval activates" do
    assert {:ok, [identity], {:reported, _}} = Identities.report([], report(), @now)

    assert %{name: "gao@laptop", status: "pending", origin: "agent", requested_generation: 1} =
             identity

    refute Identities.usable?(identity, @now)
    assert {:ok, [active]} = Identities.approve([identity], identity.id, @now)
    assert active.status == "active"
    assert active.next_rotation_at == DateTime.add(@now, 90 * 86_400)
    assert Identities.usable?(active, @now)
  end

  test "re-reporting the same key is idempotent and other generations are rejected" do
    first = report()
    {:ok, ids, _} = Identities.report([], first, @now)
    assert {:ok, ^ids, :unchanged} = Identities.report(ids, first, @now)

    assert {:error, :unexpected_generation} =
             Identities.report(ids, report(%{generation: 2}), @now)

    assert {:error, :unexpected_generation} =
             Identities.report([], report(%{generation: 2}), @now)

    assert {:error, :account_changed} = Identities.report(ids, %{first | username: "eve"}, @now)
  end

  test "requested rotation accepts exactly the next generation with a grace period" do
    {:ok, [identity], _} = Identities.report([], report(), @now)
    {:ok, ids} = Identities.approve([identity], identity.id, @now)
    {:ok, [requested]} = Identities.request_rotation(ids, identity.id, @now)
    assert requested.requested_generation == 2

    later = DateTime.add(@now, 60)

    assert {:ok, [rotated], {:rotated, _}} =
             Identities.report([requested], report(%{generation: 2}), later)

    assert [%{generation: 1, not_after: grace}, %{generation: 2, not_after: nil}] = rotated.keys
    assert grace == DateTime.add(later, 3 * 86_400)
    assert length(Identities.valid_keys(rotated, later)) == 2
    assert [%{generation: 2}] = Identities.valid_keys(rotated, DateTime.add(grace, 1))
  end

  test "duplicate fingerprints are rejected across identities" do
    key = public()
    {:ok, ids, _} = Identities.report([], report(%{public_key: key}), @now)

    assert {:error, :duplicate_key} =
             Identities.report(ids, report(%{uid: 1001, username: "ops", public_key: key}), @now)

    assert {:error, :duplicate_key} = Identities.add_external(ids, "ci", key, 90, @now)
  end

  test "external identities are active, replaceable and only flagged when due" do
    assert {:ok, [ext]} = Identities.add_external([], "gh-deploy", public(), 30, @now)
    assert %{origin: "external", status: "active", rotation_overdue: false} = ext

    assert {:error, :invalid_name} =
             Identities.add_external([ext], "gh-deploy", public(), 30, @now)

    due = DateTime.add(@now, 31 * 86_400)
    assert {[flagged], [{:rotation_overdue, id}]} = Identities.schedule([ext], due)
    assert id == ext.id and flagged.rotation_overdue and flagged.status == "active"
    assert {[^flagged], []} = Identities.schedule([flagged], due)

    assert {:ok, [replaced]} = Identities.replace_external([flagged], ext.id, public(), due)
    refute replaced.rotation_overdue
    assert [%{generation: 1, not_after: %DateTime{}}, %{generation: 2}] = replaced.keys
  end

  test "schedule requests Agent rotation and prunes long-expired keys" do
    {:ok, [identity], _} = Identities.report([], report(), @now)
    {:ok, [active]} = Identities.approve([identity], identity.id, @now)
    due = DateTime.add(@now, 91 * 86_400)
    assert {[requested], [{:rotation_requested, _, 2}]} = Identities.schedule([active], due)

    {:ok, [rotated], _} = Identities.report([requested], report(%{generation: 2}), due)
    much_later = DateTime.add(due, 40 * 86_400)
    {[pruned], events} = Identities.schedule([rotated], much_later)
    assert [%{generation: 2}] = pruned.keys
    assert {:keys_pruned, rotated.id, 1} in events
  end

  test "revocation invalidates every key immediately and blocks reports" do
    {:ok, [identity], _} = Identities.report([], report(), @now)
    {:ok, ids} = Identities.approve([identity], identity.id, @now)
    {:ok, [revoked]} = Identities.revoke(ids, identity.id, @now)
    assert revoked.status == "retired"
    assert Identities.valid_keys(revoked, @now) == []
    assert {:error, :retired} = Identities.report([revoked], report(%{generation: 2}), @now)
  end

  test "rotation days accept nil or 1..3650" do
    {:ok, [ext]} = Identities.add_external([], "ci", public(), 90, @now)

    assert {:ok, [%{rotation_days: nil, next_rotation_at: nil}]} =
             Identities.set_rotation([ext], ext.id, nil, @now)

    assert {:error, :invalid_rotation} = Identities.set_rotation([ext], ext.id, 0, @now)
  end
end
