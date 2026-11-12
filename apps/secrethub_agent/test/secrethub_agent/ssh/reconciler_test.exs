defmodule SecretHub.Agent.SSH.ReconcilerTest do
  use ExUnit.Case, async: true
  alias SecretHub.Agent.SSH.{KeyStore, Reconciler}
  @moduletag :tmp_dir

  setup %{tmp_dir: root} do
    parent = self()

    request = fn operation, payload ->
      send(parent, {operation, payload})
      {:ok, %{"accepted" => true}}
    end

    account = fn uid -> {:ok, %{uid: uid, username: "u#{uid}"}} end
    %{root: root, request: request, account: account}
  end

  test "first use creates generation 1 and reports only its public key", ctx do
    :ok = Reconciler.ensure_enrolled(%{uid: 1000, username: "gao"}, ctx.request, ctx.root)

    assert_receive {"identity_report",
                    %{"uid" => 1000, "username" => "gao", "generation" => 1, "public_key" => line}}

    refute line =~ "PRIVATE"
    :ok = Reconciler.ensure_enrolled(%{uid: 1000, username: "gao"}, ctx.request, ctx.root)
    refute_receive {"identity_report", _}
  end

  test "requested generation creates and reports the next key; prune keeps valid ones", ctx do
    {:ok, _} = KeyStore.create(1000, 1, ctx.root)

    :ok =
      Reconciler.reconcile(
        [%{"uid" => 1000, "requested_generation" => 2, "generations" => [1]}],
        ctx.request,
        ctx.root,
        ctx.account
      )

    assert_receive {"identity_report", %{"generation" => 2}}
    assert KeyStore.generations(1000, ctx.root) == [1, 2]

    :ok =
      Reconciler.reconcile(
        [%{"uid" => 1000, "requested_generation" => 2, "generations" => [2]}],
        ctx.request,
        ctx.root,
        ctx.account
      )

    refute_receive {"identity_report", _}
    assert KeyStore.generations(1000, ctx.root) == [2]
  end

  test "unknown to Core re-reports generation 1; a lost report is retried", ctx do
    {:ok, _} = KeyStore.create(1000, 1, ctx.root)
    :ok = Reconciler.reconcile([], ctx.request, ctx.root, ctx.account)
    assert_receive {"identity_report", %{"generation" => 1}}

    {:ok, _} = KeyStore.create(1000, 2, ctx.root)

    :ok =
      Reconciler.reconcile(
        [%{"uid" => 1000, "requested_generation" => 2, "generations" => [1]}],
        ctx.request,
        ctx.root,
        ctx.account
      )

    assert_receive {"identity_report", %{"generation" => 2}}
  end

  test "an empty valid list (retired identity) keeps local keys", ctx do
    {:ok, _} = KeyStore.create(1000, 1, ctx.root)

    :ok =
      Reconciler.reconcile(
        [%{"uid" => 1000, "requested_generation" => 1, "generations" => []}],
        ctx.request,
        ctx.root,
        ctx.account
      )

    assert KeyStore.generations(1000, ctx.root) == [1]
  end
end
