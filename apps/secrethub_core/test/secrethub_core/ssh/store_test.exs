defmodule SecretHub.Core.SSH.StoreTest do
  use ExUnit.Case, async: false
  alias SecretHub.Core.RuntimeDatabaseFixture

  setup_all do
    RuntimeDatabaseFixture.prepare_template()
  end

  setup tags do
    RuntimeDatabaseFixture.setup(tags)
  end

  alias SecretHub.Core.{Repo, SSH}
  alias SecretHub.Core.Vault.SealState
  alias SecretHub.Shared.Schemas.{Agent, Certificate}
  alias SecretHub.Shared.Schemas.SSH.{Identity, IdentityKey}
  alias SecretHub.Shared.SSH.Key

  setup do
    start_supervised!({SealState, repo: RuntimeDatabaseFixture.VaultRepo})
    await_state(:not_initialized)
    {:ok, shares} = SealState.initialize(3, 2)
    Enum.each(Enum.take(shares, 2), &SealState.unseal/1)
    source = agent("source", ["ssh_lookup_v1", "ssh_signing_v1"])
    target = agent("target", ["ssh_lookup_v1"])
    {:ok, host} = Key.generate("ed25519")
    {:ok, user} = Key.generate("ed25519")

    %{
      source: source,
      target: target,
      host: host.public.public_line,
      user_key: user.public.public_line
    }
  end

  test "atomic batches, stale revision, typed groups and no private fields", ctx do
    assert %{revision: 0, identities: [], groups: []} = SSH.snapshot()

    changes = [
      %{"op" => "group_upsert", "id" => "servers", "name" => "Servers", "kind" => "host"},
      %{"op" => "group_members", "group_id" => "servers", "member_ids" => ["target"]},
      %{
        "op" => "endpoint_upsert",
        "agent_id" => "target",
        "aliases" => ["target.example"],
        "port" => 22,
        "host_keys" => [ctx.host],
        "approved" => true
      },
      %{
        "op" => "identity_external_add",
        "name" => "gh-deploy",
        "public_key" => ctx.user_key,
        "rotation_days" => 30
      }
    ]

    assert {:ok, %{revision: 0, gained: [], lost: []}} = SSH.preview(changes, 0)
    assert SSH.snapshot().revision == 0
    assert {:ok, %{revision: 1, identities: [identity]}} = SSH.apply_changes(changes, 0)

    assert %{name: "gh-deploy", origin: "external", status: "active", keys: [%{generation: 1}]} =
             identity

    refute inspect(SSH.snapshot()) =~ "PRIVATE KEY"
    assert {:error, :stale_revision} = SSH.apply_changes([], 0)

    rule = %{
      "op" => "rule_upsert",
      "id" => "deploy",
      "effect" => "allow",
      "source_kind" => "identity",
      "source_id" => identity.id,
      "destination_kind" => "host_group",
      "destination_id" => "servers",
      "destination_user" => "deploy"
    }

    assert {:ok,
            %{
              gained: [
                %{identity_id: id, destination_agent_id: "target", destination_user: "deploy"}
              ]
            }} = SSH.preview([rule], 1)

    assert id == identity.id
    assert {:error, :invalid_change} = SSH.apply_changes([rule, %{"op" => "bogus"}], 1)

    assert {:error, :group_in_use} =
             SSH.apply_changes([rule, %{"op" => "group_delete", "id" => "servers"}], 1)

    assert %{revision: 1, rules: [], groups: [%{id: "servers", kind: "host"}]} = SSH.snapshot()
  end

  test "identity groups accept only known identities and rules require typed selectors", ctx do
    {:ok, %{identities: [ext]}} =
      SSH.apply_changes(
        [
          %{
            "op" => "identity_external_add",
            "name" => "ci",
            "public_key" => ctx.user_key,
            "rotation_days" => 90
          }
        ],
        0
      )

    group = %{"op" => "group_upsert", "id" => "ops", "name" => "Ops", "kind" => "identity"}

    assert {:error, :invalid_change} =
             SSH.apply_changes(
               [group, %{"op" => "group_members", "group_id" => "ops", "member_ids" => ["nope"]}],
               1
             )

    assert {:ok, %{groups: [%{kind: "identity", identity_ids: [id]}]}} =
             SSH.apply_changes(
               [group, %{"op" => "group_members", "group_id" => "ops", "member_ids" => [ext.id]}],
               1
             )

    assert id == ext.id

    # A host group cannot be a rule source, and an identity group cannot be a destination.
    assert {:error, :invalid_change} =
             SSH.apply_changes(
               [
                 %{
                   "op" => "rule_upsert",
                   "effect" => "allow",
                   "source_kind" => "host_group",
                   "source_id" => "ops",
                   "destination_kind" => "identity_group",
                   "destination_id" => "ops",
                   "destination_user" => "deploy"
                 }
               ],
               2
             )
  end

  test "identity operations: rotation settings, rotate, revoke and external replace", ctx do
    {:ok, %{identities: [ext]}} =
      SSH.apply_changes(
        [
          %{
            "op" => "identity_external_add",
            "name" => "ci",
            "public_key" => ctx.user_key,
            "rotation_days" => 90
          }
        ],
        0
      )

    {:ok, other} = Key.generate("ed25519")

    assert {:ok, %{identities: [%{keys: [_, %{generation: 2}], rotation_overdue: false}]}} =
             SSH.apply_changes(
               [
                 %{
                   "op" => "identity_external_replace",
                   "id" => ext.id,
                   "public_key" => other.public.public_line
                 }
               ],
               1
             )

    assert [_, _] = Repo.all(IdentityKey)

    assert {:ok, %{identities: [%{rotation_days: nil}]}} =
             SSH.apply_changes(
               [%{"op" => "identity_rotation", "id" => ext.id, "rotation_days" => nil}],
               2
             )

    assert {:error, :invalid_change} =
             SSH.apply_changes([%{"op" => "identity_rotate", "id" => ext.id}], 3)

    assert {:ok, %{identities: [%{status: "retired"}]}} =
             SSH.apply_changes([%{"op" => "identity_revoke", "id" => ext.id}], 3)

    assert {:error, :duplicate_key} =
             SSH.apply_changes(
               [
                 %{
                   "op" => "identity_external_add",
                   "name" => "dup",
                   "public_key" => ctx.user_key,
                   "rotation_days" => 90
                 }
               ],
               4
             )

    assert {:error, :invalid_name} =
             SSH.apply_changes(
               [
                 %{
                   "op" => "identity_external_add",
                   "name" => "bad name",
                   "public_key" => other.public.public_line
                 }
               ],
               4
             )
  end

  test "identity_delete rejects referenced identities and removes rows and keys", ctx do
    {:ok, %{identities: [ext]}} =
      SSH.apply_changes(
        [
          %{
            "op" => "identity_external_add",
            "name" => "ci",
            "public_key" => ctx.user_key,
            "rotation_days" => 90
          },
          %{
            "op" => "endpoint_upsert",
            "agent_id" => "target",
            "aliases" => ["target.example"],
            "port" => 22,
            "host_keys" => [ctx.host],
            "approved" => true
          }
        ],
        0
      )

    rule = %{
      "op" => "rule_upsert",
      "id" => "deploy",
      "effect" => "allow",
      "source_kind" => "identity",
      "source_id" => ext.id,
      "destination_kind" => "endpoint",
      "destination_id" => "target",
      "destination_user" => "deploy"
    }

    {:ok, _} = SSH.apply_changes([rule, %{"op" => "identity_revoke", "id" => ext.id}], 1)
    delete = %{"op" => "identity_delete", "id" => ext.id}
    assert {:error, :identity_in_use} = SSH.apply_changes([delete], 2)

    group = %{"op" => "group_upsert", "id" => "ops", "name" => "Ops", "kind" => "identity"}
    members = %{"op" => "group_members", "group_id" => "ops", "member_ids" => [ext.id]}
    unrule = %{"op" => "rule_delete", "id" => "deploy"}

    assert {:error, :identity_in_use} =
             SSH.apply_changes([unrule, group, members, delete], 2)

    assert [_] = Repo.all(Identity)

    assert {:ok, %{revision: 3, identities: []}} = SSH.apply_changes([unrule, delete], 2)
    assert [] = Repo.all(Identity)
    assert [] = Repo.all(IdentityKey)
    assert %{identities: []} = SSH.snapshot()
  end

  test "an active identity cannot be deleted", ctx do
    {:ok, %{identities: [ext]}} =
      SSH.apply_changes(
        [%{"op" => "identity_external_add", "name" => "ci", "public_key" => ctx.user_key}],
        0
      )

    assert {:error, :invalid_change} =
             SSH.apply_changes([%{"op" => "identity_delete", "id" => ext.id}], 1)
  end

  test "endpoint collisions, invalid aliases and pending host keys fail closed", ctx do
    base = %{
      "op" => "endpoint_upsert",
      "agent_id" => "target",
      "aliases" => ["shared.example"],
      "port" => 22,
      "host_keys" => [ctx.host],
      "approved" => true
    }

    {:ok, _} = SSH.apply_changes([base], 0)

    assert {:error, :endpoint_conflict} =
             SSH.apply_changes(
               [%{base | "agent_id" => "source", "aliases" => ["SHARED.EXAMPLE"]}],
               1
             )

    assert {:error, :invalid_change} =
             SSH.apply_changes([%{base | "aliases" => ["bad host"]}], 1)

    assert {:error, :invalid_change} =
             SSH.apply_changes([%{base | "aliases" => ["bad\nname"]}], 1)
  end

  test "audit failure rolls back management changes", ctx do
    old = Application.get_env(:secrethub_core, :audit_hmac_secret)
    Application.put_env(:secrethub_core, :audit_hmac_secret, "")

    try do
      assert {:error, :audit_unavailable} =
               SSH.apply_changes(
                 [
                   %{
                     "op" => "identity_external_add",
                     "name" => "ci",
                     "public_key" => ctx.user_key
                   }
                 ],
                 0
               )
    after
      if old,
        do: Application.put_env(:secrethub_core, :audit_hmac_secret, old),
        else: Application.delete_env(:secrethub_core, :audit_hmac_secret)
    end

    assert %{revision: 0, identities: []} = SSH.snapshot()
    assert [] = Repo.all(Identity)
  end

  test "sealed Core fails closed for management changes", ctx do
    GenServer.stop(Process.whereis(SealState))

    assert {:error, :sealed} =
             SSH.apply_changes(
               [%{"op" => "identity_external_add", "name" => "ci", "public_key" => ctx.user_key}],
               0
             )

    assert {:error, :sealed} = SSH.preview([], 0)
  end

  defp agent(id, capabilities) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    cert =
      Repo.insert!(%Certificate{
        serial_number: Ecto.UUID.generate(),
        fingerprint: Ecto.UUID.generate(),
        certificate_pem: "fixture",
        subject: id,
        issuer: "fixture",
        common_name: id,
        cert_type: :agent_client,
        entity_type: "agent",
        entity_id: id,
        valid_from: DateTime.add(now, -60),
        valid_until: DateTime.add(now, 3600)
      })

    Repo.insert!(%Agent{
      agent_id: id,
      name: id,
      status: :trusted_connected,
      certificate_id: cert.id,
      runtime_capabilities: capabilities
    })
  end

  defp await_state(expected, attempts \\ 100)
  defp await_state(_, 0), do: flunk("Vault not ready")

  defp await_state(expected, attempts) do
    if SealState.status().state != expected do
      Process.sleep(10)
      await_state(expected, attempts - 1)
    end
  end
end
