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
  alias SecretHub.Shared.Schemas.SSH.Identity
  alias SecretHub.Shared.SSH.Key

  setup do
    start_supervised!({SealState, repo: RuntimeDatabaseFixture.VaultRepo})
    await_state(:not_initialized)
    {:ok, shares} = SealState.initialize(3, 2)
    Enum.each(Enum.take(shares, 2), &SealState.unseal/1)
    source = agent("source", ["ssh_lookup_v1", "ssh_signing_v1"])
    target = agent("target", ["ssh_lookup_v1"])
    {:ok, host} = Key.generate("ed25519")
    %{source: source, target: target, host: host.public.public_line}
  end

  test "atomic batches, stale revision, dynamic group preview and no private management fields",
       ctx do
    assert %{revision: 0, identities: []} = SSH.snapshot()
    changes = changes(ctx)
    assert {:ok, %{revision: 0, gained: [_], lost: [], changes: safe}} = SSH.preview(changes, 0)
    refute inspect(safe) =~ "PRIVATE KEY"
    assert SSH.snapshot().revision == 0
    assert {:ok, %{revision: 1, identities: [identity]}} = SSH.apply_changes(changes, 0)
    refute Map.has_key?(identity, :private_key_encrypted)
    refute Map.has_key?(identity, :private_key)
    assert {:error, :stale_revision} = SSH.apply_changes([], 0)

    assert {:ok, %{lost: [_], gained: []}} =
             SSH.preview(
               [%{"op" => "group_members", "group_id" => "build", "agent_ids" => []}],
               1
             )

    assert {:error, :invalid_change} =
             SSH.apply_changes(
               [
                 %{"op" => "group_upsert", "id" => "other", "name" => "Other"},
                 %{"op" => "bogus"}
               ],
               1
             )

    assert %{revision: 1, groups: [%{id: "build"}]} = SSH.snapshot()
  end

  test "private identity is encrypted, rejects duplicate keys and UID aliases, replacement invalidates old key",
       ctx do
    {:ok, imported} = Key.generate("ed25519")

    change = %{
      "op" => "identity_upsert",
      "agent_id" => "source",
      "username" => "deploy",
      "uid" => 1000,
      "private_key" => imported.private_pem
    }

    assert {:ok, snapshot} = SSH.apply_changes([change], 0)
    [stored] = Repo.all(Identity)
    refute stored.private_key_encrypted == imported.private_pem
    refute inspect(stored) =~ imported.private_pem
    refute inspect(snapshot) =~ "PRIVATE KEY"

    assert {:error, :duplicate_identity} =
             SSH.apply_changes([%{change | "username" => "alias"}], 1)

    assert {:error, :duplicate_identity} =
             SSH.apply_changes([%{change | "agent_id" => "target"}], 1)

    assert {:ok, next} =
             SSH.apply_changes(
               [Map.drop(change, ["private_key"]) |> Map.put("algorithm", "ed25519")],
               1
             )

    assert [%{key_revision: 2, fingerprint: fingerprint}] = next.identities
    refute fingerprint == imported.public.fingerprint

    assert {:ok, revoked} =
             SSH.apply_changes([%{"op" => "identity_revoke", "id" => stored.id}], 2)

    assert [%{active: false}] = revoked.identities
    assert ctx.source.agent_id == "source"
  end

  test "endpoint collision, invalid aliases and pending keys fail closed", ctx do
    assert {:ok, _} = SSH.apply_changes(changes(ctx), 0)

    duplicate = %{
      "op" => "endpoint_upsert",
      "agent_id" => "source",
      "aliases" => ["TARGET.EXAMPLE"],
      "port" => 22,
      "host_keys" => [ctx.host],
      "approved" => true
    }

    assert {:error, :endpoint_conflict} = SSH.apply_changes([duplicate], 1)

    assert {:error, :invalid_change} =
             SSH.apply_changes([%{duplicate | "aliases" => ["bad\nname"]}], 1)

    assert {:ok, _} =
             SSH.apply_changes([%{duplicate | "agent_id" => "target", "approved" => false}], 1)

    assert {:ok, %{identities: []}} =
             SSH.runtime_operation(principal(ctx.source), "identities", %{
               "uid" => 1000,
               "username" => "deploy"
             })
  end

  test "runtime uses current principal and directed policy for exact public lookups and signing",
       ctx do
    {:ok, snapshot} = SSH.apply_changes(changes(ctx), 0)
    [identity] = snapshot.identities
    {:ok, public} = Key.decode_public(identity.public_key)

    assert {:ok, %{identities: [%{public_key: line}], revision: 1}} =
             SSH.runtime_operation(principal(ctx.source), "identities", %{
               "uid" => 1000,
               "username" => "deploy"
             })

    assert line == identity.public_key

    assert {:ok, %{private_key: pem, public_key: ^line}} =
             SSH.runtime_operation(principal(ctx.source), "authorize_sign", %{
               "uid" => 1000,
               "username" => "deploy",
               "public_key" => public.encoded
             })

    assert pem =~ "PRIVATE KEY"

    assert {:error, :denied} =
             SSH.runtime_operation(principal(ctx.source), "authorize_sign", %{
               "uid" => 999,
               "username" => "deploy",
               "public_key" => public.encoded
             })

    assert {:ok, %{lines: [authorized]}} =
             SSH.runtime_operation(principal(ctx.target), "authorized_keys", %{
               "username" => "app",
               "key" => public.encoded
             })

    assert authorized == "no-agent-forwarding " <> line

    assert {:ok, %{lines: []}} =
             SSH.runtime_operation(principal(ctx.target), "authorized_keys", %{
               "username" => "root",
               "key" => public.encoded
             })

    for reason <- ["ORDER", "HOSTNAME", "ADDRESS"] do
      assert {:ok, %{lines: [known]}} =
               SSH.runtime_operation(principal(ctx.source), "known_hosts", %{
                 "uid" => 1000,
                 "username" => "deploy",
                 "reason" => reason,
                 "host" => "target.example",
                 "port" => 22
               })

      assert known == "target.example " <> ctx.host
    end

    Repo.update!(Ecto.Changeset.change(ctx.source, status: :suspended))

    assert {:error, :agent_not_active} =
             SSH.runtime_operation(principal(ctx.source), "identities", %{
               "uid" => 1000,
               "username" => "deploy"
             })

    assert {:ok, %{lines: []}} =
             SSH.runtime_operation(principal(ctx.target), "authorized_keys", %{
               "username" => "app",
               "key" => public.encoded
             })
  end

  test "certificate expiry/revocation, seal and audit failure prevent even public release", ctx do
    {:ok, _} = SSH.apply_changes(changes(ctx), 0)

    lookup = %{
      "uid" => 1000,
      "username" => "deploy",
      "reason" => "ORDER",
      "host" => "target.example",
      "port" => 22
    }

    cert = Repo.get!(Certificate, ctx.source.certificate_id)
    Repo.update!(Ecto.Changeset.change(cert, revoked: true))

    assert {:error, :certificate_revoked} =
             SSH.runtime_operation(principal(ctx.source), "known_hosts", lookup)

    Repo.update!(
      Ecto.Changeset.change(Repo.get!(Certificate, cert.id),
        revoked: false,
        valid_until: DateTime.add(DateTime.utc_now() |> DateTime.truncate(:second), -30)
      )
    )

    assert {:error, :certificate_expired} =
             SSH.runtime_operation(principal(ctx.source), "known_hosts", lookup)

    Repo.update!(
      Ecto.Changeset.change(cert,
        valid_until: DateTime.add(DateTime.utc_now() |> DateTime.truncate(:second), 3600)
      )
    )

    old = Application.get_env(:secrethub_core, :audit_hmac_secret)
    Application.put_env(:secrethub_core, :audit_hmac_secret, "")

    try do
      assert {:error, :audit_unavailable} =
               SSH.runtime_operation(principal(ctx.source), "known_hosts", lookup)

      assert {:error, :audit_unavailable} =
               SSH.apply_changes([%{"op" => "rule_delete", "id" => "grant"}], 1)
    after
      if old,
        do: Application.put_env(:secrethub_core, :audit_hmac_secret, old),
        else: Application.delete_env(:secrethub_core, :audit_hmac_secret)
    end

    assert SSH.snapshot().revision == 1
    GenServer.stop(Process.whereis(SealState))
    assert {:error, :sealed} = SSH.runtime_operation(principal(ctx.source), "known_hosts", lookup)
  end

  test "audit-triggered revocation is observed before private material is released", ctx do
    {:ok, snapshot} = SSH.apply_changes(changes(ctx), 0)
    [identity] = snapshot.identities
    {:ok, public} = Key.decode_public(identity.public_key)

    Repo.query!("""
    CREATE FUNCTION ssh_revoke_during_audit() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      UPDATE certificates SET revoked = true WHERE entity_id = 'source';
      RETURN NEW;
    END; $$
    """)

    Repo.query!("""
    CREATE TRIGGER ssh_revoke_during_audit AFTER INSERT ON audit_logs
    FOR EACH ROW WHEN (NEW.event_type = 'ssh.authorize_sign')
    EXECUTE FUNCTION ssh_revoke_during_audit()
    """)

    assert {:error, :certificate_revoked} =
             SSH.runtime_operation(principal(ctx.source), "authorize_sign", %{
               "uid" => 1000,
               "username" => "deploy",
               "public_key" => public.encoded
             })
  end

  test "not-yet-valid and mismatched certificates are rejected", ctx do
    {:ok, _} = SSH.apply_changes(changes(ctx), 0)
    cert = Repo.get!(Certificate, ctx.source.certificate_id)

    Repo.update!(
      Ecto.Changeset.change(cert,
        valid_from: DateTime.add(DateTime.utc_now() |> DateTime.truncate(:second), 3600)
      )
    )

    payload = %{"uid" => 1000, "username" => "deploy"}

    assert {:error, :certificate_not_yet_valid} =
             SSH.runtime_operation(principal(ctx.source), "identities", payload)

    assert {:error, :certificate_mismatch} =
             SSH.runtime_operation(
               %{agent_id: "source", certificate_id: ctx.target.certificate_id},
               "identities",
               payload
             )
  end

  @tag :ipv6
  test "IPv6 aliases and nondefault ports bind approved replacement keys exactly", ctx do
    {:ok, _} = SSH.apply_changes(changes(ctx), 0)
    {:ok, replacement} = Key.generate("ed25519")

    change = %{
      "op" => "endpoint_upsert",
      "agent_id" => "target",
      "aliases" => ["::1", "TARGET.EXAMPLE.", "127.0.0.1"],
      "port" => 2222,
      "host_keys" => [ctx.host, replacement.public.public_line],
      "approved" => true
    }

    assert {:ok, _} = SSH.apply_changes([change], 1)

    lookup = %{
      "uid" => 1000,
      "username" => "deploy",
      "reason" => "ADDRESS",
      "host" => "0:0:0:0:0:0:0:1",
      "port" => 2222
    }

    assert {:ok, %{lines: lines}} =
             SSH.runtime_operation(principal(ctx.source), "known_hosts", lookup)

    assert Enum.sort(lines) ==
             Enum.sort([
               "[::1]:2222 " <> ctx.host,
               "[::1]:2222 " <> replacement.public.public_line
             ])

    for host <- ["::1", "target.example", "127.0.0.1"],
        reason <- ["ORDER", "HOSTNAME", "ADDRESS"] do
      assert {:ok, %{lines: wrapped_lines}} =
               SSH.runtime_operation(principal(ctx.source), "known_hosts", %{
                 lookup
                 | "host" => "[#{host}]:2222",
                   "reason" => reason
               })

      assert ("[#{host}]:2222 " <> ctx.host) in wrapped_lines
    end

    assert {:error, :invalid_request} =
             SSH.runtime_operation(principal(ctx.source), "known_hosts", %{
               lookup
               | "host" => "[::1]:2223"
             })

    assert {:ok, %{lines: []}} =
             SSH.runtime_operation(principal(ctx.source), "known_hosts", %{lookup | "port" => 22})

    assert {:ok, _} =
             SSH.apply_changes([%{change | "host_keys" => [replacement.public.public_line]}], 2)

    assert {:ok, %{lines: [line]}} =
             SSH.runtime_operation(principal(ctx.source), "known_hosts", lookup)

    assert line == "[::1]:2222 " <> replacement.public.public_line
  end

  test "candidate inventory never creates approval and missing signing capability fails closed",
       ctx do
    {:ok, _} = SSH.apply_changes(changes(ctx), 0)
    {:ok, candidate} = Key.generate("ed25519")

    assert {:ok, %{revision: 2}} =
             SSH.runtime_operation(principal(ctx.target), "inventory", %{
               "host_keys" => [candidate.public.public_line]
             })

    assert [%{approved: true, host_keys: [approved], candidate_host_keys: [candidate_line]}] =
             SSH.snapshot().endpoints

    assert approved == ctx.host
    assert candidate_line == candidate.public.public_line

    Repo.update!(
      Ecto.Changeset.change(Repo.get!(Agent, ctx.source.id),
        runtime_capabilities: ["ssh_lookup_v1"]
      )
    )

    assert {:error, :capability_unavailable} =
             SSH.runtime_operation(principal(ctx.source), "identities", %{
               "uid" => 1000,
               "username" => "deploy"
             })

    [identity] = SSH.snapshot().identities
    {:ok, public} = Key.decode_public(identity.public_key)

    assert {:ok, %{lines: []}} =
             SSH.runtime_operation(principal(ctx.target), "authorized_keys", %{
               "username" => "app",
               "key" => public.encoded
             })
  end

  @tag :reports
  test "reported OS prerequisites are advisory, public and revisioned", ctx do
    start_supervised!({Phoenix.PubSub, name: SecretHub.Web.PubSub})
    Phoenix.PubSub.subscribe(SecretHub.Web.PubSub, "ssh:policy")
    Repo.update!(Ecto.Changeset.change(ctx.source, runtime_capabilities: ["ssh_signing_v1"]))

    users = [
      %{
        "username" => "deploy",
        "uid" => 1000,
        "signing_access" => true,
        "lookup_access" => false,
        "unambiguous" => true
      }
    ]

    assert {:ok, %{revision: 1}} =
             SSH.runtime_operation(principal(ctx.source), "inventory", %{
               "host_keys" => [ctx.host],
               "users" => users
             })

    source = Enum.find(SSH.snapshot().agents, &(&1.agent_id == "source"))

    assert [
             %{
               username: "deploy",
               uid: 1000,
               signing_access: true,
               lookup_access: false,
               unambiguous: true
             }
           ] = source.ssh_users

    assert is_binary(source.ssh_inventory_seen_at)
    assert_receive {:ssh_policy_changed, 1}

    assert {:ok, %{revision: 1}} =
             SSH.runtime_operation(principal(ctx.source), "inventory", %{
               "host_keys" => [ctx.host],
               "users" => users
             })

    refute_receive {:ssh_policy_changed, _}, 30
    assert [] = SSH.snapshot().identities

    assert [%{approved: false, host_keys: [], candidate_host_keys: [_]}] =
             SSH.snapshot().endpoints

    assert {:error, :invalid_request} =
             SSH.runtime_operation(principal(ctx.source), "inventory", %{
               "users" => [%{"username" => "deploy", "uid" => -1}]
             })

    assert SSH.snapshot().revision == 1
  end

  @tag :float_uid
  test "a numeric UID must be an integer at the runtime boundary", ctx do
    {:ok, snapshot} = SSH.apply_changes(changes(ctx), 0)
    [identity] = snapshot.identities
    {:ok, public} = Key.decode_public(identity.public_key)

    case SSH.runtime_operation(principal(ctx.source), "authorize_sign", %{
           "uid" => 1000.0,
           "username" => "deploy",
           "public_key" => public.encoded
         }) do
      {:error, :denied} -> :ok
      _ -> flunk("noninteger UID released an identity; sensitive result redacted")
    end
  end

  @tag :audit_upgrade
  test "a denied decision cannot become a key release because an audit trigger enables the source",
       ctx do
    {:ok, snapshot} = SSH.apply_changes(changes(ctx), 0)
    [identity] = snapshot.identities
    {:ok, public} = Key.decode_public(identity.public_key)
    Repo.update!(Ecto.Changeset.change(ctx.source, status: :suspended))

    Repo.query!("""
    CREATE FUNCTION ssh_enable_during_audit() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      UPDATE agents SET status = 'trusted_connected' WHERE agent_id = 'source';
      RETURN NEW;
    END; $$
    """)

    Repo.query!("""
    CREATE TRIGGER ssh_enable_during_audit AFTER INSERT ON audit_logs
    FOR EACH ROW WHEN (NEW.event_type = 'ssh.authorize_sign')
    EXECUTE FUNCTION ssh_enable_during_audit()
    """)

    case SSH.runtime_operation(principal(ctx.source), "authorize_sign", %{
           "uid" => 1000,
           "username" => "deploy",
           "public_key" => public.encoded
         }) do
      {:error, :denied} -> :ok
      _ -> flunk("a denied decision changed into a release; sensitive result redacted")
    end
  end

  defp changes(ctx) do
    [
      %{"op" => "group_upsert", "id" => "build", "name" => "Build"},
      %{"op" => "group_members", "group_id" => "build", "agent_ids" => ["source"]},
      %{
        "op" => "endpoint_upsert",
        "agent_id" => "target",
        "aliases" => ["target.example"],
        "port" => 22,
        "host_keys" => [ctx.host],
        "approved" => true
      },
      %{
        "op" => "identity_upsert",
        "agent_id" => "source",
        "username" => "deploy",
        "uid" => 1000,
        "algorithm" => "ed25519"
      },
      %{
        "op" => "rule_upsert",
        "id" => "grant",
        "effect" => "allow",
        "enabled" => true,
        "source_kind" => "group",
        "source_id" => "build",
        "source_user" => "deploy",
        "destination_kind" => "agent",
        "destination_id" => "target",
        "destination_user" => "app"
      }
    ]
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

  defp principal(agent), do: %{agent_id: agent.agent_id, certificate_id: agent.certificate_id}
  defp await_state(expected, attempts \\ 100)
  defp await_state(_, 0), do: flunk("Vault not ready")

  defp await_state(expected, attempts) do
    if SealState.status().state != expected do
      Process.sleep(10)
      await_state(expected, attempts - 1)
    end
  end
end
