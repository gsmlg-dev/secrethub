defmodule SecretHub.Core.SSH.RuntimeTest do
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

  defp enroll(ctx, uid \\ 1000, username \\ "gao") do
    {:ok, key} = Key.generate("ed25519")

    assert {:ok, %{revision: _}} =
             SSH.runtime_operation(principal(ctx.source), "identity_report", %{
               "uid" => uid,
               "username" => username,
               "generation" => 1,
               "public_key" => key.public.public_line
             })

    identity = Enum.find(SSH.snapshot().identities, &(&1.local_uid == uid))
    {key, identity}
  end

  defp grant(ctx, identity) do
    rev = SSH.snapshot().revision

    {:ok, _} =
      SSH.apply_changes(
        [
          %{"op" => "identity_approve", "id" => identity.id},
          endpoint(ctx),
          %{
            "op" => "rule_upsert",
            "id" => "grant",
            "effect" => "allow",
            "source_kind" => "identity",
            "source_id" => identity.id,
            "destination_kind" => "endpoint",
            "destination_id" => "target",
            "destination_user" => "app"
          }
        ],
        rev
      )
  end

  defp endpoint(ctx) do
    %{
      "op" => "endpoint_upsert",
      "agent_id" => "target",
      "aliases" => ["target.example"],
      "port" => 22,
      "host_keys" => [ctx.host],
      "approved" => true
    }
  end

  defp sign(key, overrides \\ %{}),
    do:
      Map.merge(
        %{"uid" => 1000, "username" => "gao", "public_key" => key.public.public_line},
        overrides
      )

  defp lookup(overrides \\ %{}),
    do:
      Map.merge(
        %{
          "uid" => 1000,
          "username" => "gao",
          "reason" => "ORDER",
          "host" => "target.example",
          "port" => 22
        },
        overrides
      )

  test "report creates a pending identity; authorize_sign never returns key material", ctx do
    {key, identity} = enroll(ctx)
    assert %{status: "pending", name: "gao@source"} = identity
    payload = sign(key)

    assert {:error, :denied} =
             SSH.runtime_operation(principal(ctx.source), "authorize_sign", payload)

    grant(ctx, identity)
    assert {:ok, reply} = SSH.runtime_operation(principal(ctx.source), "authorize_sign", payload)
    assert reply.allowed == true and reply.public_key == key.public.public_line
    refute Map.has_key?(reply, :private_key)
    refute inspect(reply) =~ "PRIVATE KEY"

    assert {:ok, %{identities: [%{public_key: _, generation: 1}]}} =
             SSH.runtime_operation(principal(ctx.source), "identities", %{
               "uid" => 1000,
               "username" => "gao"
             })

    assert {:error, :denied} =
             SSH.runtime_operation(principal(ctx.source), "authorize_sign", %{
               payload
               | "username" => "eve"
             })

    assert {:error, :denied} =
             SSH.runtime_operation(principal(ctx.source), "authorize_sign", %{
               payload
               | "uid" => 999
             })
  end

  test "re-reporting the same key is idempotent and does not bump the revision", ctx do
    {key, _identity} = enroll(ctx)
    revision = SSH.snapshot().revision

    assert {:ok, reply} =
             SSH.runtime_operation(principal(ctx.source), "identity_report", %{
               "uid" => 1000,
               "username" => "gao",
               "generation" => 1,
               "public_key" => key.public.public_line
             })

    assert reply == %{revision: revision}
    assert SSH.snapshot().revision == revision
  end

  test "a deleted identity lets the next generation-1 report create a new pending identity",
       ctx do
    {key, identity} = enroll(ctx)

    {:ok, _} =
      SSH.apply_changes(
        [%{"op" => "identity_revoke", "id" => identity.id}],
        SSH.snapshot().revision
      )

    report = %{
      "uid" => 1000,
      "username" => "gao",
      "generation" => 1,
      "public_key" => key.public.public_line
    }

    assert {:error, :denied} =
             SSH.runtime_operation(principal(ctx.source), "identity_report", report)

    {:ok, _} =
      SSH.apply_changes(
        [%{"op" => "identity_delete", "id" => identity.id}],
        SSH.snapshot().revision
      )

    {:ok, fresh} = Key.generate("ed25519")

    assert {:ok, %{accepted: true}} =
             SSH.runtime_operation(principal(ctx.source), "identity_report", %{
               report
               | "public_key" => fresh.public.public_line
             })

    assert [%{status: "pending", name: "gao@source", keys: [%{generation: 1}]} = new] =
             SSH.snapshot().identities

    refute new.id == identity.id
  end

  test "runtime uses current principal and directed policy for lookups and signing", ctx do
    {key, identity} = enroll(ctx)
    grant(ctx, identity)

    assert {:ok, %{lines: ["no-agent-forwarding " <> line]}} =
             SSH.runtime_operation(principal(ctx.target), "authorized_keys", %{
               "username" => "app",
               "key" => key.public.encoded
             })

    assert line == key.public.public_line

    for reason <- ["ORDER", "HOSTNAME", "ADDRESS"] do
      assert {:ok, %{lines: [known]}} =
               SSH.runtime_operation(
                 principal(ctx.source),
                 "known_hosts",
                 lookup(%{"reason" => reason})
               )

      assert known == "target.example " <> ctx.host
    end

    assert {:ok, %{lines: []}} =
             SSH.runtime_operation(
               principal(ctx.source),
               "known_hosts",
               lookup(%{"username" => "eve"})
             )

    Repo.update!(Ecto.Changeset.change(ctx.source, status: :suspended))

    assert {:error, :agent_not_active} =
             SSH.runtime_operation(principal(ctx.source), "identities", %{
               "uid" => 1000,
               "username" => "gao"
             })

    assert {:error, :agent_not_active} =
             SSH.runtime_operation(principal(ctx.source), "authorize_sign", sign(key))

    Repo.update!(Ecto.Changeset.change(Repo.get!(Agent, ctx.target.id), status: :suspended))

    assert {:error, :agent_not_active} =
             SSH.runtime_operation(principal(ctx.target), "authorized_keys", %{
               "username" => "app",
               "key" => key.public.encoded
             })
  end

  test "authorized_keys no longer requires the source Agent to be online", ctx do
    {key, identity} = enroll(ctx)
    grant(ctx, identity)
    Repo.update!(Ecto.Changeset.change(ctx.source, runtime_capabilities: []))

    assert {:ok, %{lines: ["no-agent-forwarding " <> line]}} =
             SSH.runtime_operation(principal(ctx.target), "authorized_keys", %{
               "username" => "app",
               "key" => key.public.public_line
             })

    assert line == key.public.public_line

    assert {:ok, %{lines: []}} =
             SSH.runtime_operation(principal(ctx.target), "authorized_keys", %{
               "username" => "root",
               "key" => key.public.public_line
             })
  end

  test "external identities appear in authorized_keys", ctx do
    {:ok, ext} = Key.generate("ed25519")

    {:ok, %{identities: [identity]}} =
      SSH.apply_changes(
        [
          %{
            "op" => "identity_external_add",
            "name" => "gh-deploy",
            "public_key" => ext.public.public_line,
            "rotation_days" => 30
          }
        ],
        0
      )

    rev = SSH.snapshot().revision

    {:ok, _} =
      SSH.apply_changes(
        [
          endpoint(ctx),
          %{
            "op" => "rule_upsert",
            "id" => "deploy",
            "effect" => "allow",
            "source_kind" => "identity",
            "source_id" => identity.id,
            "destination_kind" => "endpoint",
            "destination_id" => "target",
            "destination_user" => "deploy"
          }
        ],
        rev
      )

    assert {:ok, %{lines: [_]}} =
             SSH.runtime_operation(principal(ctx.target), "authorized_keys", %{
               "username" => "deploy",
               "key" => ext.public.public_line
             })
  end

  test "rotation: inventory carries requested generations and only the next one is accepted",
       ctx do
    {old, identity} = enroll(ctx)
    grant(ctx, identity)

    {:ok, _} =
      SSH.apply_changes(
        [%{"op" => "identity_rotate", "id" => identity.id}],
        SSH.snapshot().revision
      )

    assert {:ok,
            %{identity_generations: [%{uid: 1000, requested_generation: 2, generations: [1]}]}} =
             SSH.runtime_operation(principal(ctx.source), "inventory", %{
               "host_keys" => [],
               "users" => []
             })

    {:ok, wrong} = Key.generate("ed25519")

    assert {:error, :denied} =
             SSH.runtime_operation(principal(ctx.source), "identity_report", %{
               "uid" => 1000,
               "username" => "gao",
               "generation" => 3,
               "public_key" => wrong.public.public_line
             })

    {:ok, new} = Key.generate("ed25519")

    assert {:ok, _} =
             SSH.runtime_operation(principal(ctx.source), "identity_report", %{
               "uid" => 1000,
               "username" => "gao",
               "generation" => 2,
               "public_key" => new.public.public_line
             })

    for key <- [old, new] do
      assert {:ok, %{allowed: true}} =
               SSH.runtime_operation(principal(ctx.source), "authorize_sign", sign(key))
    end

    assert {:ok, %{identity_generations: [%{requested_generation: 2, generations: [1, 2]}]}} =
             SSH.runtime_operation(principal(ctx.source), "inventory", %{
               "host_keys" => [],
               "users" => []
             })
  end

  test "pending host keys fail closed for every runtime view", ctx do
    {key, identity} = enroll(ctx)
    grant(ctx, identity)

    {:ok, _} =
      SSH.apply_changes([%{endpoint(ctx) | "approved" => false}], SSH.snapshot().revision)

    assert {:ok, %{identities: []}} =
             SSH.runtime_operation(principal(ctx.source), "identities", %{
               "uid" => 1000,
               "username" => "gao"
             })

    assert {:error, :denied} =
             SSH.runtime_operation(principal(ctx.source), "authorize_sign", sign(key))

    assert {:ok, %{lines: []}} =
             SSH.runtime_operation(principal(ctx.target), "authorized_keys", %{
               "username" => "app",
               "key" => key.public.public_line
             })

    assert {:ok, %{lines: []}} =
             SSH.runtime_operation(principal(ctx.source), "known_hosts", lookup())
  end

  test "sealed vault fails closed for runtime operations", ctx do
    {key, identity} = enroll(ctx)
    grant(ctx, identity)
    GenServer.stop(Process.whereis(SealState))

    assert {:error, :sealed} =
             SSH.runtime_operation(principal(ctx.source), "authorize_sign", sign(key))

    assert {:error, :sealed} =
             SSH.runtime_operation(principal(ctx.source), "known_hosts", lookup())
  end

  test "certificate expiry/revocation and audit failure deny authorize_sign", ctx do
    {key, identity} = enroll(ctx)
    grant(ctx, identity)
    revision = SSH.snapshot().revision
    cert = Repo.get!(Certificate, ctx.source.certificate_id)
    Repo.update!(Ecto.Changeset.change(cert, revoked: true))

    assert {:error, :certificate_revoked} =
             SSH.runtime_operation(principal(ctx.source), "authorize_sign", sign(key))

    assert {:error, :certificate_revoked} =
             SSH.runtime_operation(principal(ctx.source), "known_hosts", lookup())

    Repo.update!(
      Ecto.Changeset.change(Repo.get!(Certificate, cert.id),
        revoked: false,
        valid_until: DateTime.add(DateTime.utc_now() |> DateTime.truncate(:second), -30)
      )
    )

    assert {:error, :certificate_expired} =
             SSH.runtime_operation(principal(ctx.source), "authorize_sign", sign(key))

    Repo.update!(
      Ecto.Changeset.change(cert,
        valid_until: DateTime.add(DateTime.utc_now() |> DateTime.truncate(:second), 3600)
      )
    )

    assert {:ok, %{allowed: true}} =
             SSH.runtime_operation(principal(ctx.source), "authorize_sign", sign(key))

    old = Application.get_env(:secrethub_core, :audit_hmac_secret)
    Application.put_env(:secrethub_core, :audit_hmac_secret, "")

    try do
      assert {:error, :audit_unavailable} =
               SSH.runtime_operation(principal(ctx.source), "authorize_sign", sign(key))

      assert {:error, :audit_unavailable} =
               SSH.runtime_operation(principal(ctx.source), "known_hosts", lookup())

      {:ok, next} = Key.generate("ed25519")

      assert {:error, :audit_unavailable} =
               SSH.runtime_operation(principal(ctx.source), "identity_report", %{
                 "uid" => 2000,
                 "username" => "ops",
                 "generation" => 1,
                 "public_key" => next.public.public_line
               })

      assert {:error, :audit_unavailable} =
               SSH.apply_changes([%{"op" => "rule_delete", "id" => "grant"}], revision)
    after
      if old,
        do: Application.put_env(:secrethub_core, :audit_hmac_secret, old),
        else: Application.delete_env(:secrethub_core, :audit_hmac_secret)
    end

    assert %{revision: ^revision, identities: [_]} = SSH.snapshot()
  end

  test "audit-triggered revocation is observed before authorize_sign is allowed", ctx do
    {key, identity} = enroll(ctx)
    grant(ctx, identity)

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
             SSH.runtime_operation(principal(ctx.source), "authorize_sign", sign(key))
  end

  @tag :audit_upgrade
  test "a denied decision cannot become an allow because an audit trigger enables the source",
       ctx do
    {key, identity} = enroll(ctx)
    grant(ctx, identity)
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

    case SSH.runtime_operation(principal(ctx.source), "authorize_sign", sign(key)) do
      {:error, _} -> :ok
      _ -> flunk("a denied decision changed into an allow")
    end
  end

  test "not-yet-valid and mismatched certificates are rejected", ctx do
    {_key, identity} = enroll(ctx)
    grant(ctx, identity)
    cert = Repo.get!(Certificate, ctx.source.certificate_id)

    Repo.update!(
      Ecto.Changeset.change(cert,
        valid_from: DateTime.add(DateTime.utc_now() |> DateTime.truncate(:second), 3600)
      )
    )

    payload = %{"uid" => 1000, "username" => "gao"}

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
    {_key, identity} = enroll(ctx)
    grant(ctx, identity)
    {:ok, replacement} = Key.generate("ed25519")

    change = %{
      "op" => "endpoint_upsert",
      "agent_id" => "target",
      "aliases" => ["::1", "TARGET.EXAMPLE.", "127.0.0.1"],
      "port" => 2222,
      "host_keys" => [ctx.host, replacement.public.public_line],
      "approved" => true
    }

    assert {:ok, _} = SSH.apply_changes([change], SSH.snapshot().revision)
    lookup = lookup(%{"reason" => "ADDRESS", "host" => "0:0:0:0:0:0:0:1", "port" => 2222})

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
             SSH.apply_changes(
               [%{change | "host_keys" => [replacement.public.public_line]}],
               SSH.snapshot().revision
             )

    assert {:ok, %{lines: [line]}} =
             SSH.runtime_operation(principal(ctx.source), "known_hosts", lookup)

    assert line == "[::1]:2222 " <> replacement.public.public_line
  end

  test "candidate inventory never creates approval and missing signing capability fails closed",
       ctx do
    {key, identity} = enroll(ctx)
    grant(ctx, identity)
    revision = SSH.snapshot().revision
    {:ok, candidate} = Key.generate("ed25519")
    expected = revision + 1

    assert {:ok, %{revision: ^expected}} =
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
               "username" => "gao"
             })

    assert {:error, :capability_unavailable} =
             SSH.runtime_operation(principal(ctx.source), "authorize_sign", sign(key))

    {:ok, next} = Key.generate("ed25519")

    assert {:error, :capability_unavailable} =
             SSH.runtime_operation(principal(ctx.source), "identity_report", %{
               "uid" => 2000,
               "username" => "ops",
               "generation" => 1,
               "public_key" => next.public.public_line
             })

    assert [_] = SSH.snapshot().identities
  end

  @tag :reports
  test "reported OS prerequisites are advisory, public and revisioned", ctx do
    unless Process.whereis(SecretHub.Web.PubSub) do
      start_supervised!({Phoenix.PubSub, name: SecretHub.Web.PubSub})
    end

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

    assert {:ok, %{revision: 1, identity_generations: []}} =
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

    assert {:ok, %{revision: 1} = reply} =
             SSH.runtime_operation(principal(ctx.source), "inventory", %{
               "host_keys" => [ctx.host],
               "users" => users
             })

    refute Map.has_key?(reply, :unchanged)
    refute_receive {:ssh_policy_changed, _}, 30
    assert [] = SSH.snapshot().identities

    assert [%{approved: false, host_keys: [], candidate_host_keys: [_]}] =
             SSH.snapshot().endpoints

    assert {:error, :invalid_request} =
             SSH.runtime_operation(principal(ctx.source), "inventory", %{
               "users" => [%{"username" => "deploy", "uid" => -1}]
             })

    assert SSH.snapshot().revision == 1

    {:ok, key} = Key.generate("ed25519")

    assert {:ok, %{revision: 2, accepted: true}} =
             SSH.runtime_operation(principal(ctx.source), "identity_report", %{
               "uid" => 1000,
               "username" => "deploy",
               "generation" => 1,
               "public_key" => key.public.public_line
             })

    assert_receive {:ssh_policy_changed, 2}
  end

  @tag :float_uid
  test "a numeric UID must be an integer at the runtime boundary", ctx do
    {key, identity} = enroll(ctx)
    grant(ctx, identity)

    assert {:error, :invalid_request} =
             SSH.runtime_operation(principal(ctx.source), "identities", %{
               "uid" => 1000.0,
               "username" => "gao"
             })

    case SSH.runtime_operation(
           principal(ctx.source),
           "authorize_sign",
           sign(key, %{"uid" => 1000.0})
         ) do
      {:error, :denied} -> :ok
      _ -> flunk("noninteger UID authorized a signature")
    end

    {:ok, next} = Key.generate("ed25519")

    assert {:error, :denied} =
             SSH.runtime_operation(principal(ctx.source), "identity_report", %{
               "uid" => 2000.0,
               "username" => "ops",
               "generation" => 1,
               "public_key" => next.public.public_line
             })

    assert [_] = SSH.snapshot().identities
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
