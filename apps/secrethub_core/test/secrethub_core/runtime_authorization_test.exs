defmodule SecretHub.Core.RuntimeAuthorizationTest do
  use ExUnit.Case, async: false
  import Ecto.Query
  alias SecretHub.Core.Repo

  alias SecretHub.Core.RuntimeDatabaseFixture
  alias SecretHub.Core.RuntimeDatabaseFixture.VaultRepo

  setup_all do
    RuntimeDatabaseFixture.prepare_template()
  end

  setup tags do
    RuntimeDatabaseFixture.setup(tags)
  end

  alias SecretHub.Core.{
    Apps,
    AuthorizationVersions,
    Policies,
    RuntimeAuthorization,
    RuntimePrincipal,
    Secrets,
    UpgradeGates
  }

  alias SecretHub.Core.PKI.{AppCertificates, AppCertificatePreflight, CA}
  alias SecretHub.Core.Vault.SealState
  alias SecretHub.Shared.Schemas.{Agent, AuditLog, SecretPathRevision}

  setup tags do
    if pid = Process.whereis(SealState), do: GenServer.stop(pid)
    start_supervised!({SealState, repo: VaultRepo})
    await_empty()
    {:ok, shares} = SealState.initialize(3, 2)
    {:ok, _} = SealState.unseal(Enum.at(shares, 0))
    {:ok, _} = SealState.unseal(Enum.at(shares, 1))
    unique = System.unique_integer([:positive])
    {:ok, _} = CA.generate_root_ca("Authorization Root #{unique}", "SecretHub", key_size: 2048)
    public_id = "authorization-agent-#{unique}"
    {:ok, cert} = CA.issue_agent_certificate(public_id)
    # Enrollment establishes this binding; CA issuance alone does not.
    cert = Repo.update!(Ecto.Changeset.change(cert, entity_id: public_id, entity_type: "agent"))

    agent =
      Repo.insert!(
        Agent.changeset(%Agent{}, %{
          agent_id: public_id,
          name: "Authorization Agent",
          status: :active,
          certificate_id: cert.id
        })
      )

    {:ok, %{app: app, token: token}} =
      Apps.register_app(%{name: "authorization-app-#{unique}", agent_id: agent.id})

    key = X509.PrivateKey.new_ec(:secp256r1)
    csr = key |> X509.CSR.new("/CN=untrusted") |> X509.CSR.to_pem()
    {:ok, issued} = AppCertificates.issue_from_bootstrap(token, csr, Ecto.UUID.generate())
    path = "test.authorization.secret"

    for subject <- ["agent:" <> agent.id, "application:" <> app.id] do
      {:ok, _} =
        Policies.create_policy(%{
          name: "runtime-#{subject}",
          policy_document: %{
            "version" => "1.0",
            "allowed_secrets" => ["test.authorization.*"],
            "allowed_operations" => ["read"]
          },
          entity_bindings: [subject]
        })
    end

    {:ok, secret} =
      Secrets.create_secret(%{
        name: "Authorized Secret",
        secret_path: path,
        value: "private-runtime-value"
      })

    identity = %{agent_id: public_id, certificate_id: cert.id}

    {:ok, principal} =
      RuntimePrincipal.resolve_runtime_principal(
        identity,
        app.id,
        issued.cert_record.canonical_fingerprint
      )

    unless tags[:cutover],
      do:
        assert(
          {:ok, _} = UpgradeGates.verify_typed_runtime_authorization(actor_id: "operator:test")
        )

    %{
      agent: agent,
      app: app,
      certificate: issued.cert_record,
      identity: identity,
      principal: %{principal | local_auth_version: 2},
      secret: secret,
      path: path
    }
  end

  test "Core derives the app and rejects wrong claims and runtime certificate identity", ctx do
    assert {:error, :invalid_application} =
             RuntimePrincipal.resolve_runtime_principal(
               ctx.identity,
               "1234567890123456",
               ctx.certificate.canonical_fingerprint
             )

    assert {:error, _} =
             RuntimePrincipal.resolve_runtime_principal(
               ctx.identity,
               Ecto.UUID.generate(),
               ctx.certificate.canonical_fingerprint
             )

    assert {:error, :invalid_fingerprint} =
             RuntimePrincipal.resolve_runtime_principal(
               ctx.identity,
               ctx.app.id,
               String.upcase(ctx.certificate.canonical_fingerprint)
             )

    assert {:error, _} =
             RuntimePrincipal.resolve_runtime_principal(
               %{ctx.identity | agent_id: "different-agent"},
               ctx.app.id,
               ctx.certificate.canonical_fingerprint
             )

    Repo.update!(Ecto.Changeset.change(ctx.certificate, cert_type: :agent_client))

    assert {:error, _} =
             RuntimePrincipal.resolve_runtime_principal(
               ctx.identity,
               ctx.app.id,
               ctx.certificate.canonical_fingerprint
             )
  end

  test "read and exact-revision cache approval retain application audit identity without values",
       ctx do
    assert {:ok, %{value: %{"value" => "private-runtime-value"}, revision: revision, version: 1}} =
             RuntimeAuthorization.authorize_static_read(ctx.principal, ctx.path)

    assert {:ok, %{not_modified: true, revision: ^revision}} =
             RuntimeAuthorization.authorize_static_read(ctx.principal, ctx.path, revision)

    log =
      Repo.one!(
        from(a in AuditLog,
          where: a.event_type == "secret.accessed",
          order_by: [desc: a.id],
          limit: 1
        )
      )

    assert log.actor_type == "application"
    assert log.actor_id == ctx.app.id
    assert log.event_data["certificate_fingerprint"] == ctx.certificate.canonical_fingerprint
    refute inspect(log.event_data) =~ "private-runtime-value"
  end

  test "the Agent and app gates are independent and explicit deny wins", ctx do
    app_policy =
      Repo.get_by!(SecretHub.Shared.Schemas.Policy, name: "runtime-application:" <> ctx.app.id)

    {:ok, _} = Policies.delete_policy(app_policy.id)

    assert {:error, :permission_denied} =
             RuntimeAuthorization.authorize_static_read(ctx.principal, ctx.path)

    {:ok, _} =
      Policies.create_policy(%{
        name: "global-allow",
        policy_document: %{
          "version" => "1.0",
          "allowed_secrets" => ["**"],
          "allowed_operations" => ["read"]
        }
      })

    {:ok, _} =
      Policies.create_policy(%{
        name: "agent-deny",
        deny_policy: true,
        entity_bindings: ["agent:" <> ctx.agent.id],
        policy_document: %{
          "version" => "1.0",
          "allowed_secrets" => ["**"],
          "allowed_operations" => ["read"]
        }
      })

    assert {:error, :permission_denied} =
             RuntimeAuthorization.authorize_static_read(ctx.principal, ctx.path)

    assert Repo.exists?(
             from(a in AuditLog, where: a.actor_id == ^ctx.app.id and a.access_granted == false)
           )
  end

  test "suspension, revocation, reassignment, expiry and missing associations are rechecked",
       ctx do
    assert {:ok, _} = Apps.suspend_app(ctx.app.id)
    assert {:error, _} = RuntimeAuthorization.authorize_static_read(ctx.principal, ctx.path)
    assert {:ok, _} = Apps.activate_app(ctx.app.id)
    assert {:ok, _} = AppCertificates.revoke(ctx.app.id, ctx.certificate.id, "operator_revoked")
    assert {:error, _} = RuntimeAuthorization.authorize_static_read(ctx.principal, ctx.path)
  end

  test "path revision survives delete and recreation, updates and rollback", ctx do
    first = Repo.get!(SecretPathRevision, ctx.path).revision
    {:ok, updated} = Secrets.update_secret(ctx.secret.id, %{value: "replacement"})
    second = Repo.get!(SecretPathRevision, ctx.path).revision
    assert second > first
    assert {:ok, _} = Secrets.rollback_secret(updated.id, 1)
    third = Repo.get!(SecretPathRevision, ctx.path).revision
    assert third > second
    assert {:ok, _} = Secrets.delete_secret(updated.id)
    fourth = Repo.get!(SecretPathRevision, ctx.path).revision
    assert fourth > third

    assert {:ok, _} =
             Secrets.create_secret(%{
               name: "Recreated",
               secret_path: ctx.path,
               value: "new-value"
             })

    assert Repo.get!(SecretPathRevision, ctx.path).revision > fourth

    assert {:ok, %{value: %{"value" => "new-value"}}} =
             RuntimeAuthorization.authorize_static_read(ctx.principal, ctx.path, first)
  end

  test "sealed cache and malformed path/revision cannot release a value", ctx do
    revision = Repo.get!(SecretPathRevision, ctx.path).revision

    assert {:error, :invalid_path} =
             RuntimeAuthorization.authorize_static_read(
               ctx.principal,
               "test/authorization/secret"
             )

    assert {:error, :invalid_revision} =
             RuntimeAuthorization.authorize_static_read(ctx.principal, ctx.path, "1")

    stop_supervised!(SealState)
    start_supervised!({SealState, repo: VaultRepo})
    await_state(:sealed)

    assert {:error, :sealed} =
             RuntimeAuthorization.authorize_static_read(ctx.principal, ctx.path, revision)
  end

  @tag :cutover
  test "activation requires mechanical preflights and authenticated capable Agents", ctx do
    assert {:error, :authorization_unavailable} =
             RuntimeAuthorization.authorize_static_read(ctx.principal, ctx.path)

    assert {:error, :typed_authorization_not_verified} =
             UpgradeGates.activate_app_certificate_v2(actor_id: "operator:test")

    assert {:ok, _} = AppCertificatePreflight.backfill_canonical_fingerprints()
    assert AuthorizationVersions.report().findings == []
    assert {:ok, _} = UpgradeGates.verify_typed_runtime_authorization(actor_id: "operator:test")

    assert {:error, :no_fresh_active_agents} =
             UpgradeGates.activate_app_certificate_v2(actor_id: "operator:test")

    assert :ok = UpgradeGates.record_agent_runtime_capabilities(ctx.identity, [])

    assert {:error, {:incompatible_agents, _}} =
             UpgradeGates.activate_app_certificate_v2(actor_id: "operator:test")

    assert :ok =
             UpgradeGates.record_agent_runtime_capabilities(ctx.identity, [
               "uds_auth_v2",
               "unknown",
               "uds_auth_v2"
             ])

    retired =
      Repo.insert!(
        Agent.changeset(%Agent{}, %{
          agent_id: "retired-fixture",
          name: "Retired",
          status: :suspended
        })
      )

    assert {:error, {:stale_agents, [snapshot]}} =
             UpgradeGates.activate_app_certificate_v2(actor_id: "operator:test")

    assert snapshot.agent_id == retired.agent_id

    assert {:error, {:stale_agents, _}} =
             UpgradeGates.activate_app_certificate_v2(
               actor_id: "operator:test",
               stale_agent_acknowledgements: [Map.put(snapshot, :reason, "")]
             )

    assert {:ok, _} =
             UpgradeGates.activate_app_certificate_v2(
               actor_id: "operator:test",
               stale_agent_acknowledgements: [
                 Map.put(snapshot, :reason, "isolated retired fixture")
               ]
             )

    assert UpgradeGates.minimum_uds_auth_version() == 2

    assert [[1]] =
             Repo.query!("SELECT count(*) FROM upgrade_gate_stale_agent_acknowledgements").rows

    assert {:error, :incompatible_version} =
             RuntimeAuthorization.authorize_static_read(
               %{ctx.principal | local_auth_version: 1},
               ctx.path
             )

    assert {:error, :incompatible_version} =
             UpgradeGates.record_agent_runtime_capabilities(ctx.identity, [])

    assert {:ok, _} = UpgradeGates.activate_app_certificate_v2(actor_id: "operator:test")
  end

  test "floor activation committed while an older request waits is rechecked", ctx do
    assert {:ok, _} = AppCertificatePreflight.backfill_canonical_fingerprints()
    assert :ok = UpgradeGates.record_agent_runtime_capabilities(ctx.identity, ["uds_auth_v2"])
    parent = self()

    writer =
      db_task(:cutover, fn ->
        AuthorizationVersions.lock_global()
        assert {:ok, _} = UpgradeGates.activate_app_certificate_v2(actor_id: "operator:test")
        send(parent, :floor_written)

        receive do
          :commit_floor -> :ok
        after
          5_000 -> flunk("floor commit release missing")
        end
      end)

    assert_receive {:backend, :cutover, _}, 2_000
    assert_receive :floor_written, 2_000

    reader =
      db_task(:reader, fn ->
        RuntimeAuthorization.authorize_static_read(
          %{ctx.principal | local_auth_version: 1},
          ctx.path
        )
      end)

    assert_receive {:backend, :reader, pid}, 2_000
    await_lock(pid)
    send(writer.pid, :commit_floor)
    assert {:ok, :ok} = Task.await(writer, 10_000)
    assert {:ok, {:error, :incompatible_version}} = Task.await(reader, 10_000)
  end

  test "reassignment, expiration and removed association invalidate a previously resolved principal",
       ctx do
    {:ok, other} =
      SecretHub.Core.Agents.register_agent(%{agent_id: "other-assignment", name: "Other"})

    Repo.update!(Ecto.Changeset.change(ctx.app, agent_id: other.id))
    assert {:error, _} = RuntimeAuthorization.authorize_static_read(ctx.principal, ctx.path)

    Repo.update!(
      Ecto.Changeset.change(Repo.get!(SecretHub.Shared.Schemas.Application, ctx.app.id),
        agent_id: ctx.agent.id
      )
    )

    old_expiry = ctx.certificate.valid_until

    Repo.update!(
      Ecto.Changeset.change(ctx.certificate,
        valid_until: DateTime.add(DateTime.utc_now() |> DateTime.truncate(:second), -1, :second)
      )
    )

    assert {:error, _} = RuntimeAuthorization.authorize_static_read(ctx.principal, ctx.path)

    Repo.update!(
      Ecto.Changeset.change(Repo.get!(SecretHub.Shared.Schemas.Certificate, ctx.certificate.id),
        valid_until: old_expiry
      )
    )

    Repo.delete_all(
      from(ac in SecretHub.Shared.Schemas.AppCertificate,
        where: ac.certificate_id == ^ctx.certificate.id
      )
    )

    assert {:error, _} = RuntimeAuthorization.authorize_static_read(ctx.principal, ctx.path)
  end

  test "malformed deny conditions cannot be bypassed by a separate allow", ctx do
    {:ok, policy} =
      Policies.create_policy(%{
        name: "malformed-deny",
        deny_policy: true,
        entity_bindings: ["application:" <> ctx.app.id],
        policy_document: %{
          "version" => "1.0",
          "allowed_secrets" => ["**"],
          "allowed_operations" => ["read"]
        }
      })

    # Simulate an older database writer whose condition shape escaped validation.
    Repo.update!(
      Ecto.Changeset.change(policy,
        policy_document: Map.put(policy.policy_document, "conditions", %{"unknown" => true})
      )
    )

    assert {:error, :permission_denied} =
             RuntimeAuthorization.authorize_static_read(ctx.principal, ctx.path)
  end

  test "legacy Agent public-ID lookup still finds newly typed expand bindings", ctx do
    assert {:ok, _} = Policies.evaluate_access(ctx.agent.agent_id, ctx.path, "read")
  end

  for mutation <- [:app, :agent, :policy, :certificate] do
    @tag mutation: mutation
    test "#{mutation} writer committed first is observed by the blocked reader", ctx do
      parent = self()

      writer =
        db_task(:writer, fn ->
          AuthorizationVersions.lock_global()
          send(parent, :writer_locked)

          receive do
            :commit_writer -> mutate(ctx)
          after
            5_000 -> flunk("writer release missing")
          end
        end)

      assert_receive {:backend, :writer, _}, 2_000
      assert_receive :writer_locked, 2_000

      reader =
        db_task(:reader, fn ->
          RuntimeAuthorization.authorize_static_read(ctx.principal, ctx.path)
        end)

      assert_receive {:backend, :reader, reader_pid}, 2_000
      await_lock(reader_pid)
      send(writer.pid, :commit_writer)
      assert {:ok, _} = Task.await(writer, 10_000)
      assert {:ok, {:error, _}} = Task.await(reader, 10_000)
    end

    @tag mutation: mutation
    test "#{mutation} writer waits for an already-authorized read to commit", ctx do
      Repo.checkout(fn ->
        Repo.query!("SELECT pg_advisory_lock(hashtextextended($1::text, 0))", [
          "secrethub:audit-log-append:v1"
        ])

        try do
          reader =
            db_task(:reader, fn ->
              RuntimeAuthorization.authorize_static_read(ctx.principal, ctx.path)
            end)

          assert_receive {:backend, :reader, reader_pid}, 2_000
          await_lock(reader_pid)
          writer = db_task(:writer, fn -> mutate(ctx) end)
          assert_receive {:backend, :writer, writer_pid}, 2_000
          await_lock(writer_pid)

          assert Repo.query!("SELECT $1 = ANY(pg_blocking_pids($2))", [reader_pid, writer_pid]).rows ==
                   [[true]]

          Repo.query!("SELECT pg_advisory_unlock(hashtextextended($1::text, 0))", [
            "secrethub:audit-log-append:v1"
          ])

          assert {:ok, {:ok, %{value: %{"value" => "private-runtime-value"}}}} =
                   Task.await(reader, 10_000)

          assert {:ok, _} = Task.await(writer, 10_000)
          assert {:error, _} = RuntimeAuthorization.authorize_static_read(ctx.principal, ctx.path)
        after
          Repo.query!("SELECT pg_advisory_unlock_all()")
        end
      end)
    end
  end

  defp mutate(%{mutation: :app} = ctx), do: Apps.suspend_app(ctx.app.id)

  defp mutate(%{mutation: :agent} = ctx) do
    # Direct SQL also takes the global epoch before its row lock via the trigger.
    Repo.query!("UPDATE agents SET status = 'suspended' WHERE id = $1", [
      Ecto.UUID.dump!(ctx.agent.id)
    ])
  end

  defp mutate(%{mutation: :policy} = ctx) do
    policy =
      Repo.get_by!(SecretHub.Shared.Schemas.Policy, name: "runtime-application:" <> ctx.app.id)

    Policies.delete_policy(policy.id)
  end

  defp mutate(%{mutation: :certificate} = ctx),
    do: AppCertificates.revoke(ctx.app.id, ctx.certificate.id, "operator_revoked")

  defp db_task(label, operation) do
    parent = self()

    task =
      Task.async(fn ->
        Repo.put_dynamic_repo(:runtime_authorization_fixture)

        Repo.transaction(fn ->
          Repo.query!("SET LOCAL statement_timeout = '8s'")
          [[pid]] = Repo.query!("SELECT pg_backend_pid()").rows
          send(parent, {:backend, label, pid})
          operation.()
        end)
      end)

    on_exit(fn -> if Process.alive?(task.pid), do: Process.exit(task.pid, :kill) end)
    task
  end

  defp await_lock(pid, attempts \\ 200)
  defp await_lock(_, 0), do: flunk("independent database operation never blocked")

  defp await_lock(pid, attempts) do
    if Repo.query!("SELECT wait_event_type = 'Lock' FROM pg_stat_activity WHERE pid = $1", [pid]).rows ==
         [[true]],
       do: :ok,
       else:
         (
           Process.sleep(10)
           await_lock(pid, attempts - 1)
         )
  end

  defp await_state(expected, attempts \\ 100)
  defp await_state(_, 0), do: flunk("Vault did not reach expected state")

  defp await_state(expected, attempts) do
    if SealState.status().state == expected,
      do: :ok,
      else:
        (
          Process.sleep(10)
          await_state(expected, attempts - 1)
        )
  end

  defp await_empty(attempts \\ 100)
  defp await_empty(0), do: flunk("Vault did not load")

  defp await_empty(attempts) do
    if SealState.status().state == :not_initialized,
      do: :ok,
      else:
        (
          Process.sleep(10)
          await_empty(attempts - 1)
        )
  end
end
