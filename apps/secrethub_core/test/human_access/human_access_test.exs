Code.require_file("postgres_fixture.exs", __DIR__)

defmodule SecretHub.Core.HumanAccess.TestIdentity do
  def verify(token) when is_binary(token) do
    case String.split(token, ":") do
      [subject, session, device] ->
        {:ok,
         %{
           subject_id: subject,
           session_id: session,
           device_id: device,
           groups: [],
           auth_strength: :password
         }}

      [subject, session, device, group] ->
        {:ok,
         %{
           subject_id: subject,
           session_id: session,
           device_id: device,
           groups: [group],
           auth_strength: :password
         }}

      _ ->
        {:error, :unauthenticated}
    end
  end

  def verify(_), do: {:error, :unauthenticated}
end

defmodule SecretHub.Core.HumanAccess.FailingIssuedAudit do
  def record_human_event("human.dynamic_secret.issued", _, _, _), do: {:error, :audit_unavailable}
  defdelegate record_human_event(event, actor, metadata, id), to: SecretHub.Access
end

defmodule SecretHub.Core.HumanAccess.RevokingAuditBoundary do
  defdelegate read_lease(token, id), to: SecretHub.Access

  def record_human_event(event, actor, metadata, id) do
    result = SecretHub.Access.record_human_event(event, actor, metadata, id)
    Application.fetch_env!(:secrethub_core, :human_reveal_revoker).()
    result
  end
end

defmodule SecretHub.Core.HumanAccessTest do
  use SecretHub.Core.DataCase, async: false
  alias Ecto.Adapters.SQL.Sandbox
  alias SecretHub.Core.HumanAccess
  alias SecretHub.Core.HumanAccess.{PostgresFixture, PostgreSQLBackend}
  alias SecretHub.Human.Accounts, as: HumanAccounts
  alias SecretHub.Human.DynamicSecrets, as: HumanDynamicSecrets
  alias SecretHub.Human.Organizations, as: HumanOrganizations
  alias SecretHub.Human.Repo, as: HumanRepo
  alias SecretHub.Human.RevealStore, as: HumanRevealStore
  alias SecretHub.HumanWeb.Bitwarden.Token, as: HumanToken

  setup_all do
    fixture = PostgresFixture.start()
    on_exit(fn -> PostgresFixture.stop(fixture) end)
    %{fixture: fixture}
  end

  setup %{fixture: fixture} do
    subject = Ecto.UUID.generate()
    session = Ecto.UUID.generate()
    device = Ecto.UUID.generate()
    token = Enum.join([subject, session, device], ":")

    mounts = %{
      "postgres-test" => %{
        engine: PostgreSQLBackend,
        connection: fixture.connection,
        roles: %{"reader" => %{schema: "public", privileges: [:select]}}
      }
    }

    opts = [
      feature_enabled: true,
      identity_adapter: SecretHub.Core.HumanAccess.TestIdentity,
      mounts: mounts
    ]

    %{
      subject: subject,
      session: session,
      device: device,
      token: token,
      opts: opts,
      mounts: mounts
    }
  end

  defp grant(ctx, overrides \\ %{}) do
    attrs =
      Map.merge(
        %{
          subject_id: ctx.subject,
          mount_id: "postgres-test",
          role_id: "reader",
          allowed_operations: ["issue", "read", "renew", "revoke", "request_approval"],
          max_ttl: 120,
          require_device: true
        },
        overrides
      )

    assert {:ok, grant} = HumanAccess.provision_grant(attrs)
    grant
  end

  defp request(overrides \\ %{}),
    do:
      Map.merge(
        %{
          mount_id: "postgres-test",
          role_id: "reader",
          requested_ttl: 60,
          request_id: Ecto.UUID.generate()
        },
        overrides
      )

  test "feature defaults disabled and maps cannot act as authenticated principals", ctx do
    grant(ctx)
    assert {:error, :feature_disabled} = HumanAccess.list_capabilities(ctx.token)

    assert {:error, :unauthenticated} =
             HumanAccess.list_capabilities(%{subject_id: ctx.subject}, ctx.opts)

    assert {:error, :unauthenticated} =
             HumanAccess.list_capabilities(ctx.token, Keyword.delete(ctx.opts, :identity_adapter))
  end

  test "capability DTO exposes only granted roles and strict TTL requirements", ctx do
    grant(ctx)

    assert {:ok, [%{mount_id: "postgres-test", role_id: "reader", max_ttl: 120} = capability]} =
             HumanAccess.list_capabilities(ctx.token, ctx.opts)

    refute Map.has_key?(capability, :connection)
    refute inspect(capability) =~ ctx.fixture.connection[:password]

    assert {:error, :unauthorized} =
             HumanAccess.authorize(ctx.token, request(%{requested_ttl: 121}), ctx.opts)

    assert {:error, :unauthorized} =
             HumanAccess.authorize(ctx.token, request(%{mount_id: "unknown"}), ctx.opts)

    assert {:error, :invalid_input} =
             HumanAccess.authorize(ctx.token, request(%{requested_ttl: -1}), ctx.opts)
  end

  test "policy-denied authorization and issuance produce sanitized durable evidence", ctx do
    before = SecretHub.Access.human_metrics()
    denied = request()
    assert {:error, :unauthorized} = HumanAccess.authorize(ctx.token, denied, ctx.opts)
    assert {:error, :unauthorized} = HumanAccess.issue_dynamic_secret(ctx.token, denied, ctx.opts)

    events =
      Repo.all(
        from(a in SecretHub.Shared.Schemas.AuditLog,
          where: a.actor_id == ^ctx.subject and a.event_type == "human.dynamic_secret.denied"
        )
      )

    assert length(events) == 2
    after_counts = SecretHub.Access.human_metrics()
    assert after_counts.human_dynamic_requests_total == before.human_dynamic_requests_total + 1

    assert after_counts.human_dynamic_requests_denied_total ==
             before.human_dynamic_requests_denied_total + 2

    assert Enum.all?(
             events,
             &(&1.event_data["reason"] == "unauthorized" and
                 &1.event_data["request_id"] == denied.request_id)
           )

    refute inspect(events) =~ ctx.token
    refute inspect(events) =~ ctx.fixture.connection[:password]
  end

  test "actual issuance login renewal and revocation match PostgreSQL backend state", ctx do
    grant(ctx)

    assert {:ok, %{lease: lease, credentials: credentials}} =
             HumanAccess.issue_dynamic_secret(ctx.token, request(), ctx.opts)

    on_exit(fn -> PostgreSQLBackend.revoke(ctx.mounts["postgres-test"], lease.username) end)
    assert lease.status == "active"

    login =
      Keyword.merge(ctx.fixture.connection,
        username: credentials.username,
        password: credentials.password
      )

    assert {:ok, connection} = Postgrex.start_link(login)
    assert {:ok, %{rows: [[username]]}} = Postgrex.query(connection, "SELECT current_user", [])
    assert username == lease.username
    GenServer.stop(connection)

    logs =
      ExUnit.CaptureLog.capture_log(fn ->
        assert {:error, _} =
                 PostgresFixture.login(Keyword.put(login, :password, "definitely-wrong"))
      end)

    assert logs =~ "password authentication failed"

    assert {:ok, renewed} =
             HumanAccess.renew_lease(
               ctx.token,
               %{lease_id: lease.id, requested_ttl: 120},
               ctx.opts
             )

    assert DateTime.compare(renewed.expires_at, lease.expires_at) == :gt

    assert {:ok, %{rows: [[until]]}} =
             PostgresFixture.query(
               ctx.fixture,
               "SELECT rolvaliduntil FROM pg_roles WHERE rolname=$1",
               [lease.username]
             )

    assert abs(DateTime.diff(until, renewed.expires_at)) <= 1
    assert :ok = HumanAccess.revoke_lease(ctx.token, lease.id, ctx.opts)

    assert {:ok, %{rows: [[false]]}} =
             PostgresFixture.query(
               ctx.fixture,
               "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)",
               [lease.username]
             )

    assert {:ok, %{status: "revoked"}} = HumanAccess.read_lease(ctx.token, lease.id, ctx.opts)
  end

  test "lease listing projects elapsed active leases as expired before cleanup", ctx do
    grant(ctx)

    assert {:ok, %{lease: lease}} =
             HumanAccess.issue_dynamic_secret(ctx.token, request(), ctx.opts)

    on_exit(fn -> PostgreSQLBackend.revoke(ctx.mounts["postgres-test"], lease.username) end)

    Repo.get!(SecretHub.Core.HumanAccess.Lease, lease.id)
    |> Ecto.Changeset.change(expires_at: DateTime.add(DateTime.utc_now(), -1, :second))
    |> Repo.update!()

    assert {:ok, [%{id: id, status: "expired"}]} = HumanAccess.list_leases(ctx.token, ctx.opts)
    assert id == lease.id
    assert Repo.get!(SecretHub.Core.HumanAccess.Lease, lease.id).status == "active"
    assert {:error, :lease_expired} = HumanAccess.read_lease(ctx.token, lease.id, ctx.opts)
  end

  test "request idempotency never remints credentials and metadata never contains passwords",
       ctx do
    grant(ctx)
    request = request()
    assert {:ok, issued} = HumanAccess.issue_dynamic_secret(ctx.token, request, ctx.opts)

    on_exit(fn ->
      PostgreSQLBackend.revoke(ctx.mounts["postgres-test"], issued.lease.username)
    end)

    assert {:error, :already_issued} =
             HumanAccess.issue_dynamic_secret(ctx.token, request, ctx.opts)

    assert {:ok, metadata} = HumanAccess.read_lease(ctx.token, issued.lease.id, ctx.opts)
    refute inspect(metadata) =~ issued.credentials.password
    assert {:ok, [^metadata]} = HumanAccess.list_leases(ctx.token, ctx.opts)
    db_row = Repo.get!(SecretHub.Core.HumanAccess.Lease, metadata.id)
    refute Map.has_key?(db_row, :credentials)
    refute Map.has_key?(db_row, :password)
  end

  test "session ownership is enforced and revoked grants deny reveal and renewal but allow cleanup",
       ctx do
    configured = grant(ctx)
    assert {:ok, issued} = HumanAccess.issue_dynamic_secret(ctx.token, request(), ctx.opts)

    on_exit(fn ->
      PostgreSQLBackend.revoke(ctx.mounts["postgres-test"], issued.lease.username)
    end)

    wrong_session = Enum.join([ctx.subject, Ecto.UUID.generate(), ctx.device], ":")
    assert {:error, :not_found} = HumanAccess.read_lease(wrong_session, issued.lease.id, ctx.opts)
    assert :ok = HumanAccess.revoke_grant(configured.id)
    assert {:error, :unauthorized} = HumanAccess.read_lease(ctx.token, issued.lease.id, ctx.opts)

    assert {:error, :unauthorized} =
             HumanAccess.renew_lease(
               ctx.token,
               %{lease_id: issued.lease.id, requested_ttl: 60},
               ctx.opts
             )

    assert :ok = HumanAccess.revoke_lease(ctx.token, issued.lease.id, ctx.opts)
  end

  test "approval is explicitly approver-bound, request-bound, one-use and revision-sensitive",
       ctx do
    approver_subject = Ecto.UUID.generate()
    configured = grant(ctx, %{require_approval: true, approver_subject_ids: [approver_subject]})
    desired = request()

    assert {:error, :approval_required} =
             HumanAccess.issue_dynamic_secret(ctx.token, desired, ctx.opts)

    assert {:ok, approval} = HumanAccess.request_approval(ctx.token, desired, ctx.opts)
    assert {:error, :unauthorized} = HumanAccess.approve_request(ctx.token, approval.id, ctx.opts)

    approver_token =
      Enum.join([approver_subject, Ecto.UUID.generate(), Ecto.UUID.generate()], ":")

    assert {:ok, %{status: "approved"}} =
             HumanAccess.approve_request(approver_token, approval.id, ctx.opts)

    assert {:error, :approval_invalid} =
             HumanAccess.issue_dynamic_secret(
               ctx.token,
               Map.merge(desired, %{requested_ttl: 61, approval_id: approval.id}),
               ctx.opts
             )

    assert {:ok, issued} =
             HumanAccess.issue_dynamic_secret(
               ctx.token,
               Map.put(desired, :approval_id, approval.id),
               ctx.opts
             )

    on_exit(fn ->
      PostgreSQLBackend.revoke(ctx.mounts["postgres-test"], issued.lease.username)
    end)

    assert {:error, :approval_invalid} =
             HumanAccess.issue_dynamic_secret(
               ctx.token,
               request(%{approval_id: approval.id}),
               ctx.opts
             )

    assert {:ok, stale} = HumanAccess.request_approval(ctx.token, request(), ctx.opts)
    assert {:ok, _} = HumanAccess.approve_request(approver_token, stale.id, ctx.opts)
    assert {:ok, _} = HumanAccess.update_grant(configured.id, %{max_ttl: 100})

    stale_request = %{
      mount_id: stale.mount_id,
      role_id: stale.role_id,
      requested_ttl: stale.requested_ttl,
      request_id: stale.request_id,
      approval_id: stale.id
    }

    assert {:error, :approval_invalid} =
             HumanAccess.issue_dynamic_secret(ctx.token, stale_request, ctx.opts)
  end

  test "denied and expired approvals cannot issue credentials; MFA grants fail closed", ctx do
    approver = Ecto.UUID.generate()
    configured = grant(ctx, %{require_approval: true, approver_subject_ids: [approver]})
    desired = request()
    assert {:ok, approval} = HumanAccess.request_approval(ctx.token, desired, ctx.opts)
    approver_token = Enum.join([approver, Ecto.UUID.generate(), Ecto.UUID.generate()], ":")

    assert {:ok, %{status: "denied"}} =
             HumanAccess.deny_request(approver_token, approval.id, ctx.opts)

    assert {:error, :approval_invalid} =
             HumanAccess.issue_dynamic_secret(
               ctx.token,
               Map.put(desired, :approval_id, approval.id),
               ctx.opts
             )

    assert {:ok, _} = HumanAccess.update_grant(configured.id, %{require_mfa: true})
    assert {:error, :unauthorized} = HumanAccess.authorize(ctx.token, request(), ctx.opts)
  end

  test "unsupported engines and SQL-bearing grant inputs are rejected", ctx do
    assert {:error, :invalid_input} =
             HumanAccess.provision_grant(%{
               subject_id: ctx.subject,
               mount_id: "bad';DROP",
               role_id: "reader",
               max_ttl: 60,
               allowed_operations: ["issue"]
             })

    assert {:error, :unsupported_engine} =
             HumanAccess.configure_mounts(%{
               "bad" => %{engine: SecretHub.Core.Engines.Dynamic.Redis}
             })
  end

  test "expired approvals reject issuance even after an authorized approver decision", ctx do
    approver = Ecto.UUID.generate()
    grant(ctx, %{require_approval: true, approver_subject_ids: [approver]})
    desired = request()
    assert {:ok, approval} = HumanAccess.request_approval(ctx.token, desired, ctx.opts)
    approver_token = Enum.join([approver, Ecto.UUID.generate(), Ecto.UUID.generate()], ":")
    assert {:ok, _} = HumanAccess.approve_request(approver_token, approval.id, ctx.opts)

    Repo.update_all(from(a in SecretHub.Core.HumanAccess.Approval, where: a.id == ^approval.id),
      set: [expires_at: ~U[2000-01-01 00:00:00.000000Z]]
    )

    assert {:error, :approval_invalid} =
             HumanAccess.issue_dynamic_secret(
               ctx.token,
               Map.put(desired, :approval_id, approval.id),
               ctx.opts
             )
  end

  test "backend revocation failures remain pending and trusted cleanup retries the durable handle",
       ctx do
    grant(ctx)
    assert {:ok, issued} = HumanAccess.issue_dynamic_secret(ctx.token, request(), ctx.opts)

    on_exit(fn ->
      PostgreSQLBackend.revoke(ctx.mounts["postgres-test"], issued.lease.username)
    end)

    mount = ctx.mounts["postgres-test"]

    broken = %{
      mount
      | connection:
          Keyword.put(mount.connection, :socket_dir, Path.join(ctx.fixture.directory, "missing"))
    }

    opts = Keyword.put(ctx.opts, :mounts, %{"postgres-test" => broken})

    logs =
      ExUnit.CaptureLog.capture_log(fn ->
        assert {:error, :backend_unavailable} =
                 HumanAccess.revoke_lease(ctx.token, issued.lease.id, opts)
      end)

    refute logs =~ issued.credentials.password

    assert {:ok, %{status: "revoke_pending"}} =
             HumanAccess.read_lease(ctx.token, issued.lease.id, ctx.opts)

    assert {:ok, outcomes} = HumanAccess.cleanup(ctx.opts)
    assert {issued.lease.id, :ok} in outcomes

    assert {:ok, %{status: "revoked"}} =
             HumanAccess.read_lease(ctx.token, issued.lease.id, ctx.opts)

    assert {:ok, %{rows: [[false]]}} =
             PostgresFixture.query(
               ctx.fixture,
               "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)",
               [issued.lease.username]
             )
  end

  test "failed final audit compensates the actual backend role and retains a failed idempotency record",
       ctx do
    grant(ctx)
    desired = request()
    opts = Keyword.put(ctx.opts, :audit_adapter, SecretHub.Core.HumanAccess.FailingIssuedAudit)

    assert {:error, :audit_unavailable} =
             HumanAccess.issue_dynamic_secret(ctx.token, desired, opts)

    persisted =
      Repo.get_by!(SecretHub.Core.HumanAccess.Lease,
        subject_id: ctx.subject,
        request_id: desired.request_id
      )

    assert persisted.status == "failed"

    assert {:ok, %{rows: [[false]]}} =
             PostgresFixture.query(
               ctx.fixture,
               "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)",
               [persisted.username]
             )

    assert {:error, :issuance_failed} =
             HumanAccess.issue_dynamic_secret(ctx.token, desired, ctx.opts)
  end

  test "concurrent approved issuance permits one credential result across independent metadata connections",
       ctx do
    {:ok, dynamic_repo} =
      Repo.start_link(name: nil, pool: DBConnection.ConnectionPool, pool_size: 4)

    Process.unlink(dynamic_repo)
    previous = Repo.get_dynamic_repo()
    Repo.put_dynamic_repo(dynamic_repo)

    on_exit(fn ->
      Repo.put_dynamic_repo(dynamic_repo)

      for lease <-
            Repo.all(
              from(l in SecretHub.Core.HumanAccess.Lease, where: l.subject_id == ^ctx.subject)
            ) do
        PostgreSQLBackend.revoke(ctx.mounts["postgres-test"], lease.username)
      end

      Repo.delete_all(
        from(l in SecretHub.Core.HumanAccess.Lease, where: l.subject_id == ^ctx.subject)
      )

      Repo.delete_all(
        from(a in SecretHub.Core.HumanAccess.Approval, where: a.subject_id == ^ctx.subject)
      )

      Repo.delete_all(
        from(g in SecretHub.Core.HumanAccess.Grant, where: g.subject_id == ^ctx.subject)
      )

      GenServer.stop(dynamic_repo)
    end)

    approver = Ecto.UUID.generate()
    grant(ctx, %{require_approval: true, approver_subject_ids: [approver]})
    desired = request()
    {:ok, approval} = HumanAccess.request_approval(ctx.token, desired, ctx.opts)
    approver_token = Enum.join([approver, Ecto.UUID.generate(), Ecto.UUID.generate()], ":")
    {:ok, _} = HumanAccess.approve_request(approver_token, approval.id, ctx.opts)

    tasks =
      for _ <- 1..2 do
        Task.async(fn ->
          Repo.put_dynamic_repo(dynamic_repo)

          HumanAccess.issue_dynamic_secret(
            ctx.token,
            Map.put(desired, :approval_id, approval.id),
            ctx.opts
          )
        end)
      end

    results = Enum.map(tasks, &Task.await(&1, 15_000))
    assert [{:ok, issued}] = Enum.filter(results, &match?({:ok, _}, &1))
    assert [{:error, reason}] = Enum.filter(results, &match?({:error, _}, &1))
    assert reason in [:already_issued, :issuance_pending]
    persisted = Repo.get!(SecretHub.Core.HumanAccess.Lease, issued.lease.id)
    handle = persisted |> Map.take([:id, :username]) |> Jason.encode!() |> Jason.decode!()
    assert handle["username"] == issued.credentials.username
    refute inspect(handle) =~ issued.credentials.password

    assert {:ok, %{rows: [[1]]}} =
             PostgresFixture.query(
               ctx.fixture,
               "SELECT count(*)::integer FROM pg_roles WHERE rolname=$1",
               [handle["username"]]
             )

    assert :ok = HumanAccess.revoke_grant(persisted.grant_id)
    # Cleanup starts with a fresh DB query, with no credentials or issuance process state.
    assert {:ok, outcomes} = HumanAccess.cleanup(ctx.opts)
    id = handle["id"]
    assert {id, :ok} in outcomes
    assert Repo.get!(SecretHub.Core.HumanAccess.Lease, id).status == "revoked"
    Repo.put_dynamic_repo(previous)
  end

  test "server-only reveal abandonment persists pending revocation without requiring a live session",
       ctx do
    grant(ctx)
    assert {:ok, issued} = HumanAccess.issue_dynamic_secret(ctx.token, request(), ctx.opts)
    assert :ok = HumanAccess.abandon_lease(issued.lease.id)
    assert Repo.get!(SecretHub.Core.HumanAccess.Lease, issued.lease.id).status == "revoke_pending"
    assert {:ok, outcomes} = HumanAccess.cleanup(ctx.opts)
    assert {issued.lease.id, :ok} in outcomes
  end

  test "organization grants depend on current verified membership and removal queues only matching leases",
       ctx do
    organization_id = Ecto.UUID.generate()

    assert {:ok, _} =
             HumanAccess.provision_grant(%{
               organization_id: organization_id,
               mount_id: "postgres-test",
               role_id: "reader",
               allowed_operations: ["issue", "read", "renew", "revoke"],
               max_ttl: 120
             })

    assert {:error, :unauthorized} = HumanAccess.authorize(ctx.token, request(), ctx.opts)
    member_token = ctx.token <> ":" <> organization_id
    assert {:ok, issued} = HumanAccess.issue_dynamic_secret(member_token, request(), ctx.opts)
    assert issued.lease.organization_id == organization_id
    assert {:ok, _} = HumanAccess.read_lease(member_token, issued.lease.id, ctx.opts)
    grant(ctx)
    assert {:error, :unauthorized} = HumanAccess.read_lease(ctx.token, issued.lease.id, ctx.opts)
    assert {:ok, []} = HumanAccess.list_leases(ctx.token, ctx.opts)
    assert :ok = HumanAccess.revoke_organization_membership(organization_id, ctx.subject)
    assert Repo.get!(SecretHub.Core.HumanAccess.Lease, issued.lease.id).status == "revoke_pending"
    assert {:ok, outcomes} = HumanAccess.cleanup(ctx.opts)
    assert {issued.lease.id, :ok} in outcomes
  end

  defp human_bridge(ctx) do
    {:ok, _} = Application.ensure_all_started(:secrethub_human)
    owner = Sandbox.start_owner!(HumanRepo, shared: true)

    on_exit(fn ->
      Sandbox.stop_owner(owner)
      Sandbox.mode(HumanRepo, :auto)
    end)

    previous =
      Map.new([:human_dynamic_enabled, :human_identity_adapter, :human_mounts], fn key ->
        {key, Application.fetch_env(:secrethub_core, key)}
      end)

    Application.put_env(:secrethub_core, :human_dynamic_enabled, true)
    Application.put_env(:secrethub_core, :human_identity_adapter, SecretHub.Human.CoreIdentity)
    Application.put_env(:secrethub_core, :human_mounts, ctx.mounts)

    on_exit(fn ->
      Enum.each(previous, fn
        {key, {:ok, value}} -> Application.put_env(:secrethub_core, key, value)
        {key, :error} -> Application.delete_env(:secrethub_core, key)
      end)
    end)

    store = start_supervised!({HumanRevealStore, name: nil}, id: make_ref())
    %{opts: [reveal_store: store]}
  end

  defp human_session do
    encrypted =
      "2." <> Enum.map_join([16, 16, 32], "|", &Base.encode64(:crypto.strong_rand_bytes(&1)))

    attrs = %{
      email: "bridge-#{System.unique_integer([:positive])}@example.test",
      password_hash: Base.encode64(:crypto.strong_rand_bytes(32)),
      encrypted_key: encrypted
    }

    {:ok, _} = HumanAccounts.provision(attrs, server_iterations: 1000)
    limiter = start_supervised!({SecretHub.Human.RateLimiter, name: nil}, id: make_ref())

    {:ok, session} =
      HumanAccounts.authenticate(
        attrs.email,
        attrs.password_hash,
        %{identifier: "integration"},
        rate_limiter: limiter
      )

    %{
      actor: session.actor,
      token: HumanToken.issue(session),
      encrypted_key: encrypted
    }
  end

  defp human_request(session, bridge) do
    assert {:ok, reference} =
             HumanDynamicSecrets.create_reference(
               session.token,
               %{mount_id: "postgres-test", role_id: "reader", requested_ttl: 60},
               bridge.opts
             )

    HumanDynamicSecrets.request(
      session.token,
      reference.id,
      %{request_id: Ecto.UUID.generate()},
      bridge.opts
    )
  end

  @tag :human_bridge
  test "real Human session crosses public Core boundary and reveals PostgreSQL credentials once without persistence",
       ctx do
    bridge = human_bridge(ctx)
    session = human_session()
    grant(%{ctx | subject: session.actor.user_id})
    assert {:ok, %{lease: lease, reveal_token: reveal}} = human_request(session, bridge)
    on_exit(fn -> PostgreSQLBackend.revoke(ctx.mounts["postgres-test"], lease.username) end)

    assert {:ok, %{lease_id: id, credentials: credentials}} =
             HumanDynamicSecrets.reveal(session.token, reveal, bridge.opts)

    assert id == lease.id
    assert credentials.port == 6543

    login =
      Keyword.merge(ctx.fixture.connection,
        username: credentials.username,
        password: credentials.password
      )

    assert {:ok, connection} = Postgrex.start_link(login)
    assert {:ok, %{rows: [[username]]}} = Postgrex.query(connection, "SELECT current_user", [])
    assert username == lease.username
    GenServer.stop(connection)

    assert {:error, :invalid_reveal} =
             HumanDynamicSecrets.reveal(session.token, reveal, bridge.opts)

    assert {:ok, [human_metadata]} = HumanDynamicSecrets.stored_leases(session.actor)
    core_metadata = Repo.get!(SecretHub.Core.HumanAccess.Lease, lease.id)
    persisted_human = HumanRepo.get!(HumanDynamicSecrets.Lease, lease.id)

    for metadata <- [human_metadata, core_metadata, persisted_human] do
      refute Map.has_key?(metadata, :credentials)
      refute Map.has_key?(metadata, :password)
      refute inspect(metadata) =~ credentials.password
    end

    assert :ok = SecretHub.Access.revoke_lease(session.token, lease.id)

    assert {:ok, %{rows: [[false]]}} =
             PostgresFixture.query(
               ctx.fixture,
               "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)",
               [lease.username]
             )
  end

  @tag :human_bridge
  test "revoked real Human session denies outstanding reveal and Core renewal", ctx do
    bridge = human_bridge(ctx)
    session = human_session()
    grant(%{ctx | subject: session.actor.user_id})
    assert {:ok, %{lease: lease, reveal_token: reveal}} = human_request(session, bridge)
    on_exit(fn -> PostgreSQLBackend.revoke(ctx.mounts["postgres-test"], lease.username) end)
    assert :ok = HumanAccounts.revoke_session(session.actor, session.actor.session_id)

    assert {:error, :unauthenticated} =
             HumanDynamicSecrets.reveal(session.token, reveal, bridge.opts)

    assert {:error, :unauthenticated} =
             HumanDynamicSecrets.renew(
               session.token,
               %{lease_id: lease.id, requested_ttl: 120},
               bridge.opts
             )

    assert :ok = SecretHub.Access.abandon_human_lease(lease.id)
    assert {:ok, outcomes} = SecretHub.Access.process_revocations()
    assert {lease.id, :ok} in outcomes
  end

  @tag :human_bridge
  test "removing real organization membership invalidates outstanding reveal and renewal and revokes backend login",
       ctx do
    bridge = human_bridge(ctx)
    owner = human_session()
    member = human_session()

    {:ok, organization} =
      HumanOrganizations.create(owner.actor, %{
        name: owner.encrypted_key,
        encrypted_key: owner.encrypted_key
      })

    {:ok, _} =
      HumanOrganizations.add_member(owner.actor, organization.id, %{
        user_id: member.actor.user_id,
        encrypted_key: member.encrypted_key,
        role: "member"
      })

    assert {:ok, _} =
             HumanAccess.provision_grant(%{
               organization_id: organization.id,
               mount_id: "postgres-test",
               role_id: "reader",
               allowed_operations: ["issue", "read", "renew", "revoke"],
               max_ttl: 120
             })

    {:ok, collection} =
      HumanOrganizations.create_collection(owner.actor, organization.id, %{
        name: owner.encrypted_key
      })

    {:ok, shared_reference} =
      HumanOrganizations.create_dynamic_reference(owner.actor, collection.id, %{
        mount_id: "postgres-test",
        role_id: "reader",
        requested_ttl: 60
      })

    assert {:error, :unauthorized} =
             HumanDynamicSecrets.request_shared(
               member.token,
               collection.id,
               shared_reference.id,
               %{request_id: Ecto.UUID.generate()},
               bridge.opts
             )

    {:ok, _} =
      HumanOrganizations.set_collection_permission(owner.actor, collection.id, %{
        user_id: member.actor.user_id,
        can_read: true,
        can_write: false
      })

    assert {:ok, %{lease: lease, reveal_token: reveal}} =
             HumanDynamicSecrets.request_shared(
               member.token,
               collection.id,
               shared_reference.id,
               %{request_id: Ecto.UUID.generate()},
               bridge.opts
             )

    on_exit(fn -> PostgreSQLBackend.revoke(ctx.mounts["postgres-test"], lease.username) end)
    assert lease.organization_id == organization.id

    assert :ok =
             HumanOrganizations.remove_member(
               owner.actor,
               organization.id,
               member.actor.user_id
             )

    assert {:error, :invalid_reveal} =
             HumanDynamicSecrets.reveal(member.token, reveal, bridge.opts)

    assert {:error, :unauthorized} =
             HumanDynamicSecrets.renew(
               member.token,
               %{lease_id: lease.id, requested_ttl: 120},
               bridge.opts
             )

    assert Repo.get!(SecretHub.Core.HumanAccess.Lease, lease.id).status == "revoke_pending"
    assert {:ok, outcomes} = SecretHub.Access.process_revocations()
    assert {lease.id, :ok} in outcomes

    assert {:ok, %{rows: [[false]]}} =
             PostgresFixture.query(
               ctx.fixture,
               "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)",
               [lease.username]
             )
  end

  @tag :human_bridge_race
  test "session revoked during reveal audit cannot redeem stale authenticated actor", ctx do
    bridge = human_bridge(ctx)
    session = human_session()
    grant(%{ctx | subject: session.actor.user_id})
    assert {:ok, %{lease: lease, reveal_token: reveal}} = human_request(session, bridge)
    on_exit(fn -> PostgreSQLBackend.revoke(ctx.mounts["postgres-test"], lease.username) end)
    previous_revoker = Application.fetch_env(:secrethub_core, :human_reveal_revoker)

    Application.put_env(:secrethub_core, :human_reveal_revoker, fn ->
      :ok = HumanAccounts.revoke_session(session.actor, session.actor.session_id)
    end)

    on_exit(fn ->
      case previous_revoker do
        {:ok, value} -> Application.put_env(:secrethub_core, :human_reveal_revoker, value)
        :error -> Application.delete_env(:secrethub_core, :human_reveal_revoker)
      end
    end)

    opts = Keyword.put(bridge.opts, :boundary, SecretHub.Core.HumanAccess.RevokingAuditBoundary)

    assert {:error, :invalid_reveal} =
             HumanDynamicSecrets.reveal(session.token, reveal, opts)

    assert {:error, :unauthenticated} = HumanAccounts.authorize_actor(session.actor)
    assert :ok = SecretHub.Access.abandon_human_lease(lease.id)
    assert {:ok, outcomes} = SecretHub.Access.process_revocations()
    assert {lease.id, :ok} in outcomes
  end

  @tag :human_cleanup_race
  test "cleanup rechecks expiry after a concurrent renewal commits", ctx do
    {:ok, dynamic_repo} =
      Repo.start_link(name: nil, pool: DBConnection.ConnectionPool, pool_size: 4)

    Process.unlink(dynamic_repo)
    previous = Repo.get_dynamic_repo()
    Repo.put_dynamic_repo(dynamic_repo)

    on_exit(fn ->
      Repo.put_dynamic_repo(dynamic_repo)

      for lease <-
            Repo.all(
              from(l in SecretHub.Core.HumanAccess.Lease, where: l.subject_id == ^ctx.subject)
            ) do
        PostgreSQLBackend.revoke(ctx.mounts["postgres-test"], lease.username)
      end

      Repo.delete_all(
        from(l in SecretHub.Core.HumanAccess.Lease, where: l.subject_id == ^ctx.subject)
      )

      Repo.delete_all(
        from(g in SecretHub.Core.HumanAccess.Grant, where: g.subject_id == ^ctx.subject)
      )

      GenServer.stop(dynamic_repo)
    end)

    grant(ctx)
    {:ok, issued} = HumanAccess.issue_dynamic_secret(ctx.token, request(), ctx.opts)
    expires_at = DateTime.add(DateTime.utc_now(), 1)

    Repo.update_all(from(l in SecretHub.Core.HumanAccess.Lease, where: l.id == ^issued.lease.id),
      set: [expires_at: expires_at]
    )

    parent = self()
    handler_id = {__MODULE__, make_ref()}
    event = Repo.config()[:telemetry_prefix] ++ [:query]

    :ok =
      :telemetry.attach(
        handler_id,
        event,
        fn _, _, metadata, test_pid ->
          phase = Process.get(:human_cleanup_race_phase)
          query = metadata.query

          if metadata.source == "core_human_leases" and
               ((phase == :renew and String.starts_with?(query, "UPDATE")) or
                  (phase == :cleanup and String.starts_with?(query, "SELECT"))) do
            Process.delete(:human_cleanup_race_phase)
            send(test_pid, {phase, self()})

            receive do
              :resume -> :ok
            after
              10_000 -> raise "cleanup race checkpoint timed out"
            end
          end
        end,
        parent
      )

    on_exit(fn -> :telemetry.detach(handler_id) end)

    renewal =
      Task.async(fn ->
        Repo.put_dynamic_repo(dynamic_repo)
        Process.put(:human_cleanup_race_phase, :renew)

        HumanAccess.renew_lease(
          ctx.token,
          %{lease_id: issued.lease.id, requested_ttl: 120},
          ctx.opts
        )
      end)

    on_exit(fn -> if Process.alive?(renewal.pid), do: Process.exit(renewal.pid, :kill) end)
    assert_receive {:renew, renewal_pid}, 5000
    Process.sleep(max(DateTime.diff(expires_at, DateTime.utc_now(), :millisecond) + 20, 0))

    cleanup =
      Task.async(fn ->
        Repo.put_dynamic_repo(dynamic_repo)
        Process.put(:human_cleanup_race_phase, :cleanup)
        HumanAccess.cleanup(ctx.opts)
      end)

    on_exit(fn -> if Process.alive?(cleanup.pid), do: Process.exit(cleanup.pid, :kill) end)
    assert_receive {:cleanup, cleanup_pid}, 5000
    send(renewal_pid, :resume)
    assert {:ok, renewed} = Task.await(renewal, 5000)
    send(cleanup_pid, :resume)
    assert {:ok, outcomes} = Task.await(cleanup, 5000)
    refute Enum.any?(outcomes, fn {id, _} -> id == issued.lease.id end)
    assert Repo.get!(SecretHub.Core.HumanAccess.Lease, issued.lease.id).status == "active"

    assert {:ok, %{rows: [[until]]}} =
             PostgresFixture.query(
               ctx.fixture,
               "SELECT rolvaliduntil FROM pg_roles WHERE rolname=$1",
               [issued.lease.username]
             )

    assert abs(DateTime.diff(until, renewed.expires_at)) <= 1
    assert :ok = HumanAccess.revoke_lease(ctx.token, issued.lease.id, ctx.opts)
    Repo.put_dynamic_repo(previous)
  end

  defp reservation(ctx, status) do
    configured = grant(ctx)
    id = Ecto.UUID.generate()

    Repo.insert!(%SecretHub.Core.HumanAccess.Lease{
      id: id,
      grant_id: configured.id,
      grant_revision: configured.revision,
      subject_id: ctx.subject,
      session_id: ctx.session,
      device_id: ctx.device,
      request_id: Ecto.UUID.generate(),
      mount_id: "postgres-test",
      role_id: "reader",
      username: "human_" <> String.replace(id, "-", ""),
      status: status,
      expires_at: DateTime.add(DateTime.utc_now(), -1)
    })
  end

  @tag :human_recovery
  test "cleanup gives unfinished expired issuance a grace period before revoking a late role",
       ctx do
    lease = reservation(ctx, "reserved")
    assert {:ok, outcomes} = HumanAccess.cleanup(ctx.opts)
    refute Enum.any?(outcomes, fn {id, _} -> id == lease.id end)
    assert Repo.get!(SecretHub.Core.HumanAccess.Lease, lease.id).status == "reserved"

    assert {:ok, _} =
             PostgreSQLBackend.create(
               ctx.mounts["postgres-test"],
               "reader",
               lease.username,
               DateTime.add(DateTime.utc_now(), 120)
             )

    on_exit(fn -> PostgreSQLBackend.revoke(ctx.mounts["postgres-test"], lease.username) end)

    Repo.update_all(from(l in SecretHub.Core.HumanAccess.Lease, where: l.id == ^lease.id),
      set: [inserted_at: DateTime.add(DateTime.utc_now(), -31)]
    )

    assert {:ok, outcomes} = HumanAccess.cleanup(ctx.opts)
    assert {lease.id, :ok} in outcomes
    assert Repo.get!(SecretHub.Core.HumanAccess.Lease, lease.id).status == "expired"

    assert {:ok, %{rows: [[false]]}} =
             PostgresFixture.query(
               ctx.fixture,
               "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)",
               [lease.username]
             )
  end

  @tag :human_recovery
  test "abandoned unfinished issuance stays pending until its backend deadline has safely elapsed",
       ctx do
    lease = reservation(ctx, "revoke_pending")
    assert {:ok, outcomes} = HumanAccess.cleanup(ctx.opts)
    refute Enum.any?(outcomes, fn {id, _} -> id == lease.id end)
    assert Repo.get!(SecretHub.Core.HumanAccess.Lease, lease.id).status == "revoke_pending"

    Repo.update_all(from(l in SecretHub.Core.HumanAccess.Lease, where: l.id == ^lease.id),
      set: [inserted_at: DateTime.add(DateTime.utc_now(), -31)]
    )

    assert {:ok, outcomes} = HumanAccess.cleanup(ctx.opts)
    assert {lease.id, :ok} in outcomes
    assert Repo.get!(SecretHub.Core.HumanAccess.Lease, lease.id).status == "expired"
  end

  defp await_blocked_role(fixture, username, remaining \\ 30)

  defp await_blocked_role(_, _, 0),
    do: flunk("backend role operation did not reach its database lock")

  defp await_blocked_role(fixture, username, remaining) do
    {:ok, %{rows: [[blocked]]}} =
      PostgresFixture.query(
        fixture,
        "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE query LIKE $1 AND wait_event_type='Lock')",
        ["ALTER ROLE %" <> username <> "%"]
      )

    if blocked,
      do: :ok,
      else:
        (
          Process.sleep(50)
          await_blocked_role(fixture, username, remaining - 1)
        )
  end

  defp await_finished_role(fixture, username, remaining \\ 30)

  defp await_finished_role(_, _, 0),
    do: flunk("backend role operation remained active after deadline")

  defp await_finished_role(fixture, username, remaining) do
    {:ok, %{rows: [[active]]}} =
      PostgresFixture.query(
        fixture,
        "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE query LIKE $1 AND state='active')",
        ["ALTER ROLE %" <> username <> "%"]
      )

    if active,
      do:
        (
          Process.sleep(50)
          await_finished_role(fixture, username, remaining - 1)
        ),
      else: :ok
  end

  @tag :human_recovery_deadline
  test "backend task enforces its own deadline after caller death", ctx do
    grant(ctx)
    {:ok, issued} = HumanAccess.issue_dynamic_secret(ctx.token, request(), ctx.opts)

    on_exit(fn ->
      PostgreSQLBackend.revoke(ctx.mounts["postgres-test"], issued.lease.username)
    end)

    {:ok, blocker} = Postgrex.start_link(ctx.fixture.connection)
    on_exit(fn -> if Process.alive?(blocker), do: GenServer.stop(blocker) end)
    {:ok, _} = Postgrex.query(blocker, "BEGIN", [])

    {:ok, %{rows: [[_]]}} =
      Postgrex.query(blocker, "SELECT oid FROM pg_authid WHERE rolname=$1 FOR UPDATE", [
        issued.lease.username
      ])

    children = Task.Supervisor.children(SecretHub.Core.HumanAccess.BackendSupervisor)

    caller =
      spawn(fn ->
        PostgreSQLBackend.renew(
          ctx.mounts["postgres-test"],
          issued.lease.username,
          DateTime.add(DateTime.utc_now(), 120)
        )
      end)

    on_exit(fn -> if Process.alive?(caller), do: Process.exit(caller, :kill) end)
    await_blocked_role(ctx.fixture, issued.lease.username)

    assert [backend] =
             Task.Supervisor.children(SecretHub.Core.HumanAccess.BackendSupervisor) -- children

    monitor = Process.monitor(backend)
    on_exit(fn -> if Process.alive?(backend), do: Process.exit(backend, :kill) end)
    assert :erlang.suspend_process(backend)
    Process.exit(caller, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^backend, _reason}, 11_000
    {:ok, _} = Postgrex.query(blocker, "ROLLBACK", [])
    await_finished_role(ctx.fixture, issued.lease.username)

    assert {:ok, %{rows: [[until]]}} =
             PostgresFixture.query(
               ctx.fixture,
               "SELECT rolvaliduntil FROM pg_roles WHERE rolname=$1",
               [issued.lease.username]
             )

    assert abs(DateTime.diff(until, issued.lease.expires_at)) <= 1
    assert :ok = HumanAccess.revoke_lease(ctx.token, issued.lease.id, ctx.opts)
  end
end
