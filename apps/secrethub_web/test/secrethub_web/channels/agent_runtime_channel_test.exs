defmodule SecretHub.Web.AgentRuntimeChannelTest do
  use SecretHub.Web.ChannelCase, async: false

  alias SecretHub.Agent.AccessAudit.Journal
  alias SecretHub.Agent.UDSAuth
  alias SecretHub.Core.AccessAudit
  alias SecretHub.Core.Agents
  alias SecretHub.Core.Agents.ConnectionManager
  alias SecretHub.Core.Agents.Enrollment
  alias SecretHub.Core.PKI.CA
  alias SecretHub.Core.PKI.CSR
  alias SecretHub.Core.PKI.ClientAuth
  alias SecretHub.Core.{Apps, Audit, Policies, Secrets, UpgradeGates}
  alias SecretHub.Core.PKI.AppCertificates
  alias SecretHub.Core.Repo
  alias SecretHub.Core.Vault.SealState
  alias SecretHub.Core.RuntimeDatabaseFixture
  alias SecretHub.Shared.Crypto.AgentCSRProof
  alias SecretHub.Shared.Schemas.{Agent, Certificate}
  alias SecretHub.Web.{AgentRuntimeChannel, AgentTrustedSocket}
  alias X509.Certificate.Extension

  @pending_attrs %{
    hostname: "runtime-channel-01",
    fqdn: "runtime-channel-01.internal.example",
    machine_id: "runtime-channel-machine",
    os: "linux",
    arch: "x86_64",
    agent_version: "1.2.3",
    ssh_host_key_algorithm: "rsa",
    capabilities: %{"templates" => true}
  }

  setup do
    ensure_current_audit_partition!()
    start_supervised!({ConnectionManager, name: ConnectionManager})
    :ok
  end

  test "rejects runtime joins when socket has no certificate-derived identity" do
    assert {:error, %{reason: "mtls_required"}} =
             subscribe_and_join(
               socket(AgentTrustedSocket, "agent:test", %{}),
               AgentRuntimeChannel,
               "agent:runtime"
             )
  end

  test "launch profile refuses lease renewal after verifying runtime certificate identity" do
    previous = Application.get_env(:secrethub_core, :launch_profile)
    Application.put_env(:secrethub_core, :launch_profile, :single_operator)
    on_exit(fn -> Application.put_env(:secrethub_core, :launch_profile, previous) end)

    %{cert_der: cert_der} = issue_valid_agent_certificate!()

    assert {:ok, socket} =
             connect(AgentTrustedSocket, %{}, connect_info: %{peer_data: %{ssl_cert: cert_der}})

    assert {:ok, _reply, socket} =
             subscribe_and_join(socket, AgentRuntimeChannel, "agent:runtime")

    ref = push(socket, "secret:lease_renew", %{"lease_id" => "disabled-launch-lease"})
    assert_reply(ref, :error, %{reason: "feature_unavailable"}, 2_000)
  end

  test "connects and joins trusted runtime using certificate-derived identity" do
    %{certificate: certificate, cert_der: cert_der, enrollment: enrollment} =
      issue_valid_agent_certificate!()

    assert {:ok, socket} =
             connect(AgentTrustedSocket, %{}, connect_info: %{peer_data: %{ssl_cert: cert_der}})

    assert {:ok, reply, socket} =
             subscribe_and_join(socket, AgentRuntimeChannel, "agent:runtime", %{
               "agent_id" => "client-spoof",
               "certificate_serial" => "spoofed-serial"
             })

    agent_id = enrollment.agent_id
    certificate_serial = certificate.serial_number
    certificate_fingerprint = certificate.fingerprint
    certificate_id = certificate.id

    assert %{
             status: "accepted",
             agent_id: ^agent_id,
             certificate_serial: ^certificate_serial,
             certificate_fingerprint: ^certificate_fingerprint,
             certificate_id: ^certificate_id
           } = reply

    assert socket.assigns.agent_id == agent_id
    assert socket.assigns.certificate_id == certificate_id
    assert ConnectionManager.connected?(agent_id)

    assert {:ok, connection} = ConnectionManager.get_connection(agent_id)
    assert connection.metadata.certificate_id == certificate_id
    assert connection.metadata.certificate_serial == certificate_serial
  end

  test "negotiated audit ingestion binds identity, commits before ack and deduplicates replay" do
    %{cert_der: cert_der, enrollment: enrollment} = issue_valid_agent_certificate!()

    assert {:ok, socket} =
             connect(AgentTrustedSocket, %{}, connect_info: %{peer_data: %{ssl_cert: cert_der}})

    assert {:ok, %{runtime_capabilities: ["access_audit_v1"]}, socket} =
             subscribe_and_join(socket, AgentRuntimeChannel, "agent:runtime", %{
               "runtime_capabilities" => ["access_audit_v1"]
             })

    event = audit_event()
    id = event["event_id"]
    ref = push(socket, "audit:batch", %{"events" => [event]})
    assert_reply(ref, :ok, %{accepted: [^id], duplicates: []}, 2_000)
    namespace = "agent:" <> enrollment.agent_id

    assert {:ok, [%{envelope: stored}]} =
             AccessAudit.timeline(namespace, event["request_id"])

    assert stored["agent_id"] == enrollment.agent_id

    ref = push(socket, "audit:batch", %{"events" => [event]})
    assert_reply(ref, :ok, %{accepted: [], duplicates: [^id]}, 2_000)

    for forged <- [Map.put(event, "agent_id", "other-agent"), Map.put(event, "source", "core")] do
      ref = push(socket, "audit:batch", %{"events" => [forged]})
      assert_reply(ref, :error, %{reason: "invalid_event"}, 2_000)
    end

    ref = push(socket, "audit:batch", %{"events" => [Map.put(event, "reason_code", "timeout")]})
    assert_reply(ref, :error, %{reason: "event_conflict"}, 2_000)
    leave(socket)
  end

  test "legacy peers cannot upload without negotiating the audit schema" do
    %{cert_der: cert_der} = issue_valid_agent_certificate!()

    assert {:ok, socket} =
             connect(AgentTrustedSocket, %{}, connect_info: %{peer_data: %{ssl_cert: cert_der}})

    assert {:ok, _, socket} =
             subscribe_and_join(socket, AgentRuntimeChannel, "agent:runtime", %{})

    ref = push(socket, "audit:batch", %{"events" => [audit_event()]})
    assert_reply(ref, :error, %{reason: "unsupported_schema"}, 2_000)
    leave(socket)
  end

  test "audit uploads recheck revocation on the live authenticated channel" do
    prior = Process.flag(:trap_exit, true)
    on_exit(fn -> Process.flag(:trap_exit, prior) end)
    %{cert_der: cert_der, enrollment: enrollment} = issue_valid_agent_certificate!()

    assert {:ok, socket} =
             connect(AgentTrustedSocket, %{}, connect_info: %{peer_data: %{ssl_cert: cert_der}})

    assert {:ok, _, socket} =
             subscribe_and_join(socket, AgentRuntimeChannel, "agent:runtime", %{
               "runtime_capabilities" => ["access_audit_v1"]
             })

    revoke_agent_row!(enrollment.agent_id)
    ref = push(socket, "audit:batch", %{"events" => [audit_event()]})
    assert_reply(ref, :error, %{reason: "runtime_not_authorized"}, 2_000)
  end

  defp audit_event do
    %{
      "schema_version" => 1,
      "event_id" => Ecto.UUID.generate(),
      "producer_id" => Ecto.UUID.generate(),
      "producer_sequence" => 1,
      "request_id" => Ecto.UUID.generate(),
      "source" => "agent",
      "phase" => "admitted",
      "observed_at" => DateTime.to_iso8601(DateTime.utc_now()),
      "identity_status" => "unverified",
      "attribution" => "none",
      "operation" => "read",
      "outcome" => "unknown",
      "reason_code" => "none",
      "cache_status" => "none"
    }
  end

  test "capable join reports authoritative floor and forwards floor notifications" do
    %{cert_der: cert_der, enrollment: enrollment} = issue_valid_agent_certificate!()

    assert {:ok, socket} =
             connect(AgentTrustedSocket, %{}, connect_info: %{peer_data: %{ssl_cert: cert_der}})

    assert {:ok, %{minimum_uds_auth_version: 1}, socket} =
             subscribe_and_join(socket, AgentRuntimeChannel, "agent:runtime", %{
               "runtime_capabilities" => ["uds_auth_v2", "unknown", "uds_auth_v2"],
               "agent_id" => "spoofed"
             })

    agent = Agents.get_agent(enrollment.agent_id)
    assert agent.runtime_capabilities == ["uds_auth_v2"]
    assert %DateTime{} = agent.runtime_capabilities_seen_at

    Phoenix.PubSub.broadcast(
      SecretHub.Web.PubSub,
      "authorization:uds_auth_floor",
      {:uds_auth_floor_changed, %{minimum_uds_auth_version: 2}}
    )

    assert_push("agent:uds_auth_floor", %{minimum_uds_auth_version: 2})
    leave(socket)
  end

  test "floor rejects incapable join and bare reads even before an Agent receives notification" do
    %{cert_der: cert_der, enrollment: enrollment} = issue_valid_agent_certificate!()

    Repo.update_all(SecretHub.Shared.Schemas.AuthorizationEpoch,
      set: [minimum_uds_auth_version: 2]
    )

    assert {:ok, socket} =
             connect(AgentTrustedSocket, %{}, connect_info: %{peer_data: %{ssl_cert: cert_der}})

    status = Agents.get_agent(enrollment.agent_id).status

    assert {:error, %{reason: "INCOMPATIBLE_VERSION"}} =
             subscribe_and_join(socket, AgentRuntimeChannel, "agent:runtime", %{})

    assert Agents.get_agent(enrollment.agent_id).status == status
    refute ConnectionManager.connected?(enrollment.agent_id)

    assert {:ok, %{minimum_uds_auth_version: 2}, socket} =
             subscribe_and_join(socket, AgentRuntimeChannel, "agent:runtime", %{
               "runtime_capabilities" => ["uds_auth_v2"]
             })

    ref = push(socket, "secret:read", %{"path" => "prod.db.password"})
    assert_reply(ref, :error, %{reason: "INCOMPATIBLE_VERSION"}, 2_000)
  end

  test "application read preserves exact revision and rejects app claims or independent policy denial" do
    %{socket: socket, app: app, certificate: certificate, path: path, app_policy: policy} =
      application_runtime_fixture!()

    payload = %{
      "path" => path,
      "app_id" => app.id,
      "certificate_fingerprint" => certificate.canonical_fingerprint,
      "local_auth_version" => 2
    }

    ref = push(socket, "secret:read", payload)

    assert_reply(
      ref,
      :ok,
      %{
        value: %{"value" => "app-runtime-private"},
        version: 1,
        revision: revision
      },
      2_000
    )

    ref = push(socket, "secret:read", Map.put(payload, "known_revision", revision))
    assert_reply(ref, :ok, %{not_modified: true, revision: ^revision, version: 1}, 2_000)

    for bad <- [
          Map.put(payload, "app_id", Ecto.UUID.generate()),
          Map.put(payload, "certificate_fingerprint", String.duplicate("0", 64))
        ] do
      ref = push(socket, "secret:read", bad)
      assert_reply(ref, :error, %{reason: "UNAUTHORIZED"}, 2_000)
    end

    assert {:ok, _} = Policies.delete_policy(policy.id)
    ref = push(socket, "secret:read", payload)
    assert_reply(ref, :error, %{reason: "FORBIDDEN"}, 2_000)
  end

  @tag :tmp_dir
  @tag :correlated_access_audit
  test "real UDS phases join checked Core facts and durable Reporter upload without counting replay",
       %{tmp_dir: dir} do
    alias SecretHub.Agent.AccessAudit.{Journal, Reporter}
    alias SecretHub.Agent.{Cache, CertVerifier, UDSServer}

    ctx = application_runtime_fixture!(["uds_auth_v2", "access_audit_v1"])
    start_supervised!({Journal, state_dir: dir})
    start_supervised!(Cache)
    start_supervised!(CertVerifier)
    {:ok, chain} = CA.get_ca_chain_pems(ctx.certificate.issuer_id)
    assert :ok = CertVerifier.configure_trust(Enum.join(chain, "\n"))

    path =
      Path.join(System.tmp_dir!(), "sh-audit-channel-#{System.unique_integer([:positive])}.sock")

    on_exit(fn -> File.rm(path) end)
    start_supervised!({UDSServer, socket_path: path, state_dir: dir, request_timeout: 20_000})
    assert :ok = UDSServer.configure_runtime(ctx.agent.agent_id, 2)
    start_supervised!({SecretHub.Web.AccessAuditRuntimeBridge, owner: self()})

    # A failed private-key proof is retained and uploaded without adopting the
    # application claimed by its otherwise valid certificate.
    bad_client = audit_uds_connect(path)

    challenge =
      audit_uds_exchange(bad_client, "authenticate", %{
        auth_version: 2,
        certificate: Base.encode64(ctx.certificate.certificate_pem)
      })["data"]

    bad_proof =
      audit_uds_proof(challenge, ctx.app_key)
      |> Map.put(:signature, Base.encode64("invalid-signature-canary"))

    assert audit_uds_exchange(bad_client, "authenticate_proof", bad_proof)["error"]["code"] ==
             "PROOF_FAILED"

    :gen_tcp.close(bad_client)

    assert {:ok,
            [
              _,
              %{
                "operation" => "authenticate",
                "application_id" => nil,
                "identity_status" => "unverified",
                "reason_code" => "proof_failed"
              }
            ]} = Journal.batch()

    owner = self()

    reporter =
      start_supervised!(
        {Reporter,
         interval: 60_000,
         submit: fn events ->
           send(owner, {:audit_upload_waiting, self(), events})

           receive do
             {:audit_upload_reply, reply} -> reply
           after
             10_000 -> {:error, :timeout}
           end
         end}
      )

    assert_receive {:audit_upload_waiting, ^reporter, rejected_events}, 5_000
    assert length(rejected_events) == 2
    ref = push(ctx.socket, "audit:batch", %{"events" => rejected_events})
    assert_reply(ref, :ok, rejection_ack, 5_000)
    assert {:ok, ^rejected_events} = Journal.batch()
    send(reporter, {:audit_upload_reply, {:ok, audit_wire(rejection_ack)}})
    await_audit_journal_empty!()
    assert {:ok, %{requests: 0}} = AccessAudit.summary(%{application_id: ctx.app.id})

    client = audit_uds_connect(path)
    on_exit(fn -> :gen_tcp.close(client) end)

    challenge =
      audit_uds_exchange(client, "authenticate", %{
        auth_version: 2,
        certificate: Base.encode64(ctx.certificate.certificate_pem)
      })["data"]

    assert audit_uds_exchange(
             client,
             "authenticate_proof",
             audit_uds_proof(challenge, ctx.app_key)
           )["status"] == "ok"

    caller_id = Ecto.UUID.generate()

    :ok =
      :gen_tcp.send(
        client,
        Jason.encode!(%{
          request_id: caller_id,
          action: "get_secret",
          params: %{path: ctx.path, audit_request_id: caller_id, audit_attempt_id: caller_id}
        }) <> "\n"
      )

    assert_receive {:audit_runtime_read, from, read_path, claims, revision}, 5_000
    assert read_path == ctx.path
    assert revision == nil
    refute claims.audit_request_id == caller_id
    refute claims.audit_attempt_id == caller_id

    payload =
      audit_wire(claims) |> Map.put("path", read_path) |> Map.put("known_revision", revision)

    ref = push(ctx.socket, "secret:read", payload)
    assert_reply(ref, :ok, read_reply, 5_000)
    assert read_reply.audit_event_id
    GenServer.reply(from, {:ok, audit_wire(read_reply)})
    assert {:ok, line} = :gen_tcp.recv(client, 0, 5_000)
    assert Jason.decode!(line)["data"]["value"] == "app-runtime-private"
    request_id = claims.audit_request_id
    namespace = "agent:" <> ctx.agent.agent_id

    assert {:ok, [%{incomplete: true, core_outcome: "success"}]} =
             audit_matching_requests(ctx.app.id)

    await_audit_agent_phases!(4)
    assert {:ok, agent_events} = Journal.batch()

    assert Enum.map(agent_events, & &1["phase"]) ==
             ~w(admitted attempt release_intent response_sent)

    assert Enum.all?(agent_events, &(&1["request_id"] == request_id))
    assert List.last(agent_events)["core_event_id"] == read_reply.audit_event_id
    wal = File.read!(Path.join(dir, "access-audit/observations.wal"))
    refute wal =~ "app-runtime-private"
    refute wal =~ "invalid-signature-canary"
    refute wal =~ "BEGIN CERTIFICATE"

    send(reporter, :upload)
    assert_receive {:audit_upload_waiting, ^reporter, ^agent_events}, 5_000
    ref = push(ctx.socket, "audit:batch", %{"events" => agent_events})
    assert_reply(ref, :ok, committed_ack, 5_000)

    assert Enum.sort(committed_ack.accepted) ==
             Enum.sort(Enum.map(agent_events, & &1["event_id"]))

    assert {:ok, ^agent_events} = Journal.batch()
    # Kill the actual supervised Reporter after Core commit and before its
    # acknowledgement. The restarted child must upload the exact pending batch.
    reporter_monitor = Process.monitor(reporter)
    Process.exit(reporter, :kill)
    assert_receive {:DOWN, ^reporter_monitor, :process, ^reporter, :killed}, 5_000
    assert_receive {:audit_upload_waiting, restarted_reporter, ^agent_events}, 5_000
    refute restarted_reporter == reporter
    assert {:ok, ^agent_events} = Journal.batch()
    ref = push(ctx.socket, "audit:batch", %{"events" => agent_events})
    assert_reply(ref, :ok, %{accepted: [], duplicates: duplicates} = duplicate_ack, 5_000)
    assert Enum.sort(duplicates) == Enum.sort(committed_ack.accepted)
    assert {:ok, ^agent_events} = Journal.batch()
    reporter = restarted_reporter
    send(reporter, {:audit_upload_reply, {:ok, audit_wire(duplicate_ack)}})
    await_audit_journal_empty!()

    assert {:ok, %{requests: 1, success: 1, attempts: 1, incomplete: 0, unverified: 0}} =
             AccessAudit.summary(%{application_id: ctx.app.id})

    assert {:ok,
            [
              %{
                attribution: "core_certificate",
                delivery_outcome: "success",
                core_outcome: "success",
                contradictory: false
              }
            ]} = audit_matching_requests(ctx.app.id)

    assert {:ok, timeline} = AccessAudit.timeline(namespace, request_id)
    assert length(timeline) == 6

    assert Enum.sort(Enum.map(timeline, & &1.envelope["phase"])) ==
             Enum.sort(
               ~w(admitted attempt core_decision core_access release_intent response_sent)
             )

    assert Enum.all?(timeline, &(&1.request_id == request_id))

    # The public denial remains generic while audit evidence retains Core's
    # unknown-secret classification, including after cached plaintext exists.
    assert {:ok, secret} = Secrets.get_secret_by_path(ctx.path)
    assert {:ok, _} = Secrets.delete_secret(secret.id)

    :ok =
      :gen_tcp.send(
        client,
        Jason.encode!(%{
          request_id: Ecto.UUID.generate(),
          action: "get_secret",
          params: %{path: ctx.path}
        }) <> "\n"
      )

    assert_receive {:audit_runtime_read, missing_from, missing_path, missing_claims,
                    known_revision},
                   5_000

    assert missing_path == ctx.path
    assert is_integer(known_revision)

    missing_payload =
      audit_wire(missing_claims)
      |> Map.put("path", missing_path)
      |> Map.put("known_revision", known_revision)

    ref = push(ctx.socket, "secret:read", missing_payload)

    assert_reply(
      ref,
      :error,
      %{
        reason: "FORBIDDEN",
        audit_outcome: "error",
        audit_reason_code: "not_found"
      } = missing_reply,
      5_000
    )

    GenServer.reply(missing_from, {:error, audit_wire(missing_reply)})
    assert {:ok, missing_line} = :gen_tcp.recv(client, 0, 5_000)
    assert Jason.decode!(missing_line)["error"]["code"] == "FORBIDDEN"
    refute missing_line =~ "app-runtime-private"
    await_audit_agent_phases!(3)
    assert {:ok, missing_events} = Journal.batch()
    assert List.last(missing_events)["outcome"] == "error"
    assert List.last(missing_events)["reason_code"] == "not_found"
    send(reporter, :upload)
    assert_receive {:audit_upload_waiting, ^reporter, ^missing_events}, 5_000
    ref = push(ctx.socket, "audit:batch", %{"events" => missing_events})
    assert_reply(ref, :ok, missing_ack, 5_000)
    send(reporter, {:audit_upload_reply, {:ok, audit_wire(missing_ack)}})
    await_audit_journal_empty!()

    assert {:ok, %{requests: 2, success: 1, error: 1, denied: 0, incomplete: 0}} =
             AccessAudit.summary(%{application_id: ctx.app.id})

    assert {:ok, missing_timeline} =
             AccessAudit.timeline(namespace, missing_claims.audit_request_id)

    assert Enum.filter(
             missing_timeline,
             &(&1.envelope["phase"] in ~w(core_decision response_sent))
           )
           |> Enum.all?(
             &(&1.envelope["outcome"] == "error" and &1.envelope["reason_code"] == "not_found")
           )

    assert {:ok, :valid} = Audit.verify_chain()
    leave(ctx.socket)
  end

  defp audit_matching_requests(app_id) do
    with {:ok, %{entries: entries}} <-
           AccessAudit.requests(%{application_id: app_id}),
         do: {:ok, entries}
  end

  defp audit_wire(value), do: value |> Jason.encode!() |> Jason.decode!()

  defp audit_uds_connect(path) do
    {:ok, client} =
      :gen_tcp.connect(
        {:local, to_charlist(path)},
        0,
        [:binary, packet: :line, active: false],
        2_000
      )

    client
  end

  defp audit_uds_exchange(client, action, params) do
    :ok =
      :gen_tcp.send(
        client,
        Jason.encode!(%{request_id: Ecto.UUID.generate(), action: action, params: params}) <> "\n"
      )

    {:ok, line} = :gen_tcp.recv(client, 0, 5_000)
    Jason.decode!(line)
  end

  defp audit_uds_proof(data, key) do
    challenge = %{
      agent_id: data["agent_id"],
      connection_id: data["connection_id"],
      challenge_id: data["challenge_id"],
      nonce: Base.decode64!(data["challenge"]),
      certificate_fingerprint: data["certificate_fingerprint"],
      signature_algorithm: data["signature_algorithm"]
    }

    signature = :public_key.sign(UDSAuth.transcript(challenge), :sha256, key)

    %{
      auth_version: 2,
      connection_id: challenge.connection_id,
      challenge_id: challenge.challenge_id,
      signature_algorithm: challenge.signature_algorithm,
      signature: Base.encode64(signature)
    }
  end

  defp await_audit_journal_empty!(attempts \\ 500)

  defp await_audit_journal_empty!(0),
    do: flunk("committed acknowledgement did not release Journal batch")

  defp await_audit_journal_empty!(attempts) do
    if Journal.batch() == {:ok, []},
      do: :ok,
      else:
        (
          Process.sleep(10)
          await_audit_journal_empty!(attempts - 1)
        )
  end

  defp await_audit_agent_phases!(expected, attempts \\ 500)
  defp await_audit_agent_phases!(_, 0), do: flunk("Agent transport observation was not persisted")

  defp await_audit_agent_phases!(expected, attempts) do
    case Journal.batch() do
      {:ok, events} when length(events) == expected ->
        :ok

      _ ->
        Process.sleep(10)
        await_audit_agent_phases!(expected, attempts - 1)
    end
  end

  test "current Core floor rejects stale proof version and malformed payloads without releasing values" do
    %{socket: socket, app: app, certificate: certificate, path: path} =
      application_runtime_fixture!()

    Repo.update_all(SecretHub.Shared.Schemas.AuthorizationEpoch,
      set: [minimum_uds_auth_version: 2]
    )

    payload = %{
      "path" => path,
      "app_id" => app.id,
      "certificate_fingerprint" => certificate.canonical_fingerprint,
      "local_auth_version" => 2
    }

    for bad <- [
          Map.delete(payload, "local_auth_version"),
          Map.put(payload, "local_auth_version", 1),
          Map.put(payload, "local_auth_version", "2")
        ] do
      ref = push(socket, "secret:read", bad)
      assert_reply(ref, :error, %{reason: "INCOMPATIBLE_VERSION"}, 2_000)
    end

    for bad <- [Map.put(payload, "path", %{}), Map.put(payload, "known_revision", "1")] do
      ref = push(socket, "secret:read", bad)
      assert_reply(ref, :error, %{reason: "FORBIDDEN"}, 2_000)
    end

    certificate |> Certificate.revoke_changeset("app-revoked") |> Repo.update!()
    ref = push(socket, "secret:read", payload)
    assert_reply(ref, :error, %{reason: "UNAUTHORIZED"}, 2_000)
  end

  test "legacy read waiting on floor activation cannot release a value after cutover commits" do
    previous = Application.get_env(:secrethub_core, :launch_profile)
    Application.put_env(:secrethub_core, :launch_profile, :compatibility)
    on_exit(fn -> Application.put_env(:secrethub_core, :launch_profile, previous) end)

    %{socket: socket, path: path} = application_runtime_fixture!()
    assert {:ok, _} = SecretHub.Core.PKI.AppCertificatePreflight.backfill_canonical_fingerprints()
    parent = self()

    cutover =
      Task.async(fn ->
        Repo.put_dynamic_repo(:runtime_authorization_fixture)

        Repo.transaction(fn ->
          Repo.query!("SET LOCAL statement_timeout = '8s'")
          [[backend]] = Repo.query!("SELECT pg_backend_pid()").rows

          assert {:ok, _} =
                   UpgradeGates.activate_app_certificate_v2(actor_id: "operator:test")

          send(parent, {:floor_written, backend})

          receive do
            :commit_floor -> :ok
          after
            5_000 -> flunk("floor commit release missing")
          end
        end)
      end)

    on_exit(fn -> if Process.alive?(cutover.pid), do: Process.exit(cutover.pid, :kill) end)
    assert_receive {:floor_written, backend}, 2_000
    assert UpgradeGates.minimum_uds_auth_version() == 1

    ref = push(socket, "secret:read", %{"path" => path})

    # The production activation holds both the epoch and audit append locks.
    # Observe a real blocked connection before committing, rather than assuming
    # the channel reached its read based on elapsed time.
    await_cutover_blocked_read!(backend)
    send(cutover.pid, :commit_floor)
    assert {:ok, :ok} = Task.await(cutover, 10_000)
    assert UpgradeGates.minimum_uds_auth_version() == 2
    assert_reply(ref, :error, %{reason: "INCOMPATIBLE_VERSION"}, 2_000)
  end

  defp await_cutover_blocked_read!(backend, attempts \\ 200)
  defp await_cutover_blocked_read!(_, 0), do: flunk("legacy read never blocked behind cutover")

  defp await_cutover_blocked_read!(backend, attempts) do
    case Repo.query!(
           "SELECT pid FROM pg_stat_activity WHERE datname = current_database() " <>
             "AND wait_event_type = 'Lock' AND $1 = ANY(pg_blocking_pids(pid))",
           [backend]
         ).rows do
      [[_reader_backend]] ->
        :ok

      [] ->
        Process.sleep(10)
        await_cutover_blocked_read!(backend, attempts - 1)
    end
  end

  defp application_runtime_fixture!(capabilities \\ ["uds_auth_v2"]) do
    :ok = RuntimeDatabaseFixture.setup()
    ensure_current_audit_partition!()
    restart_seal_state!()
    unseal_vault!()
    %{cert_der: cert_der, enrollment: enrollment} = issue_valid_agent_certificate!()

    assert {:ok, socket} =
             connect(AgentTrustedSocket, %{}, connect_info: %{peer_data: %{ssl_cert: cert_der}})

    assert {:ok, _, socket} =
             subscribe_and_join(
               socket,
               SecretHub.Web.AgentRuntimeDatabaseChannel,
               "agent:runtime",
               %{
                 "runtime_capabilities" => capabilities
               }
             )

    agent = Agents.get_agent(enrollment.agent_id)

    {:ok, %{app: app, token: token}} =
      Apps.register_app(%{
        name: "channel-app-#{System.unique_integer([:positive])}",
        agent_id: agent.id
      })

    key = X509.PrivateKey.new_ec(:secp256r1)
    csr = key |> X509.CSR.new("/CN=untrusted") |> X509.CSR.to_pem()

    {:ok, %{cert_record: certificate}} =
      AppCertificates.issue_from_bootstrap(token, csr, Ecto.UUID.generate())

    path = "test.channel.application"

    {:ok, _} =
      Secrets.create_secret(%{
        name: "App Runtime Secret",
        secret_path: path,
        value: "app-runtime-private"
      })

    policies =
      for subject <- ["agent:" <> agent.id, "application:" <> app.id] do
        {:ok, policy} =
          Policies.create_policy(%{
            name: "channel-#{subject}",
            policy_document: %{
              "version" => "1.0",
              "allowed_secrets" => [path],
              "allowed_operations" => ["read"]
            },
            entity_bindings: [subject]
          })

        policy
      end

    assert {:ok, _} =
             UpgradeGates.verify_typed_runtime_authorization(actor_id: "operator:test")

    %{
      socket: socket,
      agent: agent,
      app_key: key,
      app: app,
      certificate: certificate,
      path: path,
      app_policy: List.last(policies)
    }
  end

  test "rejects runtime join if agent is revoked after socket connect" do
    %{cert_der: cert_der, enrollment: enrollment} = issue_valid_agent_certificate!()

    assert {:ok, socket} =
             connect(AgentTrustedSocket, %{}, connect_info: %{peer_data: %{ssl_cert: cert_der}})

    revoke_agent_row!(enrollment.agent_id)

    assert {:error, %{reason: "runtime_not_authorized"}} =
             subscribe_and_join(socket, AgentRuntimeChannel, "agent:runtime", %{})

    refute ConnectionManager.connected?(enrollment.agent_id)
    assert Agents.get_agent(enrollment.agent_id).status == :revoked
  end

  test "secret reads re-check runtime authorization before serving requests" do
    previous_trap_exit = Process.flag(:trap_exit, true)
    on_exit(fn -> Process.flag(:trap_exit, previous_trap_exit) end)

    %{cert_der: cert_der, enrollment: enrollment} = issue_valid_agent_certificate!()

    assert {:ok, socket} =
             connect(AgentTrustedSocket, %{}, connect_info: %{peer_data: %{ssl_cert: cert_der}})

    assert {:ok, _reply, socket} =
             subscribe_and_join(socket, AgentRuntimeChannel, "agent:runtime", %{})

    channel_pid = socket.channel_pid
    revoke_agent_row!(enrollment.agent_id)

    ref = push(socket, "secret:read", %{"path" => "e2e/ws/test-secret"})

    assert_reply(ref, :error, %{reason: "runtime_not_authorized"}, 1_000)
    assert_receive {:EXIT, ^channel_pid, {:shutdown, :agent_not_active}}, 1_000
    refute ConnectionManager.connected?(enrollment.agent_id)
  end

  test "secret reads do not release decrypted data when authorization is revoked during the read" do
    previous_trap_exit = Process.flag(:trap_exit, true)
    on_exit(fn -> Process.flag(:trap_exit, previous_trap_exit) end)

    :ok = RuntimeDatabaseFixture.setup()
    ensure_current_audit_partition!()
    restart_seal_state!()
    unseal_vault!()

    %{cert_der: cert_der, enrollment: enrollment} = issue_valid_agent_certificate!()
    secret_path = "runtime.revoked.during.read.#{System.unique_integer([:positive])}"

    create_readable_secret!(enrollment.agent_id, secret_path)
    install_revoke_after_secret_access_trigger!()

    assert {:ok, socket} =
             connect(AgentTrustedSocket, %{}, connect_info: %{peer_data: %{ssl_cert: cert_der}})

    assert {:ok, _reply, socket} =
             subscribe_and_join(
               socket,
               SecretHub.Web.AgentRuntimeDatabaseChannel,
               "agent:runtime",
               %{}
             )

    channel_pid = socket.channel_pid

    ref = push(socket, "secret:read", %{"path" => secret_path})

    assert_reply(ref, :error, %{reason: "runtime_not_authorized"}, 1_000)
    assert_receive {:EXIT, ^channel_pid, {:shutdown, :agent_not_active}}, 1_000
    refute_receive %{payload: %{data: %{"value" => "must-not-leak"}}}, 100
    assert Agents.get_agent(enrollment.agent_id).status == :revoked
  end

  test "Core disconnect stops an open trusted runtime channel" do
    previous_trap_exit = Process.flag(:trap_exit, true)
    on_exit(fn -> Process.flag(:trap_exit, previous_trap_exit) end)

    %{cert_der: cert_der, enrollment: enrollment} = issue_valid_agent_certificate!()

    assert {:ok, socket} =
             connect(AgentTrustedSocket, %{}, connect_info: %{peer_data: %{ssl_cert: cert_der}})

    assert {:ok, _reply, socket} =
             subscribe_and_join(socket, AgentRuntimeChannel, "agent:runtime", %{})

    channel_pid = socket.channel_pid
    monitor_ref = Process.monitor(channel_pid)

    assert :ok = ConnectionManager.disconnect_agent(enrollment.agent_id, :revoked)

    assert_receive {:DOWN, ^monitor_ref, :process, ^channel_pid, _reason}, 1_000
    assert_receive {:EXIT, ^channel_pid, {:shutdown, :revoked}}, 1_000
    refute ConnectionManager.connected?(enrollment.agent_id)
    assert Agents.get_agent(enrollment.agent_id).status == :disconnected
  end

  test "replaced channel termination does not mark the newer connection disconnected" do
    previous_trap_exit = Process.flag(:trap_exit, true)
    on_exit(fn -> Process.flag(:trap_exit, previous_trap_exit) end)

    %{cert_der: cert_der, enrollment: enrollment} = issue_valid_agent_certificate!()

    assert {:ok, first_socket} =
             connect(AgentTrustedSocket, %{}, connect_info: %{peer_data: %{ssl_cert: cert_der}})

    assert {:ok, _reply, first_socket} =
             subscribe_and_join(first_socket, AgentRuntimeChannel, "agent:runtime", %{})

    first_channel_pid = first_socket.channel_pid
    first_monitor_ref = Process.monitor(first_channel_pid)

    assert {:ok, second_socket} =
             connect(AgentTrustedSocket, %{}, connect_info: %{peer_data: %{ssl_cert: cert_der}})

    assert {:ok, _reply, second_socket} =
             subscribe_and_join(second_socket, AgentRuntimeChannel, "agent:runtime", %{})

    assert_receive {:DOWN, ^first_monitor_ref, :process, ^first_channel_pid, _reason}, 1_000
    assert Agents.get_agent(enrollment.agent_id).status == :trusted_connected
    assert ConnectionManager.connected?(enrollment.agent_id)

    leave(second_socket)
  end

  test "rejects trusted socket connection without a peer certificate" do
    assert :error = connect(AgentTrustedSocket, %{}, connect_info: %{})
  end

  test "rejects trusted socket connection when stored certificate is revoked" do
    %{certificate: certificate, cert_der: cert_der} = issue_valid_agent_certificate!()

    certificate
    |> Certificate.revoke_changeset("test_revocation")
    |> Repo.update!()

    assert :error =
             connect(AgentTrustedSocket, %{}, connect_info: %{peer_data: %{ssl_cert: cert_der}})
  end

  test "rejects hand-seeded socket identity that is not backed by Core certificate state" do
    socket =
      socket(AgentTrustedSocket, "agent:test", %{
        agent_id: "agent-from-cert",
        certificate_serial: "serial-1",
        certificate_fingerprint: "fingerprint-1",
        certificate_id: "certificate-id-1"
      })

    assert {:error, %{reason: "runtime_not_authorized"}} =
             subscribe_and_join(socket, AgentRuntimeChannel, "agent:runtime", %{
               "agent_id" => "client-spoof",
               "certificate_serial" => "spoofed-serial",
               "certificate_fingerprint" => "spoofed-fingerprint",
               "certificate_id" => "spoofed-certificate-id"
             })
  end

  test "pki:client_auth_bundle:get returns bundle and bootstraps last_accepted_sequence from recorded receipt" do
    _ = ClientAuth.initialize_authority()
    %{cert_der: cert_der} = issue_valid_agent_certificate!()

    assert {:ok, socket} =
             connect(AgentTrustedSocket, %{}, connect_info: %{peer_data: %{ssl_cert: cert_der}})

    assert {:ok, _reply, socket} =
             subscribe_and_join(socket, AgentRuntimeChannel, "agent:runtime", %{})

    # 1. Pull bundle before any receipt is recorded
    ref1 = push(socket, "pki:client_auth_bundle:get", %{})
    assert_reply(ref1, :ok, bundle1, 1_000)
    assert is_map(bundle1)
    refute Map.has_key?(bundle1, "last_accepted_sequence")

    # 2. Record receipt with observation_sequence 100
    receipt_payload = %{
      "generation" => bundle1["generation"],
      "crl_number" => bundle1["crl_number"],
      "bundle_sha256" => bundle1["bundle_sha256"],
      "status" => "applied",
      "applied_at" => DateTime.utc_now() |> DateTime.to_iso8601(),
      "observation_sequence" => 100
    }

    ref2 = push(socket, "pki:client_auth_bundle:receipt", receipt_payload)
    assert_reply(ref2, :ok, %{status: "recorded"}, 1_000)

    # 3. Pull bundle again: now Core returns last_accepted_sequence 100
    ref3 = push(socket, "pki:client_auth_bundle:get", %{})
    assert_reply(ref3, :ok, bundle2, 1_000)
    assert bundle2["last_accepted_sequence"] == 100
  end

  defp issue_valid_agent_certificate! do
    ssh_private_key = :public_key.generate_key({:rsa, 2048, 65_537})
    ssh_public_key = :ssh_file.extract_public_key(ssh_private_key)
    tls_private_key = :public_key.generate_key({:rsa, 2048, 65_537})
    fingerprint = CSR.ssh_fingerprint(ssh_public_key)

    generate_active_ca!()

    {:ok, %{enrollment: enrollment, pending_token: pending_token}} =
      @pending_attrs
      |> Map.put(:machine_id, "runtime-channel-#{System.unique_integer([:positive])}")
      |> Map.put(:ssh_host_key_fingerprint, fingerprint)
      |> Map.put(:ssh_host_public_key, openssh_public_key(ssh_public_key))
      |> Enrollment.create_pending("203.0.113.10")

    {:ok, approved} = Enrollment.approve(enrollment.id, "operator-1")
    csr_pem = csr_pem_for_required_fields(tls_private_key, approved.required_csr_fields)

    proof =
      AgentCSRProof.sign(ssh_private_key, %{
        enrollment_id: approved.id,
        challenge: approved.required_csr_fields["challenge"],
        csr_pem: csr_pem
      })

    {:ok, %{certificate: certificate, enrollment: issued}} =
      Enrollment.submit_csr(approved.id, pending_token, %{
        "csr_pem" => csr_pem,
        "ssh_proof" => proof
      })

    [{:Certificate, cert_der, :not_encrypted}] =
      :public_key.pem_decode(certificate.certificate_pem)

    %{certificate: certificate, cert_der: cert_der, enrollment: issued}
  end

  defp ensure_current_audit_partition! do
    today = Date.utc_today()
    month = String.pad_leading(to_string(today.month), 2, "0")
    partition_name = "audit_logs_y#{today.year}m#{month}"
    from_date = "#{today.year}-#{month}-01"

    next_month_number = if today.month == 12, do: 1, else: today.month + 1
    next_year = if today.month == 12, do: today.year + 1, else: today.year
    next_month = String.pad_leading(to_string(next_month_number), 2, "0")
    to_date = "#{next_year}-#{next_month}-01"

    Repo.query!("""
    CREATE TABLE IF NOT EXISTS #{partition_name} PARTITION OF audit_logs
    FOR VALUES FROM ('#{from_date}') TO ('#{to_date}')
    """)
  end

  defp revoke_agent_row!(agent_id) do
    agent = Repo.get_by!(Agent, agent_id: agent_id)

    agent
    |> Ecto.Changeset.change(status: :revoked)
    |> Repo.update!()
  end

  defp create_readable_secret!(agent_id, secret_path) do
    assert {:ok, _secret} =
             Secrets.create_secret(%{
               "name" => "Runtime Secret #{System.unique_integer([:positive])}",
               "secret_path" => secret_path,
               "secret_type" => "static",
               "secret_data" => %{"value" => "must-not-leak"},
               "created_by" => agent_id
             })

    assert {:ok, _policy} =
             Policies.create_policy(%{
               name: "runtime-read-#{System.unique_integer([:positive])}",
               description: "Allow runtime channel read test",
               policy_document: %{
                 "version" => "1.0",
                 "allowed_secrets" => [secret_path],
                 "allowed_operations" => ["read"]
               },
               entity_bindings: [agent_id]
             })

    :ok
  end

  defp install_revoke_after_secret_access_trigger! do
    suffix = System.unique_integer([:positive])
    function_name = "revoke_agent_after_secret_access_#{suffix}"
    trigger_name = "revoke_agent_after_secret_access_trigger_#{suffix}"

    Repo.query!("""
    CREATE FUNCTION #{function_name}() RETURNS trigger AS $$
    BEGIN
      IF NEW.event_type = 'secret.accessed' THEN
        UPDATE agents
        SET status = 'revoked', updated_at = NOW()
        WHERE agent_id = NEW.actor_id;
      END IF;

      RETURN NEW;
    END;
    $$ LANGUAGE plpgsql;
    """)

    Repo.query!("""
    CREATE TRIGGER #{trigger_name}
    AFTER INSERT ON audit_logs
    FOR EACH ROW
    EXECUTE FUNCTION #{function_name}();
    """)

    dynamic_repo = Repo.get_dynamic_repo()

    on_exit(fn ->
      Repo.put_dynamic_repo(dynamic_repo)
      Repo.query!("DROP TRIGGER IF EXISTS #{trigger_name} ON audit_logs")
      Repo.query!("DROP FUNCTION IF EXISTS #{function_name}()")
    end)
  end

  defp restart_seal_state! do
    case Process.whereis(SealState) do
      nil ->
        :ok

      pid ->
        GenServer.stop(pid, :normal)
        wait_until_unregistered(SealState)
    end

    opts =
      if Repo.get_dynamic_repo() == :runtime_authorization_fixture,
        do: [repo: RuntimeDatabaseFixture.VaultRepo],
        else: []

    case SealState.start_link(opts) do
      {:ok, _pid} -> :ok
      {:error, {:already_started, _pid}} -> :ok
    end

    await_vault_loaded!(200)
  end

  defp await_vault_loaded!(0), do: flunk("Vault durable state did not load")

  defp await_vault_loaded!(attempts) do
    case SealState.status().state do
      :loading ->
        Process.sleep(5)
        await_vault_loaded!(attempts - 1)

      state when state in [:not_initialized, :sealed] ->
        :ok

      state ->
        flunk("Unexpected loaded Vault state: #{state}")
    end
  end

  defp unseal_vault! do
    {:ok, shares} = SealState.initialize(3, 2)
    {:ok, _} = SealState.unseal(Enum.at(shares, 0))
    {:ok, _} = SealState.unseal(Enum.at(shares, 1))
    :ok
  end

  defp wait_until_unregistered(name) do
    if Process.whereis(name) do
      Process.sleep(10)
      wait_until_unregistered(name)
    else
      :ok
    end
  end

  defp generate_active_ca! do
    {:ok, %{cert_record: cert}} =
      CA.generate_root_ca(
        "Agent Runtime Channel Test Root CA #{System.unique_integer([:positive])}",
        "SecretHub Test",
        key_size: 2048
      )

    cert
  end

  defp openssh_public_key(public_key) do
    [{public_key, []}]
    |> :ssh_file.encode(:openssh_key)
    |> IO.iodata_to_binary()
    |> String.trim()
  end

  defp csr_pem_for_required_fields(private_key, required_fields) do
    required_fields
    |> csr_for_required_fields(private_key)
    |> X509.CSR.to_pem()
  end

  defp csr_for_required_fields(required_fields, private_key) do
    subject = required_fields["subject"]
    sans = required_fields["san"] || %{}

    uri_sans =
      sans
      |> Map.get("uri", [])
      |> List.wrap()
      |> Enum.map(&{:uniformResourceIdentifier, to_charlist(&1)})

    dns_sans =
      sans
      |> Map.get("dns", [])
      |> List.wrap()
      |> Enum.map(&{:dNSName, to_charlist(&1)})

    X509.CSR.new(private_key, [{"O", subject["O"]}, {"CN", subject["CN"]}],
      extension_request: [
        Extension.subject_alt_name(uri_sans ++ dns_sans),
        Extension.key_usage([:digitalSignature]),
        Extension.ext_key_usage([:clientAuth])
      ]
    )
  end
end

defmodule SecretHub.Web.AgentRuntimeDatabaseChannel do
  @moduledoc false
  use SecretHub.Web, :channel
  alias SecretHub.Core.Repo
  alias SecretHub.Web.AgentRuntimeChannel

  # Only test database routing changes; authorization uses production callbacks.
  def join(topic, payload, socket) do
    Repo.put_dynamic_repo(:runtime_authorization_fixture)
    AgentRuntimeChannel.join(topic, payload, socket)
  end

  defdelegate handle_in(event, payload, socket), to: AgentRuntimeChannel
  defdelegate handle_info(message, socket), to: AgentRuntimeChannel
  defdelegate terminate(reason, socket), to: AgentRuntimeChannel
end

defmodule SecretHub.Web.AccessAuditRuntimeBridge do
  @moduledoc false
  use GenServer

  def start_link(opts),
    do: GenServer.start_link(__MODULE__, opts, name: SecretHub.Agent.Connection)

  def init(opts), do: {:ok, Keyword.fetch!(opts, :owner)}

  def handle_call({:get_static_secret_for_app, path, claims, revision}, from, owner) do
    send(owner, {:audit_runtime_read, from, path, claims, revision})
    {:noreply, owner}
  end
end
