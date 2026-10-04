defmodule SecretHub.Web.AgentRuntimeChannelTest do
  use SecretHub.Web.ChannelCase, async: false

  alias SecretHub.Core.Agents
  alias SecretHub.Core.Agents.ConnectionManager
  alias SecretHub.Core.Agents.Enrollment
  alias SecretHub.Core.PKI.CA
  alias SecretHub.Core.PKI.CSR
  alias SecretHub.Core.{Apps, Policies, Secrets}
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
    assert_reply ref, :error, %{reason: "feature_unavailable"}
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

    assert_push "agent:uds_auth_floor", %{minimum_uds_auth_version: 2}
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
    assert_reply ref, :error, %{reason: "INCOMPATIBLE_VERSION"}
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

    assert_reply ref, :ok, %{
      value: %{"value" => "app-runtime-private"},
      version: 1,
      revision: revision
    }

    ref = push(socket, "secret:read", Map.put(payload, "known_revision", revision))
    assert_reply ref, :ok, %{not_modified: true, revision: ^revision, version: 1}

    for bad <- [
          Map.put(payload, "app_id", Ecto.UUID.generate()),
          Map.put(payload, "certificate_fingerprint", String.duplicate("0", 64))
        ] do
      ref = push(socket, "secret:read", bad)
      assert_reply ref, :error, %{reason: "UNAUTHORIZED"}
    end

    assert {:ok, _} = Policies.delete_policy(policy.id)
    ref = push(socket, "secret:read", payload)
    assert_reply ref, :error, %{reason: "FORBIDDEN"}
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
      assert_reply ref, :error, %{reason: "INCOMPATIBLE_VERSION"}
    end

    for bad <- [Map.put(payload, "path", %{}), Map.put(payload, "known_revision", "1")] do
      ref = push(socket, "secret:read", bad)
      assert_reply ref, :error, %{reason: "FORBIDDEN"}
    end

    certificate |> Certificate.revoke_changeset("app-revoked") |> Repo.update!()
    ref = push(socket, "secret:read", payload)
    assert_reply ref, :error, %{reason: "UNAUTHORIZED"}
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
                   SecretHub.Core.UpgradeGates.activate_app_certificate_v2(
                     actor_id: "operator:test"
                   )

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
    assert SecretHub.Core.UpgradeGates.minimum_uds_auth_version() == 1

    ref = push(socket, "secret:read", %{"path" => path})

    # The production activation holds both the epoch and audit append locks.
    # Observe a real blocked connection before committing, rather than assuming
    # the channel reached its read based on elapsed time.
    await_cutover_blocked_read!(backend)
    send(cutover.pid, :commit_floor)
    assert {:ok, :ok} = Task.await(cutover, 10_000)
    assert SecretHub.Core.UpgradeGates.minimum_uds_auth_version() == 2
    assert_reply ref, :error, %{reason: "INCOMPATIBLE_VERSION"}, 2_000
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

  defp application_runtime_fixture! do
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
                 "runtime_capabilities" => ["uds_auth_v2"]
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
             SecretHub.Core.UpgradeGates.verify_typed_runtime_authorization(
               actor_id: "operator:test"
             )

    %{
      socket: socket,
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

    assert_reply ref, :error, %{reason: "runtime_not_authorized"}, 1_000
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

    assert_reply ref, :error, %{reason: "runtime_not_authorized"}, 1_000
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
    _ = SecretHub.Core.PKI.ClientAuth.initialize_authority()
    %{cert_der: cert_der} = issue_valid_agent_certificate!()

    assert {:ok, socket} =
             connect(AgentTrustedSocket, %{}, connect_info: %{peer_data: %{ssl_cert: cert_der}})

    assert {:ok, _reply, socket} =
             subscribe_and_join(socket, AgentRuntimeChannel, "agent:runtime", %{})

    # 1. Pull bundle before any receipt is recorded
    ref1 = push(socket, "pki:client_auth_bundle:get", %{})
    assert_reply ref1, :ok, bundle1, 1_000
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
    assert_reply ref2, :ok, %{status: "recorded"}, 1_000

    # 3. Pull bundle again: now Core returns last_accepted_sequence 100
    ref3 = push(socket, "pki:client_auth_bundle:get", %{})
    assert_reply ref3, :ok, bundle2, 1_000
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
  alias SecretHub.Web.AgentRuntimeChannel

  # Only test database routing changes; authorization uses production callbacks.
  def join(topic, payload, socket) do
    SecretHub.Core.Repo.put_dynamic_repo(:runtime_authorization_fixture)
    AgentRuntimeChannel.join(topic, payload, socket)
  end

  defdelegate handle_in(event, payload, socket), to: AgentRuntimeChannel
  defdelegate handle_info(message, socket), to: AgentRuntimeChannel
  defdelegate terminate(reason, socket), to: AgentRuntimeChannel
end
