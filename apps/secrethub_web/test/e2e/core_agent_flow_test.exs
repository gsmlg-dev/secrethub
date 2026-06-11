defmodule SecretHub.E2E.CoreAgentFlowTest do
  @moduledoc """
  End-to-end test: validates the full SecretHub Core <-> Agent lifecycle.

  Requires PostgreSQL. Excluded from default test suite.

    mix test apps/secrethub_web/test/e2e/ --include e2e          # run E2E only
    mix test apps/secrethub_web/test/e2e/ --include e2e --trace  # verbose output
  """
  use ExUnit.Case, async: false

  @moduletag :e2e

  import Phoenix.ConnTest, except: [connect: 2]
  import Phoenix.ChannelTest

  alias Ecto.Adapters.SQL.Sandbox
  alias SecretHub.Core.Agents.{ConnectionManager, Enrollment}
  alias SecretHub.Core.{Policies, Secrets}
  alias SecretHub.Core.PKI.CSR
  alias SecretHub.Core.Repo
  alias SecretHub.Core.Vault.SealState
  alias SecretHub.E2E.Helpers
  alias SecretHub.Shared.Crypto.AgentCSRProof
  alias SecretHub.Shared.Schemas.Certificate
  alias SecretHub.Web.{AgentChannel, AgentRuntimeChannel, AgentTrustedSocket, UserSocket}

  @endpoint SecretHub.Web.Endpoint

  @pending_attrs %{
    hostname: "e2e-runtime-01",
    fqdn: "e2e-runtime-01.internal.example",
    machine_id: "e2e-runtime-machine",
    os: "linux",
    arch: "x86_64",
    agent_version: "1.2.3",
    ssh_host_key_algorithm: "rsa",
    capabilities: %{"templates" => true}
  }

  # ─── Setup ─────────────────────────────────────────────────

  setup_all do
    # Ensure Ecto sandbox is in shared mode for all E2E tests.
    # This allows the endpoint and channel processes to see test data.
    pid = Sandbox.start_owner!(Repo, shared: true)
    Repo.delete_all(Certificate)

    # Start SealState GenServer (disabled in test config)
    seal_state_pid =
      case SealState.start_link([]) do
        {:ok, pid} -> pid
        {:error, {:already_started, pid}} -> pid
      end

    connection_manager_pid =
      case ConnectionManager.start_link(name: ConnectionManager) do
        {:ok, pid} -> pid
        {:error, {:already_started, pid}} -> pid
      end

    on_exit(fn ->
      # Stop SealState
      if Process.alive?(seal_state_pid), do: GenServer.stop(seal_state_pid, :normal)

      if Process.alive?(connection_manager_pid),
        do: GenServer.stop(connection_manager_pid, :normal)

      Sandbox.stop_owner(pid)
    end)

    # ── Phase 1: Initialize and unseal vault ──
    {_conn, init_resp} = Helpers.init_vault(5, 3)
    shares = init_resp["shares"]
    _unseal_resp = Helpers.unseal_vault(shares, 3)

    # ── Phase 2: Create AppRole and bootstrap agent ──
    {role_id, secret_id} =
      Helpers.create_approle("e2e-test-role", secret_id_num_uses: 0, secret_id_ttl: 3600)

    agent = Helpers.bootstrap_agent(role_id, secret_id)

    # ── Phase 3: Login via REST to get agent_auth token ──
    {200, login_resp} = Helpers.approle_login(role_id, secret_id)
    token = login_resp["token"]

    # ── Phase 4: Create policy and link to agent ──
    _policy = Helpers.create_and_link_policy(agent)

    # ── Phase 5: Create a secret for WebSocket tests ──
    # Done here instead of in individual tests to avoid ConnTest HTTP
    # response messages polluting the test process mailbox during
    # ChannelTest assertions.
    Helpers.write_secret(token, "e2e/ws/test-secret", %{"value" => "ws-test-value"})

    {:ok,
     %{
       shares: shares,
       role_id: role_id,
       secret_id: secret_id,
       token: token,
       agent: agent,
       agent_id: agent.agent_id
     }}
  end

  # ─── Scenario 1: Vault Init & Unseal ──────────────────────

  test "S1: vault is initialized and unsealed", _context do
    status = Helpers.seal_status()

    assert status["initialized"] == true
    assert status["sealed"] == false
  end

  # ─── Scenario 2: AppRole Auth ──────────────────────────────

  test "S2: AppRole login returns a valid token", %{
    role_id: role_id,
    secret_id: secret_id,
    token: token
  } do
    # Verify the token from setup is valid
    assert is_binary(token)
    assert byte_size(token) > 20

    # Verify a fresh login also works (secret_id_num_uses: 0 = unlimited)
    {status, resp} = Helpers.approle_login(role_id, secret_id)
    assert status == 200
    assert is_binary(resp["token"])

    # Verify the token can authenticate against a protected endpoint.
    # A 404 (not found) or 200 is fine — 401 means the token is invalid.
    conn =
      Helpers.authed_conn(resp["token"])
      |> get("/v1/secret/data/e2e/nonexistent")

    assert conn.status in [200, 404]
  end

  # ─── Scenario 3: Secret CRUD ───────────────────────────────

  test "S3: store and retrieve a static secret", %{token: token} do
    secret_data = %{"username" => "e2e-user", "password" => "s3cr3t-hunter2"}

    # Write secret
    {write_status, _write_resp} = Helpers.write_secret(token, "e2e/db/password", secret_data)
    assert write_status == 200

    # Read it back
    {200, read_resp} = Helpers.read_secret(token, "e2e/db/password")

    assert read_resp["data"]["username"] == "e2e-user"
    assert read_resp["data"]["password"] == "s3cr3t-hunter2"
    assert is_map(read_resp["metadata"])
  end

  # ─── Scenario 4: Agent WebSocket ───────────────────────────

  test "S4: legacy agent WebSocket rejects direct runtime joins", %{agent_id: agent_id} do
    # Flush any leftover messages from HTTP calls in previous tests
    flush_mailbox()

    # Connect through the legacy socket. Runtime joins belong on AgentTrustedSocket.
    {:ok, socket} = connect(UserSocket, %{})

    assert {:error, %{reason: "trusted_runtime_requires_mtls"}} =
             subscribe_and_join(socket, AgentChannel, "agent:runtime", %{
               "agent_id" => agent_id
             })
  end

  # ─── Scenario 5: Reconnection ──────────────────────────────

  test "S5: trusted runtime agent recovers from disconnection" do
    flush_mailbox()
    Process.flag(:trap_exit, true)

    %{certificate: certificate, cert_der: cert_der, enrollment: enrollment} =
      issue_valid_agent_certificate!()

    agent_id = enrollment.agent_id

    # First connection
    socket1 = trusted_agent_socket(cert_der)

    {:ok, reply, socket1} =
      subscribe_and_join(socket1, AgentRuntimeChannel, "agent:runtime", %{})

    assert reply.status == "accepted"
    assert reply.agent_id == agent_id
    assert reply.certificate_serial == certificate.serial_number
    assert reply.certificate_fingerprint == certificate.fingerprint
    assert reply.certificate_id == certificate.id
    assert socket1.assigns.agent_id == agent_id

    ref = push(socket1, "agent:heartbeat", %{})
    assert_reply ref, :ok, %{status: "alive"}, 5_000

    # Disconnect
    leave(socket1)
    flush_mailbox()
    Process.sleep(200)

    # Reconnect
    socket2 = trusted_agent_socket(cert_der)

    {:ok, reply, socket2} =
      subscribe_and_join(socket2, AgentRuntimeChannel, "agent:runtime", %{})

    assert reply.status == "accepted"
    assert reply.agent_id == agent_id
    assert reply.certificate_serial == certificate.serial_number
    assert reply.certificate_fingerprint == certificate.fingerprint
    assert reply.certificate_id == certificate.id
    assert socket2.assigns.agent_id == agent_id

    # Verify still works after reconnection
    ref = push(socket2, "agent:heartbeat", %{})
    assert_reply ref, :ok, %{status: "alive"}, 5_000

    leave(socket2)
    flush_mailbox()
    Process.flag(:trap_exit, false)
  end

  # ─── Scenario 6: Trusted Runtime Data Transfer ─────────────

  test "S6: trusted runtime transfers secret data over mTLS channel" do
    flush_mailbox()

    %{cert_der: cert_der, enrollment: enrollment} = issue_valid_agent_certificate!()
    secret_path = "e2e.runtime.transfer.#{System.unique_integer([:positive])}"

    secret_data = %{
      "username" => "runtime-user",
      "password" => "runtime-pass",
      "token" => "runtime-token-#{System.unique_integer([:positive])}"
    }

    create_runtime_readable_secret!(enrollment.agent_id, secret_path, secret_data)

    socket = trusted_agent_socket(cert_der)

    {:ok, reply, socket} =
      subscribe_and_join(socket, AgentRuntimeChannel, "agent:runtime", %{})

    assert reply.status == "accepted"
    assert reply.agent_id == enrollment.agent_id

    ref = push(socket, "secret:read", %{"path" => secret_path})
    assert_reply ref, :ok, %{path: ^secret_path, data: ^secret_data}, 5_000

    leave(socket)
    flush_mailbox()
  end

  # ─── Scenario 7: Audit Trail ───────────────────────────────

  test "S7: audit log records operations with hash chain" do
    # Query all audit logs generated during this E2E run
    logs = Helpers.query_audit_logs()

    # We should have at least: vault_initialized, approle_created, approle_login_success,
    # secret.created, secret.accessed
    assert length(logs) >= 3, "Expected at least 3 audit log entries, got #{length(logs)}"

    # Verify event types exist
    event_types = Enum.map(logs, & &1.event_type)

    # Check that some expected events were logged
    assert "approle_login_success" in event_types or
             "approle_created" in event_types,
           "Expected AppRole events in audit log, got: #{inspect(event_types)}"

    # Verify hash chain integrity where hashes exist
    logs_with_hashes =
      Enum.filter(logs, fn log ->
        log.current_hash != nil and log.current_hash != ""
      end)

    if length(logs_with_hashes) >= 2 do
      logs_with_hashes
      |> Enum.chunk_every(2, 1, :discard)
      |> Enum.each(fn [prev, curr] ->
        if curr.previous_hash != nil do
          assert curr.previous_hash == prev.current_hash,
                 "Hash chain broken at sequence #{curr.sequence_number}: " <>
                   "previous_hash #{inspect(curr.previous_hash)} != " <>
                   "current_hash #{inspect(prev.current_hash)}"
        end
      end)
    end
  end

  # ─── Scenario 9: Real mTLS Transport ───────────────────────
  #
  # Unlike S5/S6, which inject peer_data into ChannelTest, this scenario
  # boots the real AgentEndpoint TLS listener and connects through the
  # Agent's actual WebSocket client, exercising certificate chain
  # validation on both sides of a real socket.

  @real_mtls_port 4666

  test "S9: agent connects through the real mTLS endpoint and joins runtime" do
    flush_mailbox()
    Process.flag(:trap_exit, true)

    %{certificate: certificate, enrollment: enrollment, tls_private_key: tls_private_key} =
      issue_valid_agent_certificate!()

    previous_dev_mode = Application.get_env(:secrethub_web, :dev_mode)
    previous_endpoint = Application.get_env(:secrethub_web, :agent_trusted_endpoint)
    endpoint_url = "wss://localhost:#{@real_mtls_port}/agent/socket/websocket"

    Application.put_env(:secrethub_web, :dev_mode, true)
    Application.put_env(:secrethub_web, :agent_trusted_endpoint, endpoint_url)

    on_exit(fn ->
      Application.put_env(:secrethub_web, :dev_mode, previous_dev_mode || false)

      if previous_endpoint do
        Application.put_env(:secrethub_web, :agent_trusted_endpoint, previous_endpoint)
      end

      Supervisor.terminate_child(SecretHub.Web.Supervisor, SecretHub.Web.AgentEndpoint)
      Supervisor.delete_child(SecretHub.Web.Supervisor, SecretHub.Web.AgentEndpoint)
    end)

    assert :ok = SecretHub.Web.AgentEndpointManager.ensure_started()

    {:ok, ca_chain_pem} = SecretHub.Core.PKI.CA.get_ca_chain()
    test_pid = self()

    {:ok, conn} =
      SecretHub.Agent.TrustedConnection.start_link(
        agent_id: enrollment.agent_id,
        connect_info: %{
          "trusted_websocket_endpoint" => endpoint_url,
          "expected_core_server_name" => "localhost",
          "core_ca_cert_pem" => ca_chain_pem
        },
        certificate_pem: certificate.certificate_pem,
        private_key_pem: X509.PrivateKey.to_pem(tls_private_key),
        on_runtime_accepted: fn payload -> send(test_pid, {:runtime_accepted, payload}) end
      )

    assert_receive {:runtime_accepted, payload}, 15_000

    assert payload["status"] == "accepted"
    assert payload["agent_id"] == enrollment.agent_id
    assert payload["certificate_serial"] == certificate.serial_number
    assert payload["certificate_fingerprint"] == certificate.fingerprint

    GenServer.stop(conn)
    flush_mailbox()
    Process.flag(:trap_exit, false)
  end

  # ─── Scenario 8: Health Endpoints ──────────────────────────

  test "S8: health endpoints respond" do
    {status, resp} = Helpers.check_health("/v1/sys/health")
    assert status == 200
    assert is_map(resp)

    {status, _resp} = Helpers.check_health("/v1/sys/health/ready")
    # 200 or 503 depending on vault state — both are valid responses
    assert status in [200, 503]

    {200, _resp} = Helpers.check_health("/v1/sys/health/live")
  end

  # ─── Private Helpers ───────────────────────────────────────

  defp flush_mailbox do
    receive do
      _ -> flush_mailbox()
    after
      0 -> :ok
    end
  end

  defp trusted_agent_socket(cert_der) do
    assert {:ok, socket} =
             Phoenix.ChannelTest.connect(AgentTrustedSocket, %{},
               connect_info: %{peer_data: %{ssl_cert: cert_der}}
             )

    socket
  end

  defp issue_valid_agent_certificate! do
    ssh_private_key = :public_key.generate_key({:rsa, 2048, 65_537})
    ssh_public_key = :ssh_file.extract_public_key(ssh_private_key)
    tls_private_key = :public_key.generate_key({:rsa, 2048, 65_537})
    fingerprint = CSR.ssh_fingerprint(ssh_public_key)

    generate_active_ca!()

    {:ok, %{enrollment: enrollment, pending_token: pending_token}} =
      @pending_attrs
      |> Map.put(:machine_id, "e2e-runtime-#{System.unique_integer([:positive])}")
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

    %{
      certificate: certificate,
      cert_der: cert_der,
      enrollment: issued,
      tls_private_key: tls_private_key
    }
  end

  defp create_runtime_readable_secret!(agent_id, secret_path, secret_data) do
    {:ok, _secret} =
      Secrets.create_secret(%{
        "name" => "E2E Runtime Secret #{System.unique_integer([:positive])}",
        "secret_path" => secret_path,
        "secret_type" => "static",
        "secret_data" => secret_data,
        "created_by" => agent_id
      })

    {:ok, _policy} =
      Policies.create_policy(%{
        name: "e2e-runtime-read-#{System.unique_integer([:positive])}",
        description: "Allow E2E runtime channel secret read",
        policy_document: %{
          "version" => "1.0",
          "allowed_secrets" => [secret_path],
          "allowed_operations" => ["read"]
        },
        entity_bindings: [agent_id]
      })

    :ok
  end

  defp generate_active_ca! do
    {:ok, %{cert_record: cert}} =
      SecretHub.Core.PKI.CA.generate_root_ca(
        "Core Agent E2E Test Root CA #{System.unique_integer([:positive])}",
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
        X509.Certificate.Extension.subject_alt_name(uri_sans ++ dns_sans),
        X509.Certificate.Extension.key_usage([:digitalSignature]),
        X509.Certificate.Extension.ext_key_usage([:clientAuth])
      ]
    )
  end
end
