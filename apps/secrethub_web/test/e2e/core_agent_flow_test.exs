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
  alias SecretHub.Agent.{Cache, Connection, TrustedConnection, UDSServer}
  alias SecretHub.Core.Agents.{ConnectionManager, Enrollment}
  alias SecretHub.Core.PKI.{CA, CSR}
  alias SecretHub.Core.{Policies, Secrets}
  alias SecretHub.Core.Repo
  alias SecretHub.Core.Vault.SealState
  alias SecretHub.E2E.Helpers
  alias SecretHub.Shared.Crypto.AgentCSRProof
  alias SecretHub.Shared.Schemas.{AgentEnrollment, Certificate}
  alias SecretHub.Web.{AgentChannel, AgentRuntimeChannel, AgentTrustedSocket, UserSocket}
  alias SecretHub.Web.AgentEndpointManager
  alias X509.Certificate.Extension

  @endpoint SecretHub.Web.Endpoint
  @cli_timeout 60_000

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
    ensure_current_audit_partition!()

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

    # ── Phase 3: Create policy and attach it to both auth paths ──
    policy = Helpers.create_and_link_policy(agent)
    Helpers.attach_policy_to_approle(role_id, [policy.name])

    # ── Phase 4: Login via REST to get agent_auth token ──
    {200, login_resp} = Helpers.approle_login(role_id, secret_id)
    token = login_resp["token"]

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

    secret_path = "e2e.runtime.real.#{System.unique_integer([:positive])}"
    secret_data = %{"value" => "real-runtime-value-#{System.unique_integer([:positive])}"}
    create_runtime_readable_secret!(enrollment.agent_id, secret_path, secret_data)

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

    assert :ok = AgentEndpointManager.ensure_started()

    {:ok, ca_chain_pem} = CA.get_ca_chain()
    test_pid = self()

    {:ok, conn} =
      TrustedConnection.start_link(
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

    assert {:ok, response} = Connection.get_static_secret(conn, secret_path, 5_000)
    assert runtime_secret_data(response) == secret_data

    GenServer.stop(conn)
    flush_mailbox()
    Process.flag(:trap_exit, false)
  end

  # ─── Scenario 10: CLI Against Core ─────────────────────────

  @core_cli_port 4674

  @tag :tmp_dir
  @tag timeout: 120_000
  test "S10: CLI logs in and reads a secret from Core", %{
    role_id: role_id,
    secret_id: secret_id,
    token: token,
    tmp_dir: tmp_dir
  } do
    server_url = start_core_http_endpoint!(@core_cli_port)
    home_dir = Path.join(tmp_dir, "cli-home")
    secret_path = "e2e/cli/core/#{System.unique_integer([:positive])}"
    cli_path = String.replace(secret_path, "/", ".")
    secret_data = %{"value" => "cli-core-value-#{System.unique_integer([:positive])}"}

    {200, _write_resp} = Helpers.write_secret(token, secret_path, secret_data)

    assert {_output, 0} = run_cli(["config", "set", "server_url", server_url], home_dir)

    assert {_output, 0} =
             run_cli(["login", "--role-id", role_id, "--secret-id", secret_id], home_dir)

    assert {output, 0} = run_cli(["secret", "get", cli_path, "--format", "json"], home_dir)
    expected_value = secret_data["value"]
    assert %{"value" => ^expected_value} = Jason.decode!(output)
  end

  # ─── Scenario 11: CLI Against Local Agent ──────────────────

  @agent_cli_mtls_port 4667

  @tag :tmp_dir
  @tag timeout: 120_000
  test "S11: CLI reads a secret from the local Agent backed by Core runtime", %{
    tmp_dir: tmp_dir
  } do
    flush_mailbox()
    stop_registered_process(Connection)
    stop_registered_process(Cache)
    stop_registered_process(UDSServer)
    Process.flag(:trap_exit, true)

    %{certificate: certificate, enrollment: enrollment, tls_private_key: tls_private_key} =
      issue_valid_agent_certificate!()

    secret_path = "e2e.cli.agent.#{System.unique_integer([:positive])}"
    secret_data = %{"value" => "cli-agent-value-#{System.unique_integer([:positive])}"}
    create_runtime_readable_secret!(enrollment.agent_id, secret_path, secret_data)

    previous_dev_mode = Application.get_env(:secrethub_web, :dev_mode)
    previous_endpoint = Application.get_env(:secrethub_web, :agent_trusted_endpoint)
    endpoint_url = "wss://localhost:#{@agent_cli_mtls_port}/agent/socket/websocket"

    Application.put_env(:secrethub_web, :dev_mode, true)
    Application.put_env(:secrethub_web, :agent_trusted_endpoint, endpoint_url)

    socket_path =
      Path.join(System.tmp_dir!(), "sh_e2e_#{System.unique_integer([:positive])}.sock")

    on_exit(fn ->
      Application.put_env(:secrethub_web, :dev_mode, previous_dev_mode || false)

      if previous_endpoint do
        Application.put_env(:secrethub_web, :agent_trusted_endpoint, previous_endpoint)
      end

      Supervisor.terminate_child(SecretHub.Web.Supervisor, SecretHub.Web.AgentEndpoint)
      Supervisor.delete_child(SecretHub.Web.Supervisor, SecretHub.Web.AgentEndpoint)
      stop_registered_process(UDSServer)
      stop_registered_process(Cache)
      stop_registered_process(Connection)
      File.rm(socket_path)
    end)

    assert :ok = AgentEndpointManager.ensure_started()

    {:ok, _cache} = Cache.start_link([])
    {:ok, _uds} = UDSServer.start_link(socket_path: socket_path, request_timeout: 15_000)

    {:ok, ca_chain_pem} = CA.get_ca_chain()
    test_pid = self()

    {:ok, conn} =
      TrustedConnection.start_link(
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

    assert_receive {:runtime_accepted, %{"agent_id" => agent_id}}, 15_000
    assert agent_id == enrollment.agent_id

    app_cert_path = write_app_certificate!(tmp_dir)
    home_dir = Path.join(tmp_dir, "cli-home")

    assert {output, 0} =
             run_cli(
               [
                 "secret",
                 "get",
                 secret_path,
                 "--agent-socket",
                 socket_path,
                 "--agent-cert",
                 app_cert_path,
                 "--format",
                 "json"
               ],
               home_dir
             )

    expected_value = secret_data["value"]
    assert %{"value" => ^expected_value} = Jason.decode!(output)

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

  defp ensure_current_audit_partition! do
    today = Date.utc_today()
    month = String.pad_leading(to_string(today.month), 2, "0")
    next_month_number = if today.month == 12, do: 1, else: today.month + 1
    next_year = if today.month == 12, do: today.year + 1, else: today.year
    next_month = String.pad_leading(to_string(next_month_number), 2, "0")
    partition_name = "audit_logs_y#{today.year}m#{month}"
    from_date = "#{today.year}-#{month}-01"
    to_date = "#{next_year}-#{next_month}-01"

    Ecto.Adapters.SQL.query!(Repo, """
    CREATE TABLE IF NOT EXISTS #{partition_name} PARTITION OF audit_logs
    FOR VALUES FROM ('#{from_date}') TO ('#{to_date}')
    """)
  end

  defp runtime_secret_data(%{"data" => data}), do: data
  defp runtime_secret_data(%{data: data}), do: data

  defp start_core_http_endpoint!(port) do
    Application.ensure_all_started(:inets)

    [spec] =
      Bandit.PhoenixAdapter.child_specs(SecretHub.Web.Endpoint,
        otp_app: :secrethub_web,
        http: [ip: {127, 0, 0, 1}, port: port, startup_log: false]
      )

    spec =
      Supervisor.child_spec(spec,
        id: {SecretHub.Web.Endpoint, :e2e_core_http, port},
        restart: :temporary
      )

    start_supervised!(spec)

    server_url = "http://127.0.0.1:#{port}"
    wait_for_http!(server_url <> "/v1/sys/health/live")
    server_url
  end

  defp wait_for_http!(url, attempts \\ 40)

  defp wait_for_http!(url, attempts) when attempts > 0 do
    case :httpc.request(:get, {String.to_charlist(url), []}, [], []) do
      {:ok, {{_, status, _}, _headers, _body}} when status in 200..399 ->
        :ok

      _other ->
        Process.sleep(100)
        wait_for_http!(url, attempts - 1)
    end
  end

  defp wait_for_http!(url, 0), do: flunk("HTTP endpoint did not start: #{url}")

  defp run_cli(args, home_dir) do
    File.mkdir_p!(home_dir)

    task =
      Task.async(fn ->
        System.cmd(
          "mix",
          [
            "run",
            "--no-compile",
            "--no-deps-check",
            "-e",
            "SecretHub.CLI.main(System.argv())",
            "--"
          ] ++
            args,
          cd: Path.expand("../../../../apps/secrethub_cli", __DIR__),
          env: [{"MIX_ENV", "test"}, {"HOME", home_dir}],
          stderr_to_stdout: true
        )
      end)

    case Task.yield(task, @cli_timeout) || Task.shutdown(task, :brutal_kill) do
      {:ok, result} ->
        result

      nil ->
        flunk("CLI command timed out after #{@cli_timeout}ms: #{Enum.join(args, " ")}")
    end
  end

  defp write_app_certificate!(tmp_dir) do
    app_id = Ecto.UUID.generate()
    private_key = :public_key.generate_key({:rsa, 2048, 65_537})

    cert_pem =
      private_key
      |> X509.Certificate.self_signed("/CN=#{app_id}")
      |> X509.Certificate.to_pem()

    cert_path = Path.join(tmp_dir, "app-client.pem")
    File.write!(cert_path, cert_pem)
    cert_path
  end

  defp stop_registered_process(name) do
    case Process.whereis(name) do
      nil -> :ok
      pid -> GenServer.stop(pid, :normal, 1_000)
    end
  catch
    :exit, _reason -> :ok
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

    %{certificate: certificate, enrollment: issued} =
      case Enrollment.submit_csr(approved.id, pending_token, %{
             "csr_pem" => csr_pem,
             "ssh_proof" => proof
           }) do
        {:ok, result} ->
          result

        {:error, reason} ->
          enrollment = Repo.get!(AgentEnrollment, approved.id)

          flunk(
            "CSR submission failed: #{inspect(reason)} #{inspect(enrollment.last_error)} " <>
              "expected_sans=#{inspect(approved.required_csr_fields["san"])} " <>
              "actual_sans=#{inspect(csr_sans_for_debug(csr_pem))}"
          )
      end

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
      CA.generate_root_ca(
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
        Extension.subject_alt_name(uri_sans ++ dns_sans),
        Extension.key_usage([:digitalSignature]),
        Extension.ext_key_usage([:clientAuth])
      ]
    )
  end

  defp csr_sans_for_debug(csr_pem) do
    {:ok, csr} = X509.CSR.from_pem(csr_pem)

    extension =
      csr
      |> X509.CSR.extension_request()
      |> Extension.find(:subject_alt_name)

    values = if extension, do: elem(extension, 3), else: []

    Enum.reduce(values, %{uri: [], dns: []}, fn
      {:uniformResourceIdentifier, value}, acc ->
        %{acc | uri: [to_string(value) | acc.uri]}

      {:dNSName, value}, acc ->
        %{acc | dns: [to_string(value) | acc.dns]}

      _other, acc ->
        acc
    end)
  end
end
