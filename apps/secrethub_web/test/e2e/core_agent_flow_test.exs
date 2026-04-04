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

  alias SecretHub.Core.Repo
  alias SecretHub.Core.Vault.SealState
  alias SecretHub.E2E.Helpers
  alias SecretHub.Web.{AgentChannel, UserSocket}

  @endpoint SecretHub.Web.Endpoint

  # ─── Setup ─────────────────────────────────────────────────

  setup_all do
    # Ensure Ecto sandbox is in shared mode for all E2E tests.
    # This allows the endpoint and channel processes to see test data.
    pid = Ecto.Adapters.SQL.Sandbox.start_owner!(Repo, shared: true)

    # Start SealState GenServer (disabled in test config)
    seal_state_pid =
      case SealState.start_link([]) do
        {:ok, pid} -> pid
        {:error, {:already_started, pid}} -> pid
      end

    on_exit(fn ->
      # Stop SealState
      if Process.alive?(seal_state_pid), do: GenServer.stop(seal_state_pid, :normal)
      Ecto.Adapters.SQL.Sandbox.stop_owner(pid)
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

  test "S4: agent connects via WebSocket and fetches secret", %{
    role_id: role_id,
    secret_id: secret_id,
    token: token
  } do
    # First ensure the secret exists (from S3 or create here)
    Helpers.write_secret(token, "e2e/ws/test-secret", %{"value" => "ws-test-value"})

    # Connect socket (auth happens at channel level)
    {:ok, socket} = connect(UserSocket, %{})

    # Join the lobby channel
    {:ok, reply, socket} = subscribe_and_join(socket, AgentChannel, "agent:lobby", %{})
    assert reply.status == "connected"
    assert reply.authenticated == false

    # Authenticate via channel message
    ref = push(socket, "authenticate", %{"role_id" => role_id, "secret_id" => secret_id})
    assert_reply ref, :ok, auth_reply

    assert auth_reply.status == "authenticated"
    assert is_binary(auth_reply.agent_id)
    assert is_binary(auth_reply.token)

    # Request a secret via the channel
    ref = push(socket, "secret:request", %{"path" => "e2e.ws.test-secret"})
    assert_reply ref, :ok, secret_reply

    assert secret_reply.path == "e2e.ws.test-secret"
    assert is_map(secret_reply.data)
    assert is_binary(secret_reply.lease_id)

    # Send heartbeat
    ref = push(socket, "heartbeat", %{})
    assert_reply ref, :ok, %{status: "alive"}

    leave(socket)
  end

  # ─── Scenario 5: Reconnection ──────────────────────────────

  test "S5: agent recovers from disconnection", %{role_id: role_id, secret_id: secret_id} do
    # First connection
    {:ok, socket1} = connect(UserSocket, %{})
    {:ok, _reply, socket1} = subscribe_and_join(socket1, AgentChannel, "agent:lobby", %{})

    ref = push(socket1, "authenticate", %{"role_id" => role_id, "secret_id" => secret_id})
    assert_reply ref, :ok, %{status: "authenticated"}

    # Disconnect
    leave(socket1)
    Process.sleep(200)

    # Reconnect
    {:ok, socket2} = connect(UserSocket, %{})
    {:ok, _reply, socket2} = subscribe_and_join(socket2, AgentChannel, "agent:lobby", %{})

    ref = push(socket2, "authenticate", %{"role_id" => role_id, "secret_id" => secret_id})
    assert_reply ref, :ok, %{status: "authenticated"}

    # Verify still works after reconnection
    ref = push(socket2, "heartbeat", %{})
    assert_reply ref, :ok, %{status: "alive"}

    leave(socket2)
  end

  # ─── Scenario 6: Audit Trail ───────────────────────────────

  test "S6: audit log records operations with hash chain" do
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

  # ─── Scenario 7: Health Endpoints ──────────────────────────

  test "S7: health endpoints respond" do
    {status, resp} = Helpers.check_health("/v1/sys/health")
    assert status == 200
    assert is_map(resp)

    {status, _resp} = Helpers.check_health("/v1/sys/health/ready")
    # 200 or 503 depending on vault state — both are valid responses
    assert status in [200, 503]

    {200, _resp} = Helpers.check_health("/v1/sys/health/live")
  end
end
