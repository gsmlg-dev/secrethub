defmodule SecretHub.Web.AgentChannelIntegrationTest do
  @moduledoc """
  Integration tests for Agent WebSocket channel.

  Tests cover:
  - Channel join
  - AppRole authentication flow
  - Secret request handling
  - Heartbeat mechanism
  - Error handling
  - Connection lifecycle
  """

  use SecretHub.Web.ChannelCase, async: false

  alias SecretHub.Core.Auth.AppRole
  alias SecretHub.Web.AgentChannel
  alias SecretHub.Web.UserSocket

  setup do
    # Create a test AppRole
    {:ok, role_result} =
      AppRole.create_role("test-agent",
        policies: ["default", "secrets-read"],
        secret_id_ttl: 3600,
        secret_id_num_uses: 10,
        bind_secret_id: true
      )

    {:ok, role: role_result}
  end

  # Helper: join a direct agent channel to get an authenticated socket.
  # The channel auto-registers the agent on direct topic join.
  defp join_authenticated(agent_id \\ "test-agent-#{:erlang.unique_integer([:positive])}") do
    {:ok, _reply, socket} =
      subscribe_and_join(
        socket(UserSocket, "agent:test", %{}),
        AgentChannel,
        "agent:#{agent_id}"
      )

    socket
  end

  describe "join/3" do
    test "allows agents to join the lobby" do
      {:ok, _response, socket} =
        subscribe_and_join(
          socket(UserSocket, "agent:test", %{}),
          AgentChannel,
          "agent:lobby"
        )

      assert socket.assigns.authenticated == false
      assert socket.assigns.agent_id == nil
      assert socket.assigns.last_heartbeat != nil
    end

    test "auto-registers and authenticates on direct agent channel join" do
      {:ok, reply, socket} =
        subscribe_and_join(
          socket(UserSocket, "agent:test", %{}),
          AgentChannel,
          "agent:some-agent-id"
        )

      assert reply.status == "connected"
      assert reply.authenticated == true
      assert reply.agent_id == "some-agent-id"
      assert socket.assigns.authenticated == true
      assert socket.assigns.agent_id == "some-agent-id"
    end

    test "returns connected status on join" do
      {:ok, response, _socket} =
        subscribe_and_join(
          socket(UserSocket, "agent:test", %{}),
          AgentChannel,
          "agent:lobby"
        )

      assert response.status == "connected"
      assert response.authenticated == false
    end
  end

  describe "authenticate with AppRole" do
    # These tests exercise the full AppRole.login -> bootstrap_agent ->
    # issue_agent_certificate flow. They require PKI cert generation to work.
    @tag :pki
    test "successfully authenticates with valid role_id and secret_id", %{role: role} do
      {:ok, _response, socket} =
        subscribe_and_join(
          socket(UserSocket, "agent:test", %{}),
          AgentChannel,
          "agent:lobby"
        )

      ref =
        push(socket, "authenticate", %{
          "role_id" => role.role_id,
          "secret_id" => role.secret_id
        })

      assert_reply ref, :ok, reply

      assert reply.status == "authenticated"
      assert reply.agent_id != nil
      assert reply.role_name == "test-agent"
      assert reply.token != nil
    end

    test "rejects authentication with invalid role_id" do
      {:ok, _response, socket} =
        subscribe_and_join(
          socket(UserSocket, "agent:test", %{}),
          AgentChannel,
          "agent:lobby"
        )

      ref =
        push(socket, "authenticate", %{
          "role_id" => "invalid-role-id",
          "secret_id" => "invalid-secret-id"
        })

      assert_reply ref, :error, error_reply
      assert error_reply.reason == "invalid_credentials"
    end

    test "rejects authentication with mismatched secret_id", %{role: role} do
      {:ok, _response, socket} =
        subscribe_and_join(
          socket(UserSocket, "agent:test", %{}),
          AgentChannel,
          "agent:lobby"
        )

      ref =
        push(socket, "authenticate", %{
          "role_id" => role.role_id,
          "secret_id" => "wrong-secret-id"
        })

      assert_reply ref, :error, error_reply
      assert error_reply.reason == "invalid_credentials"
    end
  end

  describe "secret:request" do
    setup _context do
      # Use direct agent channel join for authenticated state
      socket = join_authenticated()
      {:ok, socket: socket}
    end

    test "requires authentication before requesting secrets" do
      # Join without authenticating (lobby = unauthenticated)
      {:ok, _response, socket} =
        subscribe_and_join(
          socket(UserSocket, "agent:test", %{}),
          AgentChannel,
          "agent:lobby"
        )

      ref =
        push(socket, "secret:request", %{
          "path" => "prod.db.postgres.password"
        })

      assert_reply ref, :error, error_reply
      assert error_reply.reason == "not_authenticated"
    end

    test "handles secret request for authenticated agent", %{socket: socket} do
      ref =
        push(socket, "secret:request", %{
          "path" => "prod.db.postgres.password"
        })

      # Will fail until we have actual secrets created - expect not_found or access_denied
      assert_reply ref, :error, error_reply
      assert error_reply.reason in ["secret_not_found", "access_denied"]
    end
  end

  describe "heartbeat" do
    setup _context do
      socket = join_authenticated()
      {:ok, socket: socket}
    end

    test "accepts heartbeat from authenticated agent", %{socket: socket} do
      ref = push(socket, "heartbeat", %{})

      assert_reply ref, :ok, reply
      assert reply.status == "alive"
    end

    test "requires authentication for heartbeat" do
      {:ok, _response, socket} =
        subscribe_and_join(
          socket(UserSocket, "agent:test", %{}),
          AgentChannel,
          "agent:lobby"
        )

      ref = push(socket, "heartbeat", %{})

      assert_reply ref, :error, error_reply
      assert error_reply.reason == "not_authenticated"
    end
  end

  describe "secret:renew" do
    setup _context do
      socket = join_authenticated()
      {:ok, socket: socket}
    end

    test "requires authentication", %{socket: _socket} do
      {:ok, _response, unauth_socket} =
        subscribe_and_join(
          socket(UserSocket, "agent:test", %{}),
          AgentChannel,
          "agent:lobby"
        )

      ref =
        push(unauth_socket, "secret:renew", %{
          "lease_id" => "test-lease-id"
        })

      assert_reply ref, :error, error_reply
      assert error_reply.reason == "not_authenticated"
    end

    test "handles lease renewal request", %{socket: socket} do
      ref =
        push(socket, "secret:renew", %{
          "lease_id" => "test-lease-id"
        })

      assert_reply ref, :ok, reply
      assert reply.lease_id == "test-lease-id"
      assert reply.renewed == true
      assert reply.lease_duration == 3600
    end
  end

  describe "connection lifecycle" do
    test "agent can disconnect cleanly" do
      socket = join_authenticated()

      # Leave the channel cleanly
      Process.flag(:trap_exit, true)
      leave(socket)
      Process.flag(:trap_exit, false)
    end
  end

  describe "security" do
    test "prevents command injection in secret paths" do
      socket = join_authenticated()

      # Try malicious paths
      malicious_paths = [
        "../../../etc/passwd",
        "prod.db.postgres'; DROP TABLE secrets; --",
        "prod.db.postgres\x00.password"
      ]

      for malicious_path <- malicious_paths do
        ref = push(socket, "secret:request", %{"path" => malicious_path})
        assert_reply ref, :error, _error_reply
      end
    end
  end

  describe "rate limiting" do
    @tag :slow
    test "allows reasonable request rate" do
      socket = join_authenticated()

      # Send multiple heartbeats in quick succession (should be allowed)
      for _i <- 1..10 do
        ref = push(socket, "heartbeat", %{})
        assert_reply ref, :ok, _reply
      end
    end
  end
end
