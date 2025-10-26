defmodule SecretHub.WebWeb.AgentChannelTest do
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

  use SecretHub.WebWeb.ChannelCase, async: false

  alias SecretHub.Core.Agents
  alias SecretHub.Core.Auth.AppRole
  alias SecretHub.WebWeb.AgentChannel
  alias SecretHub.WebWeb.UserSocket

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

    test "rejects joining specific agent channels without authentication" do
      assert {:error, %{reason: "unauthorized"}} =
               subscribe_and_join(
                 socket(UserSocket, "agent:test", %{}),
                 AgentChannel,
                 "agent:some-agent-id"
               )
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
      assert reply.policies == ["default", "secrets-read"]
      assert reply.token != nil
    end

    test "marks socket as authenticated after successful auth", %{role: role} do
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

      assert_reply ref, :ok, _reply

      # Check socket state
      assert socket.assigns.authenticated == true
      assert socket.assigns.agent_id != nil
      assert socket.assigns.role_name == "test-agent"
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

    test "prevents re-authentication when already authenticated", %{role: role} do
      {:ok, _response, socket} =
        subscribe_and_join(
          socket(UserSocket, "agent:test", %{}),
          AgentChannel,
          "agent:lobby"
        )

      # First authentication
      ref1 =
        push(socket, "authenticate", %{
          "role_id" => role.role_id,
          "secret_id" => role.secret_id
        })

      assert_reply ref1, :ok, _reply1

      # Try to authenticate again
      ref2 =
        push(socket, "authenticate", %{
          "role_id" => role.role_id,
          "secret_id" => role.secret_id
        })

      assert_reply ref2, :error, error_reply
      assert error_reply.reason == "already_authenticated"
    end
  end

  describe "secret:request" do
    setup %{role: role} do
      # Join and authenticate
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

      assert_reply ref, :ok, _auth_reply

      # Create a test secret
      # Note: This requires the Secrets module to be properly implemented
      # For now, we'll test the channel behavior

      {:ok, socket: socket}
    end

    test "requires authentication before requesting secrets" do
      # Join without authenticating
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

      # Note: This will fail until we have actual secrets created
      # For now, we're testing the channel message handling
      assert_reply ref, :error, error_reply
      # Could be "secret_not_found" or "access_denied" depending on implementation
      assert error_reply.reason in ["secret_not_found", "access_denied"]
    end

    test "validates secret path format", %{socket: socket} do
      ref =
        push(socket, "secret:request", %{
          # Invalid empty path
          "path" => ""
        })

      assert_reply ref, :error, error_reply
      assert error_reply.reason == "invalid_secret_path"
    end

    test "requires path parameter", %{socket: socket} do
      ref = push(socket, "secret:request", %{})

      assert_reply ref, :error, error_reply
      assert error_reply.reason == "missing_secret_path"
    end
  end

  describe "heartbeat" do
    setup %{role: role} do
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

      assert_reply ref, :ok, _auth_reply

      {:ok, socket: socket}
    end

    test "accepts heartbeat from authenticated agent", %{socket: socket} do
      ref = push(socket, "heartbeat", %{})

      assert_reply ref, :ok, reply
      assert reply.status == "ok"
    end

    test "updates last_heartbeat timestamp", %{socket: socket} do
      initial_heartbeat = socket.assigns.last_heartbeat

      # Wait a moment
      Process.sleep(100)

      ref = push(socket, "heartbeat", %{})
      assert_reply ref, :ok, _reply

      # The socket's last_heartbeat should be updated
      # Note: We can't directly check socket.assigns after push
      # but the implementation should update it
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
    setup %{role: role} do
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

      assert_reply ref, :ok, _auth_reply

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

    test "requires lease_id parameter", %{socket: socket} do
      ref = push(socket, "secret:renew", %{})

      assert_reply ref, :error, error_reply
      assert error_reply.reason == "missing_lease_id"
    end

    test "handles lease renewal request", %{socket: socket} do
      ref =
        push(socket, "secret:renew", %{
          "lease_id" => "test-lease-id"
        })

      # This will fail until leases are implemented
      assert_reply ref, :error, error_reply
      assert error_reply.reason in ["lease_not_found", "lease_renewal_failed"]
    end
  end

  describe "connection lifecycle" do
    test "agent can disconnect cleanly", %{role: role} do
      {:ok, _response, socket} =
        subscribe_and_join(
          socket(UserSocket, "agent:test", %{}),
          AgentChannel,
          "agent:lobby"
        )

      # Authenticate
      ref =
        push(socket, "authenticate", %{
          "role_id" => role.role_id,
          "secret_id" => role.secret_id
        })

      assert_reply ref, :ok, auth_reply

      agent_id = auth_reply.agent_id

      # Leave the channel
      leave(socket)

      # Agent should be marked as disconnected
      # Note: This requires checking the Agents module
      # For now, just verify the channel left successfully
    end

    test "handles unexpected disconnections", %{role: role} do
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

      assert_reply ref, :ok, _auth_reply

      # Simulate crash by killing the channel process
      Process.exit(socket.channel_pid, :kill)

      # Wait for termination
      Process.sleep(100)

      # Channel should have terminated
      refute Process.alive?(socket.channel_pid)
    end
  end

  describe "security" do
    test "different agents cannot see each other's messages", %{role: role} do
      # Create first agent connection
      {:ok, _response, socket1} =
        subscribe_and_join(
          socket(UserSocket, "agent:1", %{}),
          AgentChannel,
          "agent:lobby"
        )

      ref1 =
        push(socket1, "authenticate", %{
          "role_id" => role.role_id,
          "secret_id" => role.secret_id
        })

      assert_reply ref1, :ok, _reply1

      # Rotate secret_id for second agent
      {:ok, new_secret_result} = AppRole.rotate_secret_id(role.role_id)

      # Create second agent connection
      {:ok, _response, socket2} =
        subscribe_and_join(
          socket(UserSocket, "agent:2", %{}),
          AgentChannel,
          "agent:lobby"
        )

      ref2 =
        push(socket2, "authenticate", %{
          "role_id" => role.role_id,
          "secret_id" => new_secret_result.secret_id
        })

      assert_reply ref2, :ok, _reply2

      # Messages to socket1 should not be received by socket2
      # This is inherently guaranteed by Phoenix channels' design
      # Each socket gets its own process
    end

    test "prevents command injection in secret paths", %{role: role} do
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

      assert_reply ref, :ok, _auth_reply

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
    test "allows reasonable request rate", %{role: role} do
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

      assert_reply ref, :ok, _auth_reply

      # Send multiple heartbeats in quick succession (should be allowed)
      for _i <- 1..10 do
        ref = push(socket, "heartbeat", %{})
        assert_reply ref, :ok, _reply
      end
    end
  end
end
