defmodule SecretHub.Web.AgentChannelTest do
  use SecretHub.WebWeb.ChannelCase

  alias SecretHub.Web.{AgentSocket, AgentChannel}

  setup do
    agent_id = "agent-test-01"

    # Simulate socket connection with agent_id assigned
    {:ok, socket} =
      connect(AgentSocket, %{}, connect_info: %{x_headers: [{"x-agent-id", agent_id}]})

    {:ok, %{socket: socket, agent_id: agent_id}}
  end

  describe "join/3" do
    test "successfully joins channel with matching agent_id", %{
      socket: socket,
      agent_id: agent_id
    } do
      {:ok, _reply, _socket} = subscribe_and_join(socket, AgentChannel, "agent:#{agent_id}", %{})

      # Should receive connected message
      assert_push "connected", %{agent_id: ^agent_id}
    end

    test "rejects join for mismatched agent_id", %{socket: socket} do
      assert {:error, %{reason: "unauthorized"}} =
               subscribe_and_join(socket, AgentChannel, "agent:different-agent", %{})
    end
  end

  describe "handle_in/3 - secrets:get_static" do
    setup %{socket: socket, agent_id: agent_id} do
      {:ok, _reply, socket} = subscribe_and_join(socket, AgentChannel, "agent:#{agent_id}", %{})
      {:ok, %{socket: socket}}
    end

    test "returns mock static secret", %{socket: socket} do
      ref = push(socket, "secrets:get_static", %{"path" => "prod.db.password"})

      assert_reply ref, :ok, %{
        value: "mock_secret_prod.db.password",
        version: 1,
        metadata: %{created_at: _, rotation_enabled: false}
      }
    end
  end

  describe "handle_in/3 - secrets:get_dynamic" do
    setup %{socket: socket, agent_id: agent_id} do
      {:ok, _reply, socket} = subscribe_and_join(socket, AgentChannel, "agent:#{agent_id}", %{})
      {:ok, %{socket: socket}}
    end

    test "returns mock dynamic credentials", %{socket: socket} do
      ref =
        push(socket, "secrets:get_dynamic", %{
          "role" => "prod.db.postgres.readonly",
          "ttl" => 3600
        })

      assert_reply ref, :ok, %{
        username: username,
        password: _password,
        lease_id: lease_id,
        lease_duration: 3600,
        expires_at: _expires_at
      }

      # Verify username format: v-{agent_id}-{role_suffix}-{random}
      assert username =~ ~r/^v-agent-test-01-readonly-[a-f0-9]+$/

      # Verify lease_id is a UUID
      assert {:ok, _} = Ecto.UUID.cast(lease_id)
    end
  end

  describe "handle_in/3 - lease:renew" do
    setup %{socket: socket, agent_id: agent_id} do
      {:ok, _reply, socket} = subscribe_and_join(socket, AgentChannel, "agent:#{agent_id}", %{})
      {:ok, %{socket: socket}}
    end

    test "renews lease successfully", %{socket: socket} do
      lease_id = Ecto.UUID.generate()
      ref = push(socket, "lease:renew", %{"lease_id" => lease_id})

      assert_reply ref, :ok, %{
        lease_id: ^lease_id,
        renewed_ttl: 3600,
        new_expires_at: _expires_at
      }
    end
  end

  describe "handle_in/3 - unknown event" do
    setup %{socket: socket, agent_id: agent_id} do
      {:ok, _reply, socket} = subscribe_and_join(socket, AgentChannel, "agent:#{agent_id}", %{})
      {:ok, %{socket: socket}}
    end

    test "returns error for unknown event", %{socket: socket} do
      ref = push(socket, "unknown:event", %{})

      assert_reply ref, :error, %{
        reason: "unknown_event",
        event: "unknown:event"
      }
    end
  end

  describe "server push notifications" do
    setup %{socket: socket, agent_id: agent_id} do
      {:ok, _reply, socket} = subscribe_and_join(socket, AgentChannel, "agent:#{agent_id}", %{})
      {:ok, %{socket: socket}}
    end

    test "can notify secret rotation", %{socket: socket} do
      payload = %{
        secret_path: "prod.db.password",
        new_version: 2,
        rotation_time: DateTime.utc_now()
      }

      AgentChannel.notify_secret_rotated(socket, payload)

      assert_push "secret:rotated", ^payload
    end

    test "can notify policy update", %{socket: socket} do
      payload = %{policy_id: "policy-123", changes: ["secrets_added"]}

      AgentChannel.notify_policy_updated(socket, payload)

      assert_push "policy:updated", ^payload
    end

    test "can notify certificate expiring", %{socket: socket} do
      payload = %{expires_at: "2025-11-01T00:00:00Z", days_remaining: 10}

      AgentChannel.notify_cert_expiring(socket, payload)

      assert_push "cert:expiring", ^payload
    end

    test "can notify lease revoked", %{socket: socket} do
      lease_id = Ecto.UUID.generate()
      payload = %{lease_id: lease_id, reason: "admin_revocation"}

      AgentChannel.notify_lease_revoked(socket, payload)

      assert_push "lease:revoked", ^payload
    end
  end
end
