defmodule SecretHub.Web.AgentChannelTest do
  use SecretHub.Web.ChannelCase

  alias SecretHub.Web.{AgentChannel, UserSocket}

  setup do
    # Connect socket - authentication happens at channel level, not socket level
    {:ok, socket} = connect(UserSocket, %{})

    {:ok, %{socket: socket}}
  end

  describe "join/3" do
    test "successfully joins agent:lobby", %{socket: socket} do
      {:ok, reply, socket} = subscribe_and_join(socket, AgentChannel, "agent:lobby", %{})

      assert reply.status == "connected"
      assert reply.authenticated == false
      assert socket.assigns.authenticated == false
      assert socket.assigns.agent_id == nil
    end

    test "rejects joining specific agent channels", %{socket: socket} do
      assert {:error, %{reason: "unauthorized"}} =
               subscribe_and_join(socket, AgentChannel, "agent:some-agent-id", %{})
    end
  end

  describe "handle_in/3 - unauthenticated" do
    setup %{socket: socket} do
      {:ok, _reply, socket} = subscribe_and_join(socket, AgentChannel, "agent:lobby", %{})
      {:ok, %{socket: socket}}
    end

    test "rejects secret:request without authentication", %{socket: socket} do
      ref = push(socket, "secret:request", %{"path" => "prod.db.password"})
      assert_reply ref, :error, %{reason: "not_authenticated"}
    end

    test "rejects heartbeat without authentication", %{socket: socket} do
      ref = push(socket, "heartbeat", %{})
      assert_reply ref, :error, %{reason: "not_authenticated"}
    end

    test "rejects secret:renew without authentication", %{socket: socket} do
      ref = push(socket, "secret:renew", %{"lease_id" => "test-lease"})
      assert_reply ref, :error, %{reason: "not_authenticated"}
    end

    test "returns error for invalid authentication payload", %{socket: socket} do
      ref = push(socket, "authenticate", %{"invalid" => "data"})
      assert_reply ref, :error, %{reason: "invalid_authentication_payload"}
    end

    test "returns error for unknown event", %{socket: socket} do
      ref = push(socket, "unknown:event", %{})
      assert_reply ref, :error, %{reason: "unknown_event"}
    end
  end
end
