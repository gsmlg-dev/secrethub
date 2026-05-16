defmodule SecretHub.Web.AgentChannelIntegrationTest do
  @moduledoc """
  Integration tests for the legacy Agent WebSocket channel.

  Runtime agent traffic now uses the trusted mTLS socket. This channel only
  accepts unauthenticated lobby joins and rejects legacy runtime authentication.
  """

  use SecretHub.Web.ChannelCase, async: false

  alias SecretHub.Web.AgentChannel
  alias SecretHub.Web.UserSocket

  defp join_lobby do
    subscribe_and_join(
      socket(UserSocket, "agent:test", %{}),
      AgentChannel,
      "agent:lobby"
    )
  end

  describe "join/3" do
    test "allows agents to join the lobby" do
      {:ok, response, socket} = join_lobby()

      assert response.status == "connected"
      assert response.authenticated == false
      assert socket.assigns.authenticated == false
      assert socket.assigns.agent_id == nil
      assert socket.assigns.last_heartbeat != nil
    end

    test "rejects direct agent channel joins without trusted mTLS identity" do
      assert {:error, %{reason: "trusted_runtime_requires_mtls"}} =
               subscribe_and_join(
                 socket(UserSocket, "agent:test", %{}),
                 AgentChannel,
                 "agent:some-agent-id"
               )
    end
  end

  describe "legacy authentication" do
    test "rejects AppRole authentication over the legacy channel" do
      {:ok, _response, socket} = join_lobby()

      ref =
        push(socket, "authenticate", %{
          "role_id" => "role-id",
          "secret_id" => "secret-id"
        })

      assert_reply ref, :error, %{reason: "trusted_runtime_requires_mtls"}
    end

    test "rejects certificate requests over the legacy channel" do
      {:ok, _response, socket} = join_lobby()

      ref = push(socket, "certificate:request", %{"csr" => "csr"})

      assert_reply ref, :error, %{reason: "trusted_runtime_requires_mtls"}
    end
  end

  describe "unauthenticated lobby messages" do
    test "requires authentication before requesting secrets" do
      {:ok, _response, socket} = join_lobby()

      ref =
        push(socket, "secret:request", %{
          "path" => "prod.db.postgres.password"
        })

      assert_reply ref, :error, %{reason: "not_authenticated"}
    end

    test "requires authentication for heartbeat" do
      {:ok, _response, socket} = join_lobby()

      ref = push(socket, "heartbeat", %{})

      assert_reply ref, :error, %{reason: "not_authenticated"}
    end

    test "requires authentication before renewing leases" do
      {:ok, _response, socket} = join_lobby()

      ref = push(socket, "secret:renew", %{"lease_id" => "test-lease-id"})

      assert_reply ref, :error, %{reason: "not_authenticated"}
    end

    test "returns an error for unknown events" do
      {:ok, _response, socket} = join_lobby()

      ref = push(socket, "unknown:event", %{})

      assert_reply ref, :error, %{reason: "unknown_event"}
    end
  end
end
