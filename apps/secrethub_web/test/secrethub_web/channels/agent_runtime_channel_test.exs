defmodule SecretHub.Web.AgentRuntimeChannelTest do
  use SecretHub.Web.ChannelCase, async: false

  alias SecretHub.Core.Agents.ConnectionManager
  alias SecretHub.Web.{AgentRuntimeChannel, AgentTrustedSocket}

  setup do
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

  test "registers runtime joins using socket assigns, not client supplied ids" do
    socket =
      socket(AgentTrustedSocket, "agent:test", %{
        agent_id: "agent-from-cert",
        certificate_serial: "serial-1",
        certificate_fingerprint: "fingerprint-1"
      })

    assert {:ok, reply, socket} =
             subscribe_and_join(socket, AgentRuntimeChannel, "agent:runtime", %{
               "agent_id" => "client-spoof"
             })

    assert reply.status == "accepted"
    assert reply.agent_id == "agent-from-cert"
    assert socket.assigns.agent_id == "agent-from-cert"
    assert ConnectionManager.connected?("agent-from-cert")
  end
end
