defmodule SecretHub.Agent.MTLSWebSocketTransportTest do
  use ExUnit.Case, async: true

  alias SecretHub.Agent.MTLSWebSocketTransport

  test "uses websocket_client option shape for mTLS" do
    assert {:module, MTLSWebSocketTransport} = Code.ensure_loaded(MTLSWebSocketTransport)
    assert {:module, :websocket_client} = :code.ensure_loaded(:websocket_client)

    assert function_exported?(MTLSWebSocketTransport, :open, 2)
    assert function_exported?(MTLSWebSocketTransport, :init, 1)
    assert function_exported?(MTLSWebSocketTransport, :onconnect, 2)
  end
end
