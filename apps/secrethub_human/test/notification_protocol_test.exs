defmodule SecretHub.Human.NotificationProtocolTest do
  use ExUnit.Case, async: true
  alias SecretHub.HumanWeb.Bitwarden.SignalR

  test "MessagePack heartbeat matches the SignalR wire specification" do
    assert SignalR.heartbeat(:messagepack) == {:binary, <<2, 0x91, 6>>}
    assert SignalR.heartbeat(:json) == {:text, "{\"type\":6}\x1e"}
  end

  test "handshake accepts only supported version-one protocols" do
    assert {:ok, :messagepack} =
             SignalR.handshake(~s({"protocol":"messagepack","version":1}) <> <<0x1E>>)

    assert {:ok, :json} = SignalR.handshake(~s({"protocol":"json","version":1}) <> <<0x1E>>)

    assert {:error, :invalid_protocol} =
             SignalR.handshake(~s({"protocol":"unknown","version":1}) <> <<0x1E>>)

    assert {:error, :invalid_protocol} = SignalR.handshake(String.duplicate("a", 1025))
  end
end
