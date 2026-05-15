defmodule SecretHub.Agent.ConnectionProtocolTest do
  use ExUnit.Case, async: true

  alias SecretHub.Agent.Connection

  test "uses the normalized trusted runtime topic" do
    assert Connection.runtime_topic() == "agent:runtime"
  end

  test "uses the server runtime event vocabulary" do
    assert Connection.runtime_event(:get_static_secret) == "secret:read"
    assert Connection.runtime_event(:get_dynamic_secret) == "secret:read"
    assert Connection.runtime_event(:renew_lease) == "secret:lease_renew"
    assert Connection.runtime_event(:heartbeat) == "agent:heartbeat"
  end
end
