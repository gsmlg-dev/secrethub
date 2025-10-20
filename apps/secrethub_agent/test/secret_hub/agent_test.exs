defmodule SecretHub.AgentTest do
  use ExUnit.Case
  doctest SecretHub.Agent

  test "greets the world" do
    assert SecretHub.Agent.hello() == :world
  end
end
