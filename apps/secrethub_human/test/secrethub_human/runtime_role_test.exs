defmodule SecretHub.Human.RuntimeRoleTest do
  use ExUnit.Case, async: true

  alias SecretHub.Human.RuntimeRole

  test "defaults to core in production" do
    assert RuntimeRole.resolve!(nil, :prod) == :core
  end

  test "defaults to all outside production" do
    assert RuntimeRole.resolve!(nil, :dev) == :all
    assert RuntimeRole.resolve!(nil, :test) == :all
  end

  test "accepts each supported role" do
    assert RuntimeRole.resolve!("all", :prod) == :all
    assert RuntimeRole.resolve!("core", :dev) == :core
    assert RuntimeRole.resolve!("human", :test) == :human
    assert RuntimeRole.resolve!("agent", :prod) == :agent
  end

  test "rejects unsupported roles" do
    assert_raise ArgumentError, ~r/invalid SECRETHUB_ROLE.*all, core, human, or agent/, fn ->
      RuntimeRole.resolve!("Human", :prod)
    end
  end
end
