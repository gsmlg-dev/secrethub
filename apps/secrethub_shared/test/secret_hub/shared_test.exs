defmodule SecretHub.SharedTest do
  use ExUnit.Case
  doctest SecretHub.Shared

  test "greets the world" do
    assert SecretHub.Shared.hello() == :world
  end
end
