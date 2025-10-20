defmodule SecretHub.CoreTest do
  use ExUnit.Case
  doctest SecretHub.Core

  test "greets the world" do
    assert SecretHub.Core.hello() == :world
  end
end
