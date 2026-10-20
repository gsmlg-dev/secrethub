defmodule SecretHub.Web.UnifiedAgentSupervisionTest do
  use ExUnit.Case, async: true

  test "web supervision has no separate machine endpoint" do
    child_ids =
      SecretHub.Web.Supervisor
      |> Supervisor.which_children()
      |> Enum.map(&elem(&1, 0))

    assert SecretHub.Web.Endpoint in child_ids
    refute SecretHub.Web.MachineEndpoint in child_ids
    assert is_pid(Process.whereis(SecretHub.Web.MachineEndpoint))
    assert SecretHub.Web.MachineEndpoint.config(:server) == false
  end
end
