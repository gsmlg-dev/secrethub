defmodule SecretHub.Human.ApplicationTest do
  use ExUnit.Case, async: true

  alias SecretHub.Human.Application, as: HumanApplication

  test "starts the Human supervision tree when enabled" do
    assert HumanApplication.children(enabled: true) == [
             SecretHub.Human.Repo,
             {Phoenix.PubSub, name: SecretHub.Human.PubSub},
             SecretHub.HumanWeb.Endpoint
           ]
  end

  test "starts no Human children when disabled" do
    assert HumanApplication.children(enabled: false) == []
  end

  test "does not add the Human application to the Core runtime" do
    assert Application.load(:secrethub_core) in [
             :ok,
             {:error, {:already_loaded, :secrethub_core}}
           ]

    refute :secrethub_human in Application.spec(:secrethub_core, :applications)
  end
end
