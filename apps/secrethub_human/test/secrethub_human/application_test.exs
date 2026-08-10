defmodule SecretHub.Human.ApplicationTest do
  use ExUnit.Case, async: false

  alias SecretHub.Human.Application, as: HumanApplication

  setup do
    enabled = Application.fetch_env(:secrethub_human, :enabled)

    on_exit(fn ->
      case enabled do
        {:ok, value} -> Application.put_env(:secrethub_human, :enabled, value)
        :error -> Application.delete_env(:secrethub_human, :enabled)
      end
    end)
  end

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

  test "uses the configured enablement when no option is given" do
    Application.put_env(:secrethub_human, :enabled, false)

    assert HumanApplication.children() == []
  end

  test "defaults to enabled when enablement is not configured" do
    Application.delete_env(:secrethub_human, :enabled)

    assert HumanApplication.children() == [
             SecretHub.Human.Repo,
             {Phoenix.PubSub, name: SecretHub.Human.PubSub},
             SecretHub.HumanWeb.Endpoint
           ]
  end

  test "does not add the Human application to the Core runtime" do
    assert Application.load(:secrethub_core) in [
             :ok,
             {:error, {:already_loaded, :secrethub_core}}
           ]

    refute :secrethub_human in Application.spec(:secrethub_core, :applications)
  end
end
