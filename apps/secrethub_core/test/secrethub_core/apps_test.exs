defmodule SecretHub.Core.AppsTest do
  use SecretHub.Core.DataCase, async: false

  alias SecretHub.Core.{Agents, Apps}

  # Apps require a real agent record for the foreign key constraint.
  defp create_agent do
    {:ok, agent} =
      Agents.register_agent(%{
        agent_id: "agent-apps-test-#{System.unique_integer([:positive])}",
        name: "Test Agent #{System.unique_integer([:positive])}",
        auth_method: "approle"
      })

    agent
  end

  defp register_app(overrides \\ %{}) do
    agent = create_agent()

    defaults = %{
      name: "app-#{System.unique_integer([:positive])}",
      agent_id: agent.id,
      description: "Test application"
    }

    Apps.register_app(Map.merge(defaults, overrides))
  end

  describe "register_app/1" do
    test "creates an application and returns a bootstrap token" do
      assert {:ok, %{app: app, token: token, token_expires_at: expires_at}} = register_app()
      assert app.status == "active"
      assert String.starts_with?(token, "hvs.")
      assert %DateTime{} = expires_at
    end

    test "fails when name is missing" do
      agent = create_agent()
      assert {:error, changeset} = Apps.register_app(%{agent_id: agent.id})
      assert {_msg, _} = changeset.errors[:name]
    end

    test "fails when agent_id is missing" do
      assert {:error, changeset} = Apps.register_app(%{name: "no-agent"})
      assert {_msg, _} = changeset.errors[:agent_id]
    end

    test "succeeds with a valid agent_id (FK not enforced at DB level)" do
      # The Application schema uses a belongs_to but there's no hard FK constraint,
      # so registration succeeds even with an unknown agent UUID.
      assert {:ok, %{app: app}} =
               Apps.register_app(%{
                 name: "orphan-app",
                 agent_id: Ecto.UUID.generate()
               })

      assert app.name == "orphan-app"
    end
  end

  describe "get_app/1" do
    test "returns app by UUID" do
      {:ok, %{app: app}} = register_app()
      assert {:ok, fetched} = Apps.get_app(app.id)
      assert fetched.id == app.id
    end

    test "returns not_found for unknown UUID" do
      assert {:error, :not_found} = Apps.get_app(Ecto.UUID.generate())
    end
  end

  describe "get_app_by_name/1" do
    test "returns app by name" do
      {:ok, %{app: app}} =
        register_app(%{name: "unique-app-name-#{System.unique_integer([:positive])}"})

      assert {:ok, fetched} = Apps.get_app_by_name(app.name)
      assert fetched.id == app.id
    end

    test "returns not_found for unknown name" do
      assert {:error, :not_found} = Apps.get_app_by_name("nonexistent-app-xyz")
    end
  end

  describe "list_apps/1" do
    test "returns all apps without filter" do
      {:ok, %{app: a1}} = register_app()
      {:ok, %{app: a2}} = register_app()
      {:ok, apps} = Apps.list_apps()
      ids = Enum.map(apps, & &1.id)
      assert a1.id in ids
      assert a2.id in ids
    end

    test "filters by agent_id" do
      agent = create_agent()
      {:ok, %{app: targeted}} = Apps.register_app(%{name: "targeted-app", agent_id: agent.id})
      {:ok, %{app: _other}} = register_app()

      {:ok, filtered} = Apps.list_apps(agent_id: agent.id)
      ids = Enum.map(filtered, & &1.id)
      assert targeted.id in ids
    end

    test "filters by status" do
      {:ok, %{app: app}} = register_app()
      Apps.suspend_app(app.id)

      {:ok, suspended} = Apps.list_apps(status: :suspended)
      assert Enum.any?(suspended, fn a -> a.id == app.id end)

      {:ok, active} = Apps.list_apps(status: :active)
      refute Enum.any?(active, fn a -> a.id == app.id end)
    end

    test "respects limit option" do
      for _ <- 1..3, do: register_app()
      {:ok, limited} = Apps.list_apps(limit: 1)
      assert length(limited) == 1
    end
  end

  describe "update_app/2" do
    test "updates app description" do
      {:ok, %{app: app}} = register_app()
      assert {:ok, updated} = Apps.update_app(app.id, %{description: "Updated description"})
      assert updated.description == "Updated description"
    end

    test "returns error for non-existent app" do
      assert {:error, :not_found} =
               Apps.update_app(Ecto.UUID.generate(), %{description: "ghost"})
    end
  end

  describe "suspend_app/1 and activate_app/1" do
    test "suspends an active app" do
      {:ok, %{app: app}} = register_app()
      assert {:ok, suspended} = Apps.suspend_app(app.id)
      assert suspended.status == "suspended"
    end

    test "reactivates a suspended app" do
      {:ok, %{app: app}} = register_app()
      {:ok, _} = Apps.suspend_app(app.id)
      assert {:ok, active} = Apps.activate_app(app.id)
      assert active.status == "active"
    end
  end

  describe "delete_app/1" do
    test "deletes an existing app" do
      {:ok, %{app: app}} = register_app()
      assert {:ok, _deleted} = Apps.delete_app(app.id)
      assert {:error, :not_found} = Apps.get_app(app.id)
    end

    test "returns error for non-existent app" do
      assert {:error, :not_found} = Apps.delete_app(Ecto.UUID.generate())
    end
  end

  describe "generate_bootstrap_token/1 and validate_bootstrap_token/1" do
    test "validates a freshly generated token" do
      {:ok, %{app: app}} = register_app()
      {:ok, token, _record} = Apps.generate_bootstrap_token(app.id)
      assert {:ok, app_id} = Apps.validate_bootstrap_token(token)
      assert app_id == app.id
    end

    test "rejects an already-used token" do
      {:ok, %{app: app}} = register_app()
      {:ok, token, _} = Apps.generate_bootstrap_token(app.id)
      {:ok, _} = Apps.validate_bootstrap_token(token)

      # Second use should fail
      assert {:error, :invalid_token} = Apps.validate_bootstrap_token(token)
    end

    test "rejects an invalid token" do
      assert {:error, :invalid_token} =
               Apps.validate_bootstrap_token("hvs.invalid_token_xyz")
    end
  end

  describe "get_stats/0" do
    test "returns app counts by status" do
      assert {:ok, stats} = Apps.get_stats()
      assert is_integer(stats.total)
      assert is_integer(stats.active)
      assert is_integer(stats.suspended)
    end
  end

  describe "cleanup_expired_tokens/0" do
    test "returns count of cleaned up tokens" do
      # Should succeed even with no expired tokens
      assert {:ok, count} = Apps.cleanup_expired_tokens()
      assert is_integer(count)
    end
  end
end
