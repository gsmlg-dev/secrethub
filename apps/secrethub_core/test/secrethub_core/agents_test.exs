defmodule SecretHub.Core.AgentsTest do
  use SecretHub.Core.DataCase, async: false

  alias SecretHub.Core.Agents

  defp unique_agent_id, do: "agent-test-#{System.unique_integer([:positive])}"

  defp register(overrides \\ []) do
    defaults = [
      agent_id: unique_agent_id(),
      name: "Test Agent #{System.unique_integer([:positive])}",
      auth_method: "approle"
    ]

    Agents.register_agent(Keyword.merge(defaults, overrides) |> Map.new())
  end

  describe "register_agent/1" do
    test "creates an agent in pending_bootstrap status" do
      {:ok, agent} = register()
      assert agent.status == :pending_bootstrap
      assert agent.agent_id != nil
    end

    test "fails when agent_id is missing" do
      assert {:error, changeset} = Agents.register_agent(%{name: "No ID"})
      assert {_msg, _} = changeset.errors[:agent_id]
    end

    test "fails when name is missing" do
      assert {:error, changeset} =
               Agents.register_agent(%{agent_id: unique_agent_id()})

      assert {_msg, _} = changeset.errors[:name]
    end

    test "fails with duplicate agent_id" do
      id = unique_agent_id()
      assert {:ok, _} = register(agent_id: id, name: "First")
      assert {:error, changeset} = register(agent_id: id, name: "Second")
      assert {_msg, _} = changeset.errors[:agent_id]
    end
  end

  describe "get_agent/1" do
    test "returns agent by agent_id string" do
      {:ok, created} = register()
      fetched = Agents.get_agent(created.agent_id)
      assert fetched.id == created.id
    end

    test "returns nil for unknown agent_id" do
      assert nil == Agents.get_agent("agent-does-not-exist-xyz")
    end
  end

  describe "get_agent!/1" do
    test "returns agent by database UUID" do
      {:ok, created} = register()
      fetched = Agents.get_agent!(created.id)
      assert fetched.agent_id == created.agent_id
    end

    test "raises for unknown UUID" do
      assert_raise Ecto.NoResultsError, fn ->
        Agents.get_agent!(Ecto.UUID.generate())
      end
    end
  end

  describe "generate_approle_credentials/1" do
    test "generates role_id and secret_id for registered agent" do
      {:ok, agent} = register()
      assert {:ok, role_id, secret_id} = Agents.generate_approle_credentials(agent.id)
      assert is_binary(role_id)
      assert is_binary(secret_id)
    end

    test "returns error for unknown agent database ID" do
      assert {:error, "Agent not found"} =
               Agents.generate_approle_credentials(Ecto.UUID.generate())
    end
  end

  describe "authenticate_with_approle/2" do
    test "authenticates agent with valid credentials and activates it" do
      {:ok, agent} = register()
      {:ok, role_id, secret_id} = Agents.generate_approle_credentials(agent.id)

      assert {:ok, %{certificate: cert, agent: active_agent}} =
               Agents.authenticate_with_approle(role_id, secret_id)

      assert active_agent.status == :active
      assert is_binary(cert.fingerprint)
    end

    test "returns error for invalid credentials" do
      assert {:error, "Invalid credentials"} =
               Agents.authenticate_with_approle(Ecto.UUID.generate(), Ecto.UUID.generate())
    end

    test "rejects revoked agent" do
      {:ok, agent} = register()
      {:ok, role_id, secret_id} = Agents.generate_approle_credentials(agent.id)
      Agents.revoke_agent_certificate(agent.id)

      assert {:error, "Agent has been revoked"} =
               Agents.authenticate_with_approle(role_id, secret_id)
    end
  end

  describe "update_heartbeat/1" do
    test "updates last_heartbeat_at for active agent" do
      {:ok, agent} = register()

      assert {:ok, updated} = Agents.update_heartbeat(agent.agent_id)
      assert updated.id == agent.id
    end

    test "returns error for unknown agent" do
      assert {:error, "Agent not found"} = Agents.update_heartbeat("agent-ghost-xyz")
    end
  end

  describe "mark_disconnected/1" do
    test "sets agent status to disconnected" do
      {:ok, agent} = register()
      {:ok, role_id, secret_id} = Agents.generate_approle_credentials(agent.id)
      {:ok, %{agent: active}} = Agents.authenticate_with_approle(role_id, secret_id)
      assert active.status == :active

      assert {:ok, disconnected} = Agents.mark_disconnected(agent.agent_id)
      assert disconnected.status == :disconnected
    end

    test "returns error for unknown agent" do
      assert {:error, "Agent not found"} = Agents.mark_disconnected("agent-ghost-xyz")
    end
  end

  describe "suspend_agent/2" do
    test "suspends an existing agent" do
      {:ok, agent} = register()
      assert {:ok, _} = Agents.suspend_agent(agent.agent_id, "Testing suspension")
      refetched = Agents.get_agent(agent.agent_id)
      assert refetched.status == :suspended
    end

    test "returns error for unknown agent" do
      assert {:error, "Agent not found"} = Agents.suspend_agent("agent-ghost-xyz")
    end
  end

  describe "revoke_agent/2" do
    test "revokes an existing agent" do
      {:ok, agent} = register()
      assert {:ok, _} = Agents.revoke_agent(agent.agent_id, "Test revocation")
      refetched = Agents.get_agent(agent.agent_id)
      assert refetched.status == :revoked
    end

    test "returns error for unknown agent" do
      assert {:error, "Agent not found"} = Agents.revoke_agent("agent-ghost-xyz")
    end
  end

  describe "list_agents/1" do
    test "returns all agents without filter" do
      {:ok, a1} = register()
      {:ok, a2} = register()
      all_agents = Agents.list_agents()
      ids = Enum.map(all_agents, & &1.agent_id)
      assert a1.agent_id in ids
      assert a2.agent_id in ids
    end

    test "filters by status" do
      {:ok, agent} = register()
      pending = Agents.list_agents(%{status: :pending_bootstrap})
      assert Enum.any?(pending, fn a -> a.agent_id == agent.agent_id end)

      active = Agents.list_agents(%{status: :active})
      refute Enum.any?(active, fn a -> a.agent_id == agent.agent_id end)
    end

    test "filters by search term on name" do
      unique_name = "SearchableAgent#{System.unique_integer([:positive])}"
      {:ok, _} = register(name: unique_name)
      results = Agents.list_agents(%{search: unique_name})
      assert Enum.any?(results, fn a -> a.name == unique_name end)
    end
  end

  describe "update_agent_config/2" do
    test "updates the agent config map" do
      {:ok, agent} = register()
      config = %{"log_level" => "debug", "max_connections" => 10}
      assert {:ok, updated} = Agents.update_agent_config(agent.agent_id, config)
      assert updated.config == config
    end

    test "returns error for unknown agent" do
      assert {:error, "Agent not found"} =
               Agents.update_agent_config("agent-ghost-xyz", %{})
    end
  end

  describe "get_agent_stats/0" do
    test "returns aggregate counts by status" do
      stats = Agents.get_agent_stats()
      assert is_integer(stats.total)
      assert is_integer(stats.active)
      assert is_integer(stats.pending_bootstrap)
      assert is_integer(stats.suspended)
      assert is_integer(stats.revoked)
    end
  end

  describe "revoke_agent_certificate/2" do
    test "revokes agent by database ID" do
      {:ok, agent} = register()
      assert {:ok, revoked} = Agents.revoke_agent_certificate(agent.id)
      assert revoked.status == :revoked
    end

    test "returns error for unknown database ID" do
      assert {:error, "Agent not found"} =
               Agents.revoke_agent_certificate(Ecto.UUID.generate())
    end
  end
end
