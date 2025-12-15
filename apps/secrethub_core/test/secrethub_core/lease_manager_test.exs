defmodule SecretHub.Core.LeaseManagerTest do
  use SecretHub.Core.DataCase, async: false

  alias SecretHub.Core.LeaseManager
  alias SecretHub.Shared.Schemas.Lease

  setup do
    # Start LeaseManager for testing
    start_supervised!(LeaseManager)
    :ok
  end

  describe "create_lease/1" do
    test "creates a lease with valid attributes" do
      attrs = %{
        engine_type: "postgresql",
        role_name: "readonly",
        credentials: %{
          username: "v_readonly_abc123_1234567890",
          password: "secret123",
          metadata: %{host: "localhost", port: 5432, database: "testdb"}
        },
        ttl: 3600,
        metadata: %{config: %{}}
      }

      assert {:ok, lease} = LeaseManager.create_lease(attrs)
      assert lease.engine_type == "postgresql"
      assert lease.role_name == "readonly"
      assert lease.status == "active"
      assert lease.renewable == true
      assert is_binary(lease.id)

      # Verify it's in the manager's state
      assert {:ok, fetched_lease} = LeaseManager.get_lease(lease.id)
      assert fetched_lease.id == lease.id
    end

    test "fails with invalid attributes" do
      attrs = %{
        # Missing required fields
        ttl: 3600
      }

      assert {:error, changeset} = LeaseManager.create_lease(attrs)
      refute changeset.valid?
    end

    test "creates lease with calculated expiry time" do
      attrs = %{
        engine_type: "postgresql",
        role_name: "readonly",
        credentials: %{username: "test", password: "test"},
        ttl: 60,
        metadata: %{}
      }

      {:ok, lease} = LeaseManager.create_lease(attrs)

      # Expiry should be approximately 60 seconds from now
      expected_expiry = DateTime.add(DateTime.utc_now(), 60, :second)
      diff = DateTime.diff(lease.expires_at, expected_expiry)

      # Allow 2 second tolerance
      assert abs(diff) <= 2
    end
  end

  describe "get_lease/1" do
    test "returns lease when found" do
      {:ok, lease} = create_test_lease()

      assert {:ok, fetched} = LeaseManager.get_lease(lease.id)
      assert fetched.id == lease.id
      assert fetched.engine_type == lease.engine_type
    end

    test "returns error when lease not found" do
      assert {:error, :not_found} = LeaseManager.get_lease("non_existent")
    end
  end

  describe "list_active_leases/1" do
    test "lists all active leases" do
      {:ok, lease1} = create_test_lease(%{engine_type: "postgresql"})
      {:ok, lease2} = create_test_lease(%{engine_type: "redis"})

      leases = LeaseManager.list_active_leases()

      assert length(leases) >= 2
      lease_ids = Enum.map(leases, & &1.id)
      assert lease1.id in lease_ids
      assert lease2.id in lease_ids
    end

    test "filters leases by engine_type" do
      {:ok, _pg_lease} = create_test_lease(%{engine_type: "postgresql"})
      {:ok, redis_lease} = create_test_lease(%{engine_type: "redis"})

      leases = LeaseManager.list_active_leases(engine_type: "redis")

      assert length(leases) == 1
      assert hd(leases).id == redis_lease.id
    end

    test "filters leases by agent_id" do
      {:ok, _lease1} = create_test_lease(%{agent_id: "agent_1"})
      {:ok, lease2} = create_test_lease(%{agent_id: "agent_2"})

      leases = LeaseManager.list_active_leases(agent_id: "agent_2")

      assert length(leases) == 1
      assert hd(leases).id == lease2.id
    end

    test "respects limit parameter" do
      # Create 5 leases
      for _ <- 1..5, do: create_test_lease()

      leases = LeaseManager.list_active_leases(limit: 3)

      assert length(leases) <= 3
    end
  end

  describe "get_stats/0" do
    test "returns correct statistics" do
      {:ok, _} = create_test_lease(%{engine_type: "postgresql"})
      {:ok, _} = create_test_lease(%{engine_type: "postgresql"})
      {:ok, _} = create_test_lease(%{engine_type: "redis"})

      stats = LeaseManager.get_stats()

      assert stats.total_active >= 3
      assert stats.by_engine["postgresql"] >= 2
      assert stats.by_engine["redis"] >= 1
      assert is_integer(stats.expiring_soon)
    end

    test "counts expiring soon leases correctly" do
      # Create a lease expiring in 2 minutes
      {:ok, _} =
        create_test_lease(%{
          ttl: 120
        })

      # Create a lease expiring in 10 minutes
      {:ok, _} =
        create_test_lease(%{
          ttl: 600
        })

      stats = LeaseManager.get_stats()

      # At least one should be expiring soon (within 5 minutes)
      assert stats.expiring_soon >= 1
    end
  end

  describe "renew_lease/2" do
    @tag :skip
    # Skipped because it requires mocking the engine module
    test "renews lease and updates expiry time" do
      {:ok, lease} = create_test_lease(%{ttl: 60})

      # Sleep to let some time pass
      Process.sleep(100)

      assert {:ok, renewed} = LeaseManager.renew_lease(lease.id, 120)

      # Expiry should be extended
      assert DateTime.compare(renewed.expires_at, lease.expires_at) == :gt
    end

    test "returns error for non-existent lease" do
      assert {:error, :not_found} = LeaseManager.renew_lease("non_existent", 60)
    end

    @tag :skip
    test "returns error for expired lease" do
      # Create a lease that expires immediately
      {:ok, lease} = create_test_lease(%{ttl: 1})

      # Wait for expiry
      Process.sleep(1100)

      assert {:error, :expired} = LeaseManager.renew_lease(lease.id, 60)
    end
  end

  describe "revoke_lease/1" do
    @tag :skip
    # Skipped because it requires mocking the engine module
    test "revokes lease successfully" do
      {:ok, lease} = create_test_lease()

      assert :ok = LeaseManager.revoke_lease(lease.id)

      # Lease should no longer be found in active leases
      assert {:error, :not_found} = LeaseManager.get_lease(lease.id)
    end

    test "returns error for non-existent lease" do
      assert {:error, :not_found} = LeaseManager.revoke_lease("non_existent")
    end
  end

  # Helper functions

  defp create_test_lease(attrs \\ %{}) do
    default_attrs = %{
      engine_type: "postgresql",
      role_name: "test_role",
      credentials: %{
        username: "v_test_#{:rand.uniform(1000)}",
        password: "test_password",
        metadata: %{host: "localhost"}
      },
      ttl: 3600,
      metadata: %{config: %{}}
    }

    merged_attrs = Map.merge(default_attrs, attrs)
    LeaseManager.create_lease(merged_attrs)
  end
end
