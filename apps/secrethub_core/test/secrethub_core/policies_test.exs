defmodule SecretHub.Core.PoliciesTest do
  @moduledoc """
  Tests for policy condition evaluation in SecretHub.Core.Policies.

  The private condition evaluation functions (evaluate_time_condition,
  evaluate_ip_condition, evaluate_ttl_condition, matches_glob_pattern?, etc.)
  are tested indirectly through the public `evaluate_access/4` API.
  """

  use SecretHub.Core.DataCase, async: false

  alias SecretHub.Core.Policies

  # Unique suffix generator for policy/entity names
  defp unique_suffix, do: :rand.uniform(1_000_000)

  # Creates a policy bound to the given entity_id and returns {policy, entity_id}.
  defp create_bound_policy(policy_doc, opts \\ []) do
    suffix = unique_suffix()
    entity_id = Keyword.get(opts, :entity_id, "test-entity-#{suffix}")
    policy_name = Keyword.get(opts, :policy_name, "test-policy-#{suffix}")
    deny = Keyword.get(opts, :deny_policy, false)

    {:ok, policy} =
      Policies.create_policy(%{
        name: policy_name,
        description: "Test policy",
        policy_document: policy_doc,
        entity_bindings: [entity_id],
        deny_policy: deny
      })

    {policy, entity_id}
  end

  describe "glob pattern matching via evaluate_access/4" do
    test "prod.db.* matches prod.db.password" do
      {_policy, entity_id} =
        create_bound_policy(%{
          "version" => "1.0",
          "allowed_secrets" => ["prod.db.*"],
          "allowed_operations" => ["read"]
        })

      assert {:ok, _policy} =
               Policies.evaluate_access(entity_id, "prod.db.password", "read")
    end

    test "prod.db.* does not match staging.db.password" do
      {_policy, entity_id} =
        create_bound_policy(%{
          "version" => "1.0",
          "allowed_secrets" => ["prod.db.*"],
          "allowed_operations" => ["read"]
        })

      assert {:error, _reason} =
               Policies.evaluate_access(entity_id, "staging.db.password", "read")
    end

    test "*.password matches any path ending in .password" do
      {_policy, entity_id} =
        create_bound_policy(%{
          "version" => "1.0",
          "allowed_secrets" => ["*.password"],
          "allowed_operations" => ["read"]
        })

      assert {:ok, _} =
               Policies.evaluate_access(entity_id, "prod.db.password", "read")

      assert {:ok, _} =
               Policies.evaluate_access(entity_id, "staging.api.password", "read")
    end

    test "prod.*.password matches prod.db.password but not staging.db.password" do
      {_policy, entity_id} =
        create_bound_policy(%{
          "version" => "1.0",
          "allowed_secrets" => ["prod.*.password"],
          "allowed_operations" => ["read"]
        })

      assert {:ok, _} =
               Policies.evaluate_access(entity_id, "prod.db.password", "read")

      assert {:error, _} =
               Policies.evaluate_access(entity_id, "staging.db.password", "read")
    end

    test "exact path matches exactly" do
      {_policy, entity_id} =
        create_bound_policy(%{
          "version" => "1.0",
          "allowed_secrets" => ["prod.db.postgres.password"],
          "allowed_operations" => ["read"]
        })

      assert {:ok, _} =
               Policies.evaluate_access(entity_id, "prod.db.postgres.password", "read")

      assert {:error, _} =
               Policies.evaluate_access(entity_id, "prod.db.mysql.password", "read")
    end

    test "empty allowed_secrets list denies all access" do
      {_policy, entity_id} =
        create_bound_policy(%{
          "version" => "1.0",
          "allowed_secrets" => [],
          "allowed_operations" => ["read"]
        })

      assert {:error, _} =
               Policies.evaluate_access(entity_id, "anything", "read")
    end
  end

  describe "operation-level permissions via evaluate_access/4" do
    test "allowed operation succeeds" do
      {_policy, entity_id} =
        create_bound_policy(%{
          "version" => "1.0",
          "allowed_secrets" => ["app.*"],
          "allowed_operations" => ["read", "renew"]
        })

      assert {:ok, _} = Policies.evaluate_access(entity_id, "app.secret", "read")
      assert {:ok, _} = Policies.evaluate_access(entity_id, "app.secret", "renew")
    end

    test "disallowed operation is denied" do
      {_policy, entity_id} =
        create_bound_policy(%{
          "version" => "1.0",
          "allowed_secrets" => ["app.*"],
          "allowed_operations" => ["read"]
        })

      assert {:error, _} =
               Policies.evaluate_access(entity_id, "app.secret", "write")

      assert {:error, _} =
               Policies.evaluate_access(entity_id, "app.secret", "delete")
    end
  end

  describe "IP range condition via evaluate_access/4" do
    test "access granted when client IP matches an exact allowed IP" do
      {_policy, entity_id} =
        create_bound_policy(%{
          "version" => "1.0",
          "allowed_secrets" => ["secure.*"],
          "allowed_operations" => ["read"],
          "conditions" => %{
            "ip_ranges" => ["10.0.1.50", "192.168.1.100"]
          }
        })

      assert {:ok, _} =
               Policies.evaluate_access(entity_id, "secure.key", "read", %{
                 ip_address: "10.0.1.50"
               })

      assert {:ok, _} =
               Policies.evaluate_access(entity_id, "secure.key", "read", %{
                 ip_address: "192.168.1.100"
               })
    end

    test "access denied when client IP does not match any allowed IP" do
      {_policy, entity_id} =
        create_bound_policy(%{
          "version" => "1.0",
          "allowed_secrets" => ["secure.*"],
          "allowed_operations" => ["read"],
          "conditions" => %{
            "ip_ranges" => ["10.0.1.50", "192.168.1.100"]
          }
        })

      assert {:error, _} =
               Policies.evaluate_access(entity_id, "secure.key", "read", %{
                 ip_address: "172.16.5.10"
               })
    end

    test "access granted when no IP is provided in context (fail-open)" do
      {_policy, entity_id} =
        create_bound_policy(%{
          "version" => "1.0",
          "allowed_secrets" => ["secure.*"],
          "allowed_operations" => ["read"],
          "conditions" => %{
            "ip_ranges" => ["10.0.1.50"]
          }
        })

      # No ip_address in context => allowed (fail-open behavior)
      assert {:ok, _} =
               Policies.evaluate_access(entity_id, "secure.key", "read", %{})
    end

    test "exact IP match is strict - similar IPs do not match" do
      {_policy, entity_id} =
        create_bound_policy(%{
          "version" => "1.0",
          "allowed_secrets" => ["secure.*"],
          "allowed_operations" => ["read"],
          "conditions" => %{
            "ip_ranges" => ["192.168.1.100"]
          }
        })

      assert {:ok, _} =
               Policies.evaluate_access(entity_id, "secure.key", "read", %{
                 ip_address: "192.168.1.100"
               })

      assert {:error, _} =
               Policies.evaluate_access(entity_id, "secure.key", "read", %{
                 ip_address: "192.168.1.101"
               })
    end

    test "CIDR notation matches IPs within the subnet" do
      {_policy, entity_id} =
        create_bound_policy(%{
          "version" => "1.0",
          "allowed_secrets" => ["secure.*"],
          "allowed_operations" => ["read"],
          "conditions" => %{
            "ip_ranges" => ["10.0.0.0/8"]
          }
        })

      # 10.0.1.50 is within 10.0.0.0/8
      assert {:ok, _} =
               Policies.evaluate_access(entity_id, "secure.key", "read", %{
                 ip_address: "10.0.1.50"
               })

      # 10.255.255.255 is within 10.0.0.0/8
      assert {:ok, _} =
               Policies.evaluate_access(entity_id, "secure.key", "read", %{
                 ip_address: "10.255.255.255"
               })

      # 11.0.0.1 is NOT within 10.0.0.0/8
      assert {:error, _} =
               Policies.evaluate_access(entity_id, "secure.key", "read", %{
                 ip_address: "11.0.0.1"
               })
    end

    test "CIDR /24 subnet matching" do
      {_policy, entity_id} =
        create_bound_policy(%{
          "version" => "1.0",
          "allowed_secrets" => ["secure.*"],
          "allowed_operations" => ["read"],
          "conditions" => %{
            "ip_ranges" => ["192.168.1.0/24"]
          }
        })

      assert {:ok, _} =
               Policies.evaluate_access(entity_id, "secure.key", "read", %{
                 ip_address: "192.168.1.100"
               })

      assert {:error, _} =
               Policies.evaluate_access(entity_id, "secure.key", "read", %{
                 ip_address: "192.168.2.1"
               })
    end
  end

  describe "max TTL condition via evaluate_access/4" do
    test "access granted when requested TTL is within limit" do
      {_policy, entity_id} =
        create_bound_policy(%{
          "version" => "1.0",
          "allowed_secrets" => ["db.*"],
          "allowed_operations" => ["read"],
          "conditions" => %{
            "max_ttl" => "3600"
          }
        })

      assert {:ok, _} =
               Policies.evaluate_access(entity_id, "db.creds", "read", %{ttl: 1800})
    end

    test "access granted when requested TTL equals max TTL exactly" do
      {_policy, entity_id} =
        create_bound_policy(%{
          "version" => "1.0",
          "allowed_secrets" => ["db.*"],
          "allowed_operations" => ["read"],
          "conditions" => %{
            "max_ttl" => "3600"
          }
        })

      assert {:ok, _} =
               Policies.evaluate_access(entity_id, "db.creds", "read", %{ttl: 3600})
    end

    test "access denied when requested TTL exceeds limit" do
      {_policy, entity_id} =
        create_bound_policy(%{
          "version" => "1.0",
          "allowed_secrets" => ["db.*"],
          "allowed_operations" => ["read"],
          "conditions" => %{
            "max_ttl" => "3600"
          }
        })

      assert {:error, _} =
               Policies.evaluate_access(entity_id, "db.creds", "read", %{ttl: 7200})
    end

    test "access granted when no TTL in context (defaults to 0)" do
      {_policy, entity_id} =
        create_bound_policy(%{
          "version" => "1.0",
          "allowed_secrets" => ["db.*"],
          "allowed_operations" => ["read"],
          "conditions" => %{
            "max_ttl" => "3600"
          }
        })

      # No ttl in context defaults to 0, which is <= 3600
      assert {:ok, _} =
               Policies.evaluate_access(entity_id, "db.creds", "read", %{})
    end
  end

  describe "time-of-day condition via evaluate_access/4" do
    test "access granted when current time is within the allowed window (full day)" do
      # Use 00:00-23:59 which always passes
      {_policy, entity_id} =
        create_bound_policy(%{
          "version" => "1.0",
          "allowed_secrets" => ["app.*"],
          "allowed_operations" => ["read"],
          "conditions" => %{
            "time_of_day" => "00:00-23:59"
          }
        })

      assert {:ok, _} =
               Policies.evaluate_access(entity_id, "app.config", "read")
    end

    test "access denied when current time is outside a narrow past window" do
      # Create a window guaranteed to be in the past (or if time happens to be
      # in the window, this test gracefully passes). We use a 1-minute window
      # 12 hours from now to make collision extremely unlikely.
      current_hour = Time.utc_now().hour
      # Pick a 1-minute window 12 hours from now (mod 24)
      start_hour = rem(current_hour + 12, 24)
      end_hour = start_hour

      start_str =
        "#{String.pad_leading(Integer.to_string(start_hour), 2, "0")}:00"

      end_str =
        "#{String.pad_leading(Integer.to_string(end_hour), 2, "0")}:01"

      {_policy, entity_id} =
        create_bound_policy(%{
          "version" => "1.0",
          "allowed_secrets" => ["app.*"],
          "allowed_operations" => ["read"],
          "conditions" => %{
            "time_of_day" => "#{start_str}-#{end_str}"
          }
        })

      assert {:error, _} =
               Policies.evaluate_access(entity_id, "app.config", "read")
    end
  end

  describe "multiple conditions via evaluate_access/4" do
    test "all conditions must be satisfied (Enum.all? behavior)" do
      {_policy, entity_id} =
        create_bound_policy(%{
          "version" => "1.0",
          "allowed_secrets" => ["multi.*"],
          "allowed_operations" => ["read"],
          "conditions" => %{
            "time_of_day" => "00:00-23:59",
            "max_ttl" => "3600",
            "ip_ranges" => ["10.0.1.5"]
          }
        })

      # All conditions met: time is within 00:00-23:59, TTL < 3600, IP matches exactly
      assert {:ok, _} =
               Policies.evaluate_access(entity_id, "multi.secret", "read", %{
                 ttl: 1800,
                 ip_address: "10.0.1.5"
               })
    end

    test "fails when one condition is not met (TTL exceeded)" do
      {_policy, entity_id} =
        create_bound_policy(%{
          "version" => "1.0",
          "allowed_secrets" => ["multi.*"],
          "allowed_operations" => ["read"],
          "conditions" => %{
            "time_of_day" => "00:00-23:59",
            "max_ttl" => "3600",
            "ip_ranges" => ["10.0.1.5"]
          }
        })

      # TTL exceeds limit even though IP and time are fine
      assert {:error, _} =
               Policies.evaluate_access(entity_id, "multi.secret", "read", %{
                 ttl: 7200,
                 ip_address: "10.0.1.5"
               })
    end

    test "fails when one condition is not met (IP not matching)" do
      {_policy, entity_id} =
        create_bound_policy(%{
          "version" => "1.0",
          "allowed_secrets" => ["multi.*"],
          "allowed_operations" => ["read"],
          "conditions" => %{
            "time_of_day" => "00:00-23:59",
            "max_ttl" => "3600",
            "ip_ranges" => ["10.0.1.5"]
          }
        })

      # IP doesn't match even though TTL and time are fine
      assert {:error, _} =
               Policies.evaluate_access(entity_id, "multi.secret", "read", %{
                 ttl: 1800,
                 ip_address: "172.16.0.1"
               })
    end
  end

  describe "unknown conditions via evaluate_access/4" do
    test "unknown condition types are ignored (fail-open for extensibility)" do
      {_policy, entity_id} =
        create_bound_policy(%{
          "version" => "1.0",
          "allowed_secrets" => ["ext.*"],
          "allowed_operations" => ["read"],
          "conditions" => %{
            "some_future_condition" => "some_value",
            "another_unknown" => %{"nested" => true}
          }
        })

      # Access should be granted since unknown conditions are ignored
      assert {:ok, _} =
               Policies.evaluate_access(entity_id, "ext.secret", "read")
    end

    test "unknown conditions mixed with known conditions still evaluate known ones" do
      {_policy, entity_id} =
        create_bound_policy(%{
          "version" => "1.0",
          "allowed_secrets" => ["ext.*"],
          "allowed_operations" => ["read"],
          "conditions" => %{
            "unknown_condition" => "ignored",
            "max_ttl" => "100"
          }
        })

      # Known condition (max_ttl) is still enforced even with unknown conditions present
      assert {:error, _} =
               Policies.evaluate_access(entity_id, "ext.secret", "read", %{ttl: 200})

      assert {:ok, _} =
               Policies.evaluate_access(entity_id, "ext.secret", "read", %{ttl: 50})
    end
  end

  describe "entity binding via evaluate_access/4" do
    test "unbound entity gets no access" do
      {_policy, _entity_id} =
        create_bound_policy(%{
          "version" => "1.0",
          "allowed_secrets" => ["*"],
          "allowed_operations" => ["read"]
        })

      # A different entity that is not bound to any policy
      assert {:error, _} =
               Policies.evaluate_access("totally-unknown-entity", "anything", "read")
    end

    test "bind_policy_to_entity grants access to new entity" do
      {policy, _entity_id} =
        create_bound_policy(%{
          "version" => "1.0",
          "allowed_secrets" => ["shared.*"],
          "allowed_operations" => ["read"]
        })

      new_entity = "new-entity-#{unique_suffix()}"

      # Before binding, new entity has no access
      assert {:error, _} =
               Policies.evaluate_access(new_entity, "shared.key", "read")

      # Bind the policy to the new entity
      {:ok, _updated_policy} = Policies.bind_policy_to_entity(policy.id, new_entity)

      # After binding, new entity has access
      assert {:ok, _} =
               Policies.evaluate_access(new_entity, "shared.key", "read")
    end

    test "unbind_policy_from_entity revokes access" do
      {policy, entity_id} =
        create_bound_policy(%{
          "version" => "1.0",
          "allowed_secrets" => ["revoke.*"],
          "allowed_operations" => ["read"]
        })

      # Entity has access
      assert {:ok, _} =
               Policies.evaluate_access(entity_id, "revoke.key", "read")

      # Unbind
      {:ok, _} = Policies.unbind_policy_from_entity(policy.id, entity_id)

      # Entity no longer has access
      assert {:error, _} =
               Policies.evaluate_access(entity_id, "revoke.key", "read")
    end
  end

  describe "no conditions (empty conditions map)" do
    test "access granted when conditions map is empty" do
      {_policy, entity_id} =
        create_bound_policy(%{
          "version" => "1.0",
          "allowed_secrets" => ["open.*"],
          "allowed_operations" => ["read"],
          "conditions" => %{}
        })

      assert {:ok, _} =
               Policies.evaluate_access(entity_id, "open.secret", "read")
    end

    test "access granted when conditions key is absent" do
      {_policy, entity_id} =
        create_bound_policy(%{
          "version" => "1.0",
          "allowed_secrets" => ["open.*"],
          "allowed_operations" => ["read"]
        })

      assert {:ok, _} =
               Policies.evaluate_access(entity_id, "open.secret", "read")
    end
  end
end
