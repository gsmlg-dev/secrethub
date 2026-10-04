defmodule SecretHub.Core.RuntimePolicyTest do
  use ExUnit.Case, async: true
  alias SecretHub.Core.PolicyEvaluator
  alias SecretHub.Shared.Schemas.Policy

  test "runtime paths and operations have one canonical namespace" do
    assert {:ok, "prod.db.password"} = PolicyEvaluator.normalize_runtime_path("prod.db.password")

    for path <- ["prod/db/password", "prod..password", ".prod", "prod.", "prod.**", "../prod"] do
      assert {:error, :invalid_path} = PolicyEvaluator.normalize_runtime_path(path)
    end

    assert {:deny, _} =
             PolicyEvaluator.evaluate_runtime(policy(%{}), %{
               secret_path: "prod.db.password",
               operation: "write"
             })
  end

  test "unknown, malformed, and missing-context conditions fail closed" do
    context = %{secret_path: "prod.db.password", operation: "read"}

    for conditions <- [
          %{"unknown" => true},
          %{"ip_ranges" => "all"},
          %{"ip_ranges" => ["127.0.0.0/8"]},
          %{"max_ttl" => "60"},
          %{"time_of_day" => "invalid"},
          []
        ] do
      assert {:deny, _} = PolicyEvaluator.evaluate_runtime(policy(conditions), context)
    end

    assert {:allow, _} = PolicyEvaluator.evaluate_runtime(policy(%{}), context)
  end

  test "literal wildcard sentinel names grant only the exact runtime path" do
    policy = policy(%{}, ["prod.___DOUBLE_STAR___"])

    assert {:allow, :policy_match} =
             PolicyEvaluator.evaluate_runtime(policy, %{
               secret_path: "prod.___DOUBLE_STAR___",
               operation: "read"
             })

    for path <- ["prod.db.password", "prod.___DOUBLE_STAR___.password"] do
      assert {:deny, :policy_denied} =
               PolicyEvaluator.evaluate_runtime(policy, %{secret_path: path, operation: "read"})
    end
  end

  test "single-star runtime grants match exactly one segment" do
    policy = policy(%{}, ["prod.*"])

    assert {:allow, :policy_match} =
             PolicyEvaluator.evaluate_runtime(policy, %{secret_path: "prod.db", operation: "read"})

    for path <- ["prod", "prod.db.password", "dev.db"] do
      assert {:deny, :policy_denied} =
               PolicyEvaluator.evaluate_runtime(policy, %{secret_path: path, operation: "read"})
    end
  end

  test "double-star runtime grants match multiple segments within the literal prefix" do
    policy = policy(%{}, ["prod.**"])

    for path <- ["prod.db", "prod.db.password"] do
      assert {:allow, :policy_match} =
               PolicyEvaluator.evaluate_runtime(policy, %{secret_path: path, operation: "read"})
    end

    for path <- ["prod", "dev.db.password"] do
      assert {:deny, :policy_denied} =
               PolicyEvaluator.evaluate_runtime(policy, %{secret_path: path, operation: "read"})
    end
  end

  defp policy(conditions, patterns \\ ["prod.db.*"]) do
    %Policy{
      policy_document: %{
        "allowed_secrets" => patterns,
        "allowed_operations" => ["read"],
        "conditions" => conditions
      }
    }
  end
end
