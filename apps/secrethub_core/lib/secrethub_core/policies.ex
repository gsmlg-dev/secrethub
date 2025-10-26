defmodule SecretHub.Core.Policies do
  @moduledoc """
  Policy management and evaluation module.

  Handles creation, retrieval, and evaluation of policies that control access to secrets.

  ## Policy Document Format

  Policies use a JSON document format:

  ```json
  {
    "version": "1.0",
    "allowed_secrets": ["prod.db.*", "prod.api.keys.*"],
    "allowed_operations": ["read", "renew"],
    "conditions": {
      "time_of_day": "00:00-23:59",
      "max_ttl": "3600",
      "ip_ranges": ["10.0.0.0/8", "192.168.1.0/24"]
    }
  }
  ```

  ## Policy Evaluation

  Policies are evaluated in order:
  1. Check if entity (agent/app) is bound to policy
  2. Match secret path against allowed_secrets patterns
  3. Verify operation is in allowed_operations
  4. Evaluate conditions (time, TTL, IP range, etc.)

  ## Wildcard Patterns

  Secret paths support glob-style wildcards:
  - `prod.db.*` matches `prod.db.postgres`, `prod.db.mysql`, etc.
  - `prod.*.password` matches `prod.db.password`, `prod.api.password`, etc.
  - `*.password` matches any path ending in `.password`
  """

  require Logger
  import Ecto.Query

  alias SecretHub.Core.{Audit, Repo}
  alias SecretHub.Shared.Schemas.{Agent, Policy, Secret}

  @doc """
  Create a new policy.

  ## Parameters

  - `attrs` - Map containing policy attributes

  ## Examples

      iex> create_policy(%{
        name: "database-readonly",
        description: "Read-only access to database secrets",
        policy_document: %{
          "version" => "1.0",
          "allowed_secrets" => ["prod.db.*"],
          "allowed_operations" => ["read"]
        },
        entity_bindings: ["agent-001", "agent-002"]
      })
      {:ok, %Policy{}}
  """
  @spec create_policy(map()) :: {:ok, Policy.t()} | {:error, Ecto.Changeset.t()}
  def create_policy(attrs) do
    %Policy{}
    |> Policy.changeset(attrs)
    |> Repo.insert()
    |> case do
      {:ok, policy} = result ->
        Logger.info("Policy created", policy_id: policy.id, policy_name: policy.name)

        # Audit log the policy creation
        Audit.log_event(%{
          event_type: "policy.created",
          actor_type: "admin",
          actor_id: Map.get(attrs, :created_by, "system"),
          event_data: %{
            policy_id: policy.id,
            policy_name: policy.name,
            deny_policy: policy.deny_policy || false,
            entity_bindings_count: length(policy.entity_bindings || [])
          }
        })

        result

      {:error, changeset} = error ->
        Logger.error("Failed to create policy", errors: inspect(changeset.errors))
        error
    end
  end

  @doc """
  Update an existing policy.
  """
  @spec update_policy(binary(), map()) :: {:ok, Policy.t()} | {:error, term()}
  def update_policy(policy_id, attrs) do
    case Repo.get(Policy, policy_id) do
      nil ->
        {:error, "Policy not found"}

      policy ->
        policy
        |> Policy.changeset(attrs)
        |> Repo.update()
        |> case do
          {:ok, policy} = result ->
            Logger.info("Policy updated", policy_id: policy.id)
            result

          error ->
            error
        end
    end
  end

  @doc """
  Delete a policy.
  """
  @spec delete_policy(binary()) :: {:ok, Policy.t()} | {:error, term()}
  def delete_policy(policy_id) do
    case Repo.get(Policy, policy_id) do
      nil ->
        {:error, "Policy not found"}

      policy ->
        Repo.delete(policy)
        |> case do
          {:ok, policy} = result ->
            Logger.info("Policy deleted", policy_id: policy.id)

            # Audit log the policy deletion
            Audit.log_event(%{
              event_type: "policy.deleted",
              actor_type: "admin",
              actor_id: "system",
              event_data: %{
                policy_id: policy.id,
                policy_name: policy.name
              }
            })

            result

          error ->
            error
        end
    end
  end

  @doc """
  Get a policy by ID.
  """
  @spec get_policy(binary()) :: {:ok, Policy.t()} | {:error, term()}
  def get_policy(policy_id) do
    case Repo.get(Policy, policy_id) do
      nil -> {:error, "Policy not found"}
      policy -> {:ok, policy}
    end
  end

  @doc """
  Get a policy by name.
  """
  @spec get_policy_by_name(String.t()) :: {:ok, Policy.t()} | {:error, term()}
  def get_policy_by_name(name) do
    case Repo.get_by(Policy, name: name) do
      nil -> {:error, "Policy not found"}
      policy -> {:ok, policy}
    end
  end

  @doc """
  List all policies with optional filtering.
  """
  @spec list_policies(map()) :: [Policy.t()]
  def list_policies(filters \\ %{}) do
    query = from(p in Policy, order_by: [desc: p.inserted_at])

    query =
      Enum.reduce(filters, query, fn
        {:search, term}, q ->
          search_term = "%#{term}%"
          where(q, [p], ilike(p.name, ^search_term) or ilike(p.description, ^search_term))

        {:entity_binding, entity_id}, q ->
          where(q, [p], ^entity_id in p.entity_bindings)

        _, q ->
          q
      end)

    Repo.all(query)
  end

  @doc """
  Bind a policy to an entity (agent, app, etc.).

  ## Examples

      iex> bind_policy_to_entity("policy-uuid", "agent-001")
      {:ok, %Policy{}}
  """
  @spec bind_policy_to_entity(binary(), String.t()) :: {:ok, Policy.t()} | {:error, term()}
  def bind_policy_to_entity(policy_id, entity_id) do
    case Repo.get(Policy, policy_id) do
      nil ->
        {:error, "Policy not found"}

      policy ->
        current_bindings = policy.entity_bindings || []

        if entity_id in current_bindings do
          {:ok, policy}
        else
          new_bindings = [entity_id | current_bindings]

          policy
          |> Ecto.Changeset.change(entity_bindings: new_bindings)
          |> Repo.update()
        end
    end
  end

  @doc """
  Unbind a policy from an entity.
  """
  @spec unbind_policy_from_entity(binary(), String.t()) :: {:ok, Policy.t()} | {:error, term()}
  def unbind_policy_from_entity(policy_id, entity_id) do
    case Repo.get(Policy, policy_id) do
      nil ->
        {:error, "Policy not found"}

      policy ->
        current_bindings = policy.entity_bindings || []
        new_bindings = Enum.reject(current_bindings, &(&1 == entity_id))

        policy
        |> Ecto.Changeset.change(entity_bindings: new_bindings)
        |> Repo.update()
    end
  end

  @doc """
  Evaluate if an entity has access to a secret based on policies.

  ## Parameters

  - `entity_id` - The ID of the entity (agent, app) requesting access
  - `secret_path` - The path of the secret being requested
  - `operation` - The operation being performed ("read", "write", "delete", "renew")
  - `context` - Additional context (IP address, time, etc.)

  ## Returns

  - `{:ok, policy}` - Access granted, returns the policy that allowed access
  - `{:error, reason}` - Access denied with reason

  ## Examples

      iex> evaluate_access("agent-001", "prod.db.postgres.password", "read", %{})
      {:ok, %Policy{name: "database-readonly"}}

      iex> evaluate_access("agent-001", "prod.api.keys.stripe", "read", %{})
      {:error, "No policy allows access"}
  """
  @spec evaluate_access(String.t(), String.t(), String.t(), map()) ::
          {:ok, Policy.t()} | {:error, String.t()}
  def evaluate_access(entity_id, secret_path, operation, context \\ %{}) do
    # Get all policies bound to this entity
    policies = list_policies(%{entity_binding: entity_id})

    Logger.debug("Evaluating access",
      entity_id: entity_id,
      secret_path: secret_path,
      operation: operation,
      policies_count: length(policies)
    )

    # Find first policy that allows access
    case Enum.find(policies, fn policy ->
           evaluate_policy(policy, secret_path, operation, context)
         end) do
      nil ->
        Logger.warning("Access denied - no matching policy",
          entity_id: entity_id,
          secret_path: secret_path,
          operation: operation
        )

        {:error, "No policy allows access to this secret"}

      policy ->
        Logger.info("Access granted",
          entity_id: entity_id,
          secret_path: secret_path,
          operation: operation,
          policy: policy.name
        )

        {:ok, policy}
    end
  end

  @doc """
  Get all policies bound to an entity.
  """
  @spec get_entity_policies(String.t()) :: [Policy.t()]
  def get_entity_policies(entity_id) do
    list_policies(%{entity_binding: entity_id})
  end

  @doc """
  Get policy statistics.
  """
  @spec get_policy_stats() :: map()
  def get_policy_stats do
    total = Repo.aggregate(Policy, :count, :id)

    deny_policies =
      Repo.aggregate(from(p in Policy, where: p.deny_policy == true), :count, :id)

    %{
      total: total,
      allow_policies: total - deny_policies,
      deny_policies: deny_policies
    }
  end

  ## Private Functions

  # Evaluate a single policy against the request
  defp evaluate_policy(policy, secret_path, operation, context) do
    # Check if it's a deny policy first
    if policy.deny_policy do
      # Deny policies work in reverse - if they match, access is denied
      !matches_policy?(policy, secret_path, operation, context)
    else
      # Allow policies - must match to grant access
      matches_policy?(policy, secret_path, operation, context)
    end
  end

  defp matches_policy?(policy, secret_path, operation, context) do
    doc = policy.policy_document || %{}

    # Check allowed_secrets patterns
    secret_matches? = matches_secret_pattern?(secret_path, doc["allowed_secrets"] || [])

    # Check allowed_operations
    operation_allowed? =
      operation in (doc["allowed_operations"] || ["read", "write", "delete", "renew"])

    # Check conditions
    conditions_met? = evaluate_conditions(doc["conditions"] || %{}, context)

    secret_matches? and operation_allowed? and conditions_met?
  end

  defp matches_secret_pattern?(_secret_path, []), do: false

  defp matches_secret_pattern?(secret_path, patterns) when is_list(patterns) do
    Enum.any?(patterns, fn pattern ->
      matches_glob_pattern?(secret_path, pattern)
    end)
  end

  defp matches_glob_pattern?(secret_path, pattern) do
    # Convert glob pattern to regex
    regex_pattern =
      pattern
      |> String.replace(".", "\\.")
      |> String.replace("*", ".*")
      |> then(&("^" <> &1 <> "$"))

    case Regex.compile(regex_pattern) do
      {:ok, regex} ->
        Regex.match?(regex, secret_path)

      {:error, _} ->
        # If regex compilation fails, fall back to exact match
        secret_path == pattern
    end
  end

  defp evaluate_conditions(conditions, context) when is_map(conditions) do
    Enum.all?(conditions, fn
      {"time_of_day", time_range} ->
        evaluate_time_condition(time_range, context)

      {"max_ttl", max_ttl_str} ->
        evaluate_ttl_condition(max_ttl_str, context)

      {"ip_ranges", ranges} ->
        evaluate_ip_condition(ranges, context)

      _ ->
        # Unknown condition types are ignored (fail-open for extensibility)
        true
    end)
  end

  defp evaluate_conditions(_, _), do: true

  defp evaluate_time_condition(time_range, _context) when is_binary(time_range) do
    # Parse time range like "09:00-17:00"
    case String.split(time_range, "-") do
      [start_time, end_time] ->
        current_time = Time.utc_now()

        with {:ok, start} <- Time.from_iso8601(start_time <> ":00"),
             {:ok, end_time} <- Time.from_iso8601(end_time <> ":00") do
          Time.compare(current_time, start) != :lt and Time.compare(current_time, end_time) != :gt
        else
          _ -> true
        end

      _ ->
        true
    end
  end

  defp evaluate_time_condition(_, _), do: true

  defp evaluate_ttl_condition(max_ttl_str, context) when is_binary(max_ttl_str) do
    # Parse max TTL (in seconds)
    requested_ttl = Map.get(context, :ttl, 0)
    max_ttl = String.to_integer(max_ttl_str)

    requested_ttl <= max_ttl
  rescue
    _ -> true
  end

  defp evaluate_ttl_condition(_, _), do: true

  defp evaluate_ip_condition(ranges, context) when is_list(ranges) do
    client_ip = Map.get(context, :ip_address)

    if client_ip do
      Enum.any?(ranges, fn range ->
        ip_in_range?(client_ip, range)
      end)
    else
      # No IP in context, allow
      true
    end
  end

  defp evaluate_ip_condition(_, _), do: true

  defp ip_in_range?(ip_str, range_str) do
    # Basic CIDR matching - can be enhanced with a proper IP library
    if String.contains?(range_str, "/") do
      # CIDR notation
      [network, _prefix] = String.split(range_str, "/")
      String.starts_with?(ip_str, String.slice(network, 0..-3))
    else
      # Exact IP match
      ip_str == range_str
    end
  rescue
    _ -> false
  end
end
