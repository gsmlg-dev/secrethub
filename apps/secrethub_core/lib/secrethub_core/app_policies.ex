defmodule SecretHub.Core.AppPolicies do
  @moduledoc """
  Default policy templates and helpers for applications.

  Provides common policy patterns for applications to access secrets securely.

  ## Policy Templates

  This module includes pre-defined policy templates for common use cases:

  - **read-only**: Read-only access to specified secret paths
  - **read-write**: Read and write access to specified secret paths
  - **dynamic-secrets**: Access to dynamic secrets (PostgreSQL, Redis, etc.)
  - **env-vars**: Access to environment variable secrets
  - **config-files**: Access to configuration file secrets

  ## Usage

  ```elixir
  # Create a read-only policy for an app
  {:ok, policy} = AppPolicies.create_app_policy(
    "payment-app-readonly",
    :read_only,
    ["prod.payment.*", "prod.db.payment.*"]
  )

  # Bind to an application
  Apps.bind_policy(app_id, policy.id)
  ```
  """

  alias SecretHub.Core.Policies
  require Logger

  @doc """
  Create a new application policy from a template.

  ## Parameters

    - `name` - Unique policy name
    - `template` - Policy template atom (:read_only, :read_write, :dynamic_secrets, etc.)
    - `secret_paths` - List of secret path patterns (supports wildcards)
    - `opts` - Optional parameters:
      - `:description` - Policy description
      - `:max_ttl` - Maximum TTL for leases in seconds
      - `:conditions` - Additional policy conditions

  ## Templates

    - `:read_only` - Read-only access to secrets
    - `:read_write` - Read and write access to secrets
    - `:dynamic_secrets` - Access to generate and renew dynamic secrets
    - `:env_vars` - Access to environment variable secrets
    - `:config_files` - Access to configuration file secrets
    - `:full_access` - Full access to all operations (use with caution)

  ## Examples

      iex> create_app_policy("payment-db-readonly", :read_only, ["prod.db.payment.*"])
      {:ok, %Policy{}}

      iex> create_app_policy("api-full", :read_write, ["prod.api.*"], max_ttl: 3600)
      {:ok, %Policy{}}
  """
  def create_app_policy(name, template, secret_paths, opts \\ [])
      when is_binary(name) and is_atom(template) and is_list(secret_paths) do
    description = Keyword.get(opts, :description, generate_description(template, secret_paths))
    max_ttl = Keyword.get(opts, :max_ttl)
    conditions = Keyword.get(opts, :conditions, %{})

    policy_document = build_policy_document(template, secret_paths, max_ttl, conditions)

    attrs = %{
      name: name,
      description: description,
      policy_document: policy_document,
      max_ttl_seconds: max_ttl
    }

    case Policies.create_policy(attrs) do
      {:ok, policy} = result ->
        Logger.info("App policy created", policy_id: policy.id, template: template)
        result

      {:error, changeset} = error ->
        Logger.error("Failed to create app policy",
          name: name,
          template: template,
          errors: inspect(changeset.errors)
        )

        error
    end
  end

  @doc """
  Create a set of default policies for an application.

  Creates common policy templates and returns them for binding to applications.

  ## Parameters

    - `app_name` - Application name (used as prefix for policy names)
    - `environment` - Environment name (e.g., "prod", "staging", "dev")
    - `scope` - Secret scope (e.g., "db", "api", "all")

  ## Examples

      iex> create_default_policies("payment-service", "prod", "db")
      {:ok, [%Policy{name: "payment-service-prod-db-read"}, ...]}
  """
  def create_default_policies(app_name, environment, scope) do
    secret_pattern = build_secret_pattern(environment, scope)

    policies = [
      {:"#{app_name}-#{environment}-#{scope}-read", :read_only,
       "Read-only access to #{environment} #{scope} secrets"},
      {:"#{app_name}-#{environment}-#{scope}-readwrite", :read_write,
       "Read-write access to #{environment} #{scope} secrets"}
    ]

    results =
      Enum.map(policies, fn {name, template, desc} ->
        create_app_policy(
          to_string(name),
          template,
          [secret_pattern],
          description: desc
        )
      end)

    # Check if all succeeded
    case Enum.all?(results, &match?({:ok, _}, &1)) do
      true ->
        policies = Enum.map(results, fn {:ok, policy} -> policy end)
        {:ok, policies}

      false ->
        errors = Enum.filter(results, &match?({:error, _}, &1))
        {:error, "Failed to create some policies", errors}
    end
  end

  @doc """
  Get policy template definitions.

  Returns a map of available templates with their configurations.
  """
  def list_templates do
    %{
      read_only: %{
        name: "Read-Only Access",
        description: "Read-only access to specified secrets",
        operations: ["read"],
        use_cases: ["Configuration reading", "Secret retrieval"]
      },
      read_write: %{
        name: "Read-Write Access",
        description: "Read and write access to specified secrets",
        operations: ["read", "write"],
        use_cases: ["Configuration management", "Secret updates"]
      },
      dynamic_secrets: %{
        name: "Dynamic Secrets Access",
        description: "Access to dynamic secret generation and renewal",
        operations: ["read", "renew"],
        use_cases: ["Database credentials", "API tokens"]
      },
      env_vars: %{
        name: "Environment Variables",
        description: "Access to environment variable secrets",
        operations: ["read"],
        use_cases: ["Application configuration", "Runtime environment"]
      },
      config_files: %{
        name: "Configuration Files",
        description: "Access to configuration file secrets",
        operations: ["read"],
        use_cases: ["Config file generation", "Template rendering"]
      },
      full_access: %{
        name: "Full Access",
        description: "Full access to all operations (use with caution)",
        operations: ["read", "write", "delete", "renew"],
        use_cases: ["Admin applications", "Secret management tools"]
      }
    }
  end

  ## Private Functions

  defp build_policy_document(template, secret_paths, max_ttl, conditions) do
    operations = get_template_operations(template)

    base_conditions =
      if max_ttl do
        Map.put(conditions, "max_ttl", to_string(max_ttl))
      else
        conditions
      end

    %{
      "version" => "1.0",
      "allowed_secrets" => secret_paths,
      "allowed_operations" => operations,
      "conditions" => base_conditions
    }
  end

  defp get_template_operations(:read_only), do: ["read"]
  defp get_template_operations(:read_write), do: ["read", "write"]
  defp get_template_operations(:dynamic_secrets), do: ["read", "renew"]
  defp get_template_operations(:env_vars), do: ["read"]
  defp get_template_operations(:config_files), do: ["read"]
  defp get_template_operations(:full_access), do: ["read", "write", "delete", "renew"]

  defp get_template_operations(unknown) do
    Logger.warning("Unknown template, defaulting to read-only", template: unknown)
    ["read"]
  end

  defp generate_description(:read_only, paths) do
    "Read-only access to: #{Enum.join(paths, ", ")}"
  end

  defp generate_description(:read_write, paths) do
    "Read-write access to: #{Enum.join(paths, ", ")}"
  end

  defp generate_description(:dynamic_secrets, paths) do
    "Dynamic secrets access to: #{Enum.join(paths, ", ")}"
  end

  defp generate_description(:env_vars, paths) do
    "Environment variables access to: #{Enum.join(paths, ", ")}"
  end

  defp generate_description(:config_files, paths) do
    "Configuration files access to: #{Enum.join(paths, ", ")}"
  end

  defp generate_description(:full_access, paths) do
    "Full access to: #{Enum.join(paths, ", ")}"
  end

  defp generate_description(_template, paths) do
    "Access to: #{Enum.join(paths, ", ")}"
  end

  defp build_secret_pattern("all", "all"), do: "*"
  defp build_secret_pattern(env, "all"), do: "#{env}.*"
  defp build_secret_pattern("all", scope), do: "*.#{scope}.*"
  defp build_secret_pattern(env, scope), do: "#{env}.#{scope}.*"
end
