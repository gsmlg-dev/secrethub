defmodule SecretHub.Core.PolicyTemplates do
  @moduledoc """
  Pre-configured policy templates for common use cases.

  Templates provide starting points for:
  - Business hours access
  - IP-restricted access
  - Read-only policies
  - Emergency access
  - Development environment access
  """

  @doc """
  Returns all available policy templates.
  """
  def list_templates do
    [
      business_hours_template(),
      ip_restricted_template(),
      read_only_template(),
      emergency_access_template(),
      dev_environment_template(),
      production_readonly_template(),
      time_limited_template(),
      multi_region_template()
    ]
  end

  @doc """
  Gets a template by name.
  """
  def get_template(template_name) do
    templates = list_templates()
    Enum.find(templates, fn t -> t.name == template_name end)
  end

  @doc """
  Creates a policy from a template with custom parameters.

  ## Parameters

  - `template_name` - Name of the template to use
  - `params` - Map of parameters to customize the template

  ## Examples

      iex> create_from_template("business_hours", %{
        name: "Production Business Hours",
        entity_bindings: ["app-prod-001"],
        allowed_secrets: ["prod.*"]
      })
      {:ok, %Policy{}}
  """
  def create_from_template(template_name, params) do
    case get_template(template_name) do
      nil ->
        {:error, "Template not found: #{template_name}"}

      template ->
        policy_attrs =
          template.policy_document
          |> merge_params(params)
          |> Map.put("name", Map.get(params, :name, template.name))
          |> Map.put("description", Map.get(params, :description, template.description))
          |> Map.put("entity_bindings", Map.get(params, :entity_bindings, []))

        {:ok, policy_attrs}
    end
  end

  ## Template Definitions

  defp business_hours_template do
    %{
      name: "business_hours",
      display_name: "Business Hours Access",
      description: "Allow access only during business hours (9 AM - 5 PM, Monday-Friday)",
      category: "time_based",
      policy_document: %{
        "version" => "2024-01-01",
        "allowed_secrets" => ["*"],
        "allowed_operations" => ["read"],
        "conditions" => %{
          "time_of_day" => "09:00-17:00",
          "days_of_week" => ["monday", "tuesday", "wednesday", "thursday", "friday"]
        }
      },
      example_usage: """
      Use this template for applications that should only access secrets during business hours.
      Ideal for batch jobs or non-critical services.
      """,
      customizable_fields: [:allowed_secrets, :allowed_operations, :time_of_day, :days_of_week]
    }
  end

  defp ip_restricted_template do
    %{
      name: "ip_restricted",
      display_name: "IP-Restricted Access",
      description: "Allow access only from specific IP ranges",
      category: "network_security",
      policy_document: %{
        "version" => "2024-01-01",
        "allowed_secrets" => ["*"],
        "allowed_operations" => ["read", "write"],
        "conditions" => %{
          "ip_ranges" => ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        }
      },
      example_usage: """
      Use this template to restrict secret access to specific network ranges.
      Default includes private IP ranges. Customize for your infrastructure.
      """,
      customizable_fields: [:allowed_secrets, :ip_ranges]
    }
  end

  defp read_only_template do
    %{
      name: "read_only",
      display_name: "Read-Only Access",
      description: "Allow read-only access to secrets",
      category: "permissions",
      policy_document: %{
        "version" => "2024-01-01",
        "allowed_secrets" => ["*"],
        "allowed_operations" => ["read"]
      },
      example_usage: """
      Use this template for applications that only need to read secrets.
      Most secure option for production workloads that don't modify secrets.
      """,
      customizable_fields: [:allowed_secrets]
    }
  end

  defp emergency_access_template do
    %{
      name: "emergency_access",
      display_name: "Emergency Access",
      description: "Temporary full access with short TTL",
      category: "emergency",
      policy_document: %{
        "version" => "2024-01-01",
        "allowed_secrets" => ["*"],
        "allowed_operations" => ["read", "write", "delete", "rotate"],
        "conditions" => %{
          "max_ttl_seconds" => 3600
        }
      },
      example_usage: """
      Use this template for emergency break-glass scenarios.
      Grants full access but with a 1-hour TTL. Should be tightly monitored.
      """,
      customizable_fields: [:allowed_secrets, :max_ttl_seconds]
    }
  end

  defp dev_environment_template do
    %{
      name: "dev_environment",
      display_name: "Development Environment",
      description: "Full access to development secrets",
      category: "environment",
      policy_document: %{
        "version" => "2024-01-01",
        "allowed_secrets" => ["dev.*", "staging.*"],
        "allowed_operations" => ["read", "write", "rotate"]
      },
      example_usage: """
      Use this template for development environments.
      Allows read/write access to dev and staging secrets only.
      """,
      customizable_fields: [:allowed_secrets, :allowed_operations]
    }
  end

  defp production_readonly_template do
    %{
      name: "production_readonly",
      display_name: "Production Read-Only",
      description:
        "Read-only access to production secrets during business hours from trusted IPs",
      category: "production",
      policy_document: %{
        "version" => "2024-01-01",
        "allowed_secrets" => ["prod.*"],
        "allowed_operations" => ["read"],
        "conditions" => %{
          "time_of_day" => "00:00-23:59",
          "ip_ranges" => ["10.0.0.0/8"]
        }
      },
      example_usage: """
      Use this template for production workloads that need read-only access.
      Combines network restrictions with production secret path filtering.
      """,
      customizable_fields: [:allowed_secrets, :time_of_day, :ip_ranges]
    }
  end

  defp time_limited_template do
    %{
      name: "time_limited",
      display_name: "Time-Limited Access",
      description: "Access limited to a specific date range",
      category: "time_based",
      policy_document: %{
        "version" => "2024-01-01",
        "allowed_secrets" => ["*"],
        "allowed_operations" => ["read"],
        "conditions" => %{
          "date_range" => "2024-01-01,2024-12-31"
        }
      },
      example_usage: """
      Use this template for temporary contractors or time-limited projects.
      Access automatically expires after the end date.
      """,
      customizable_fields: [:allowed_secrets, :date_range, :allowed_operations]
    }
  end

  defp multi_region_template do
    %{
      name: "multi_region",
      display_name: "Multi-Region Access",
      description: "Access from multiple datacenter IP ranges with TTL limits",
      category: "network_security",
      policy_document: %{
        "version" => "2024-01-01",
        "allowed_secrets" => ["*"],
        "allowed_operations" => ["read"],
        "conditions" => %{
          "ip_ranges" => [
            "10.1.0.0/16",
            "10.2.0.0/16",
            "10.3.0.0/16"
          ],
          "max_ttl_seconds" => 86_400
        }
      },
      example_usage: """
      Use this template for multi-datacenter deployments.
      Allows access from multiple region IP ranges with TTL restrictions.
      """,
      customizable_fields: [:allowed_secrets, :ip_ranges, :max_ttl_seconds]
    }
  end

  ## Helper Functions

  defp merge_params(policy_document, params) do
    # Extract customizable condition params
    conditions = Map.get(policy_document, "conditions", %{})

    conditions =
      conditions
      |> maybe_put_condition("time_of_day", Map.get(params, :time_of_day))
      |> maybe_put_condition("days_of_week", Map.get(params, :days_of_week))
      |> maybe_put_condition("date_range", Map.get(params, :date_range))
      |> maybe_put_condition("ip_ranges", Map.get(params, :ip_ranges))
      |> maybe_put_condition("max_ttl_seconds", Map.get(params, :max_ttl_seconds))

    policy_document
    |> maybe_put("allowed_secrets", Map.get(params, :allowed_secrets))
    |> maybe_put("allowed_operations", Map.get(params, :allowed_operations))
    |> Map.put("conditions", conditions)
  end

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp maybe_put_condition(conditions, _key, nil), do: conditions
  defp maybe_put_condition(conditions, key, value), do: Map.put(conditions, key, value)

  @doc """
  Validates that template parameters are valid.

  Returns {:ok, params} or {:error, reason}.
  """
  def validate_template_params(template_name, params) do
    case get_template(template_name) do
      nil ->
        {:error, "Template not found: #{template_name}"}

      template ->
        customizable = template.customizable_fields

        invalid_fields =
          params
          |> Map.keys()
          |> Enum.reject(fn key ->
            key in (customizable ++ [:name, :description, :entity_bindings])
          end)

        if invalid_fields == [] do
          {:ok, params}
        else
          {:error,
           "Invalid fields for template #{template_name}: #{inspect(invalid_fields)}. " <>
             "Customizable fields: #{inspect(customizable)}"}
        end
    end
  end

  @doc """
  Returns template categories for grouping in UI.
  """
  def get_categories do
    [
      %{
        id: "time_based",
        name: "Time-Based Access",
        description: "Policies that restrict access based on time"
      },
      %{
        id: "network_security",
        name: "Network Security",
        description: "Policies that restrict access based on IP addresses"
      },
      %{
        id: "permissions",
        name: "Permission Levels",
        description: "Policies that define different permission levels"
      },
      %{
        id: "environment",
        name: "Environment-Specific",
        description: "Policies tailored for specific environments"
      },
      %{
        id: "emergency",
        name: "Emergency Access",
        description: "Policies for break-glass scenarios"
      },
      %{
        id: "production",
        name: "Production",
        description: "Production-ready secure policies"
      }
    ]
  end

  @doc """
  Returns templates for a specific category.
  """
  def get_templates_by_category(category_id) do
    list_templates()
    |> Enum.filter(fn t -> t.category == category_id end)
  end
end
