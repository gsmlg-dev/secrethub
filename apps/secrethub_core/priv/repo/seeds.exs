# Script to populate SecretHub with sample data for development

alias SecretHub.Core.Repo

import SecretHub.Shared.Schemas.{Secret, Policy, Role}
import Ecto.UUID

# Start Repo (ignore if already started)
case Repo.start_link() do
  {:ok, _} -> :ok
  {:error, {:already_started, _}} -> :ok
  other -> other
end

# Clean existing data
Repo.delete_all(SecretHub.Shared.Schemas.Secret)
Repo.delete_all(SecretHub.Shared.Schemas.Policy)
Repo.delete_all(SecretHub.Shared.Schemas.Role)
Repo.delete_all(SecretHub.Shared.Schemas.Lease)

# Create sample secrets
secrets = [
  %{
    secret_path: "dev.db.postgres.auth.password",
    secret_type: :static,
    encrypted_data: "encrypted_pg_password_123",
    description: "PostgreSQL auth database password",
    rotation_enabled: true,
    rotation_schedule: "0 2 * * 1"  # Every Sunday at 2 AM
  },
  %{
    secret_path: "dev.api.payment-gateway.apikey",
    secret_type: :static,
    encrypted_data: "encrypted_payment_api_key_456",
    description: "Payment gateway API key",
    rotation_enabled: true,
    rotation_schedule: "0 3 * * 1"
  },
  %{
    secret_path: "dev.db.redis.cache.role",
    secret_type: :dynamic_role,
    encrypted_data: "redis_cache_role_template",
    description: "Redis cache access role",
    rotation_enabled: false
  }
]

created_secrets = Enum.map(secrets, fn secret_attrs ->
  {:ok, secret} =
    %SecretHub.Shared.Schemas.Secret{}
    |> SecretHub.Shared.Schemas.Secret.changeset(secret_attrs)
    |> Repo.insert()

  secret
end)

# Create sample roles
roles = [
  %{
    role_id: Ecto.UUID.generate(),
    role_name: "Production Web Application",
    bound_cidr_list: ["10.0.0.0/8", "192.168.1.0/24"],
    token_policies: ["webapp-secrets", "database-access"],
    secret_id_accessor: "dev.api.payment-gateway.apikey",
    bind_secret_id: true
  },
  %{
    role_id: Ecto.UUID.generate(),
    role_name: "Backend Service Role",
    bound_cidr_list: ["10.1.0.0/16"],
    token_policies: ["backend-secrets", "database-read"],
    secret_id_accessor: "dev.db.postgres.auth.password",
    bind_secret_id: true
  }
]

created_roles = Enum.map(roles, fn role_attrs ->
  {:ok, role} =
    %SecretHub.Shared.Schemas.Role{}
    |> SecretHub.Shared.Schemas.Role.changeset(role_attrs)
    |> Repo.insert()

  role
end)

# Create sample policies
policies = [
  %{
    name: "webapp-secrets",
    description: "Policy for web application secret access",
    policy_document: %{
      "version" => "1.0",
      "allowed_secrets" => ["dev/api/*", "dev/db/postgres/readonly"]
    },
    deny_policy: false
  },
  %{
    name: "database-access",
    description: "Policy for database access",
    policy_document: %{
      "version" => "1.0",
      "allowed_secrets" => ["dev/db/*"],
      "conditions" => %{
        "forbidden_paths" => ["dev/db/postgres/admin"]
      }
    },
    deny_policy: false
  },
  %{
    name: "deny-admin-secrets",
    description: "Deny all admin secret access",
    policy_document: %{
      "version" => "1.0",
      "allowed_secrets" => [],
      "conditions" => %{
        "forbidden_paths" => ["prod/admin/*"]
      }
    },
    deny_policy: true
  }
]

created_policies = Enum.map(policies, fn policy_attrs ->
  {:ok, policy} =
    %SecretHub.Shared.Schemas.Policy{}
    |> SecretHub.Shared.Schemas.Policy.changeset(policy_attrs)
    |> Repo.insert()

  policy
end)

IO.puts("✅ Database seeded successfully!")
IO.puts("📊 Created #{length(created_secrets)} secrets")
IO.puts("👥 Created #{length(created_roles)} roles")
IO.puts("📋 Created #{length(created_policies)} policies")