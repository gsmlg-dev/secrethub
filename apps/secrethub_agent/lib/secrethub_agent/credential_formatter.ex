defmodule SecretHub.Agent.CredentialFormatter do
  @moduledoc """
  Credential format handler for different dynamic secret engines.

  Provides standardized formatting and access patterns for credentials
  from various secret engines (PostgreSQL, Redis, AWS STS, etc.).

  ## Supported Engine Types

  ### PostgreSQL Dynamic Credentials

  Format:
  ```elixir
  %{
    "username" => "v_myapp_a3f9k2m1_1698765432",
    "password" => "random-secure-password",
    "ttl" => 3600,
    "metadata" => %{
      "host" => "postgres.example.com",
      "port" => 5432,
      "database" => "myapp_production",
      "role" => "readonly"
    }
  }
  ```

  Template access:
  ```
  username: <%= secret.username %>
  password: <%= secret.password %>
  host: <%= secret.metadata.host %>
  connection_string: postgresql://<%= secret.username %>:<%= secret.password %>@<%= secret.metadata.host %>:<%= secret.metadata.port %>/<%= secret.metadata.database %>
  ```

  ### Redis ACL Dynamic Credentials

  Format:
  ```elixir
  %{
    "username" => "v_cache_b7k3m5n2_1698765433",
    "password" => "random-secure-password",
    "ttl" => 3600,
    "metadata" => %{
      "host" => "redis.example.com",
      "port" => 6379,
      "database" => 0,
      "role" => "cache_user"
    }
  }
  ```

  Template access:
  ```
  username: <%= secret.username %>
  password: <%= secret.password %>
  host: <%= secret.metadata.host %>
  redis_url: redis://<%= secret.username %>:<%= secret.password %>@<%= secret.metadata.host %>:<%= secret.metadata.port %>/<%= secret.metadata.database %>
  ```

  ### AWS STS Dynamic Credentials

  Format:
  ```elixir
  %{
    "access_key_id" => "ASIAIOSFODNN7EXAMPLE",
    "secret_access_key" => "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "session_token" => "FwoGZXIvYXdzEBYaDD...",
    "expiration" => "2023-10-20T14:30:00Z",
    "ttl" => 3600,
    "metadata" => %{
      "role_arn" => "arn:aws:iam::123456789012:role/MyRole",
      "session_name" => "secrethub-myapp-abc123-1698765434",
      "region" => "us-west-2",
      "role" => "app_role"
    }
  }
  ```

  Template access:
  ```
  AWS_ACCESS_KEY_ID=<%= secret.access_key_id %>
  AWS_SECRET_ACCESS_KEY=<%= secret.secret_access_key %>
  AWS_SESSION_TOKEN=<%= secret.session_token %>
  AWS_DEFAULT_REGION=<%= secret.metadata.region %>
  ```

  ## Connection String Formatting

  The module provides helpers to generate connection strings from credentials:

  ```elixir
  # PostgreSQL connection string
  CredentialFormatter.format_connection_string(:postgresql, credentials)
  #=> "postgresql://username:password@host:5432/database"

  # Redis connection string
  CredentialFormatter.format_connection_string(:redis, credentials)
  #=> "redis://username:password@host:6379/0"
  ```

  ## Environment Variable Formatting

  For direct export to environment:

  ```elixir
  CredentialFormatter.to_env_vars(:aws_sts, credentials)
  #=> %{
  #     "AWS_ACCESS_KEY_ID" => "...",
  #     "AWS_SECRET_ACCESS_KEY" => "...",
  #     "AWS_SESSION_TOKEN" => "..."
  #   }
  ```
  """

  @type credentials :: map()
  @type engine_type :: :postgresql | :redis | :aws_sts
  @type env_vars :: %{String.t() => String.t()}

  @doc """
  Format credentials as a connection string for the given engine type.

  ## Examples

      iex> creds = %{"username" => "user", "password" => "pass",
      ...>           "metadata" => %{"host" => "localhost", "port" => 5432, "database" => "mydb"}}
      iex> CredentialFormatter.format_connection_string(:postgresql, creds)
      "postgresql://user:pass@localhost:5432/mydb"
  """
  @spec format_connection_string(engine_type(), credentials()) :: String.t()
  def format_connection_string(:postgresql, credentials) do
    username = credentials["username"]
    password = credentials["password"]
    metadata = credentials["metadata"] || %{}
    host = metadata["host"] || "localhost"
    port = metadata["port"] || 5432
    database = metadata["database"] || "postgres"

    "postgresql://#{username}:#{password}@#{host}:#{port}/#{database}"
  end

  def format_connection_string(:redis, credentials) do
    username = credentials["username"]
    password = credentials["password"]
    metadata = credentials["metadata"] || %{}
    host = metadata["host"] || "localhost"
    port = metadata["port"] || 6379
    database = metadata["database"] || 0

    "redis://#{username}:#{password}@#{host}:#{port}/#{database}"
  end

  def format_connection_string(:aws_sts, _credentials) do
    # AWS STS credentials don't have a connection string format
    # They're used as environment variables instead
    ""
  end

  @doc """
  Convert credentials to environment variable format.

  Returns a map of environment variable names to values.

  ## Examples

      iex> creds = %{"access_key_id" => "AKIA...", "secret_access_key" => "secret",
      ...>           "session_token" => "token", "metadata" => %{"region" => "us-west-2"}}
      iex> CredentialFormatter.to_env_vars(:aws_sts, creds)
      %{
        "AWS_ACCESS_KEY_ID" => "AKIA...",
        "AWS_SECRET_ACCESS_KEY" => "secret",
        "AWS_SESSION_TOKEN" => "token",
        "AWS_DEFAULT_REGION" => "us-west-2"
      }
  """
  @spec to_env_vars(engine_type(), credentials()) :: env_vars()
  def to_env_vars(:postgresql, credentials) do
    metadata = credentials["metadata"] || %{}

    %{
      "PGUSER" => credentials["username"],
      "PGPASSWORD" => credentials["password"],
      "PGHOST" => metadata["host"] || "localhost",
      "PGPORT" => to_string(metadata["port"] || 5432),
      "PGDATABASE" => metadata["database"] || "postgres"
    }
  end

  def to_env_vars(:redis, credentials) do
    metadata = credentials["metadata"] || %{}

    %{
      "REDIS_USER" => credentials["username"],
      "REDIS_PASSWORD" => credentials["password"],
      "REDIS_HOST" => metadata["host"] || "localhost",
      "REDIS_PORT" => to_string(metadata["port"] || 6379),
      "REDIS_DB" => to_string(metadata["database"] || 0)
    }
  end

  def to_env_vars(:aws_sts, credentials) do
    metadata = credentials["metadata"] || %{}

    env_vars = %{
      "AWS_ACCESS_KEY_ID" => credentials["access_key_id"],
      "AWS_SECRET_ACCESS_KEY" => credentials["secret_access_key"],
      "AWS_SESSION_TOKEN" => credentials["session_token"]
    }

    # Add region if available
    if region = metadata["region"] do
      Map.put(env_vars, "AWS_DEFAULT_REGION", region)
    else
      env_vars
    end
  end

  @doc """
  Validate credential structure for a given engine type.

  Returns :ok if credentials are valid, {:error, reasons} otherwise.

  ## Examples

      iex> creds = %{"username" => "user", "password" => "pass"}
      iex> CredentialFormatter.validate(:postgresql, creds)
      :ok

      iex> creds = %{"username" => "user"}  # missing password
      iex> CredentialFormatter.validate(:postgresql, creds)
      {:error, ["missing required field: password"]}
  """
  @spec validate(engine_type(), credentials()) :: :ok | {:error, [String.t()]}
  def validate(:postgresql, credentials) do
    required_fields = ["username", "password"]
    check_required_fields(credentials, required_fields)
  end

  def validate(:redis, credentials) do
    required_fields = ["username", "password"]
    check_required_fields(credentials, required_fields)
  end

  def validate(:aws_sts, credentials) do
    required_fields = ["access_key_id", "secret_access_key", "session_token"]
    check_required_fields(credentials, required_fields)
  end

  @doc """
  Get the TTL (time-to-live) from credentials.

  Returns the TTL in seconds, or nil if not present.
  """
  @spec get_ttl(credentials()) :: integer() | nil
  def get_ttl(credentials) do
    credentials["ttl"]
  end

  @doc """
  Get the expiration timestamp from credentials.

  Returns the expiration as a DateTime, or nil if not present.
  """
  @spec get_expiration(credentials()) :: DateTime.t() | nil
  def get_expiration(credentials) do
    case credentials["expiration"] do
      nil ->
        nil

      iso_string when is_binary(iso_string) ->
        case DateTime.from_iso8601(iso_string) do
          {:ok, dt, _offset} -> dt
          {:error, _} -> nil
        end

      _ ->
        nil
    end
  end

  @doc """
  Check if credentials are expired.

  Returns true if credentials have an expiration timestamp and it has passed.
  """
  @spec expired?(credentials()) :: boolean()
  def expired?(credentials) do
    case get_expiration(credentials) do
      nil -> false
      expiration -> DateTime.compare(DateTime.utc_now(), expiration) == :gt
    end
  end

  ## Private functions

  defp check_required_fields(credentials, required_fields) do
    missing_fields =
      required_fields
      |> Enum.reject(fn field -> Map.has_key?(credentials, field) end)

    if Enum.empty?(missing_fields) do
      :ok
    else
      errors = Enum.map(missing_fields, fn field -> "missing required field: #{field}" end)
      {:error, errors}
    end
  end
end
