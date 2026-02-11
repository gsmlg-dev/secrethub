defmodule SecretHub.Core.Engines.Dynamic.AWSSTS do
  @moduledoc """
  AWS STS (Security Token Service) dynamic secret engine.

  Generates temporary AWS credentials via AssumeRole with configurable TTL.
  Credentials are automatically invalidated when leases expire.

  ## Configuration

  Each role requires:
  - `connection` - AWS connection parameters
    - `access_key_id` - AWS access key ID (optional, uses instance role if not provided)
    - `secret_access_key` - AWS secret access key (optional)
    - `region` - AWS region (default: us-east-1)
    - `session_token` - Session token for temporary credentials (optional)
  - `role_arn` - ARN of the IAM role to assume
  - `session_name_prefix` - Prefix for session names (default: "secrethub")
  - `policy` - Optional IAM policy to further restrict permissions (JSON string)
  - `external_id` - External ID for cross-account role assumption (optional)
  - `default_ttl` - Default session duration in seconds (default: 3600)
  - `max_ttl` - Maximum session duration in seconds (default: 43200, max 12 hours)

  ## Example Role Configuration

      %{
        "connection" => %{
          "region" => "us-west-2",
          "access_key_id" => "AKIAIOSFODNN7EXAMPLE",
          "secret_access_key" => "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        },
        "role_arn" => "arn:aws:iam::123456789012:role/MyApplicationRole",
        "session_name_prefix" => "myapp",
        "policy" => "{\\"Version\\":\\"2012-10-17\\",\\"Statement\\":[...]}",
        "external_id" => "unique-external-id",
        "default_ttl" => 3600,
        "max_ttl" => 43200
      }

  ## Credentials Response

  Returns temporary AWS credentials:
  - `access_key_id` - Temporary access key ID
  - `secret_access_key` - Temporary secret access key
  - `session_token` - Session token
  - `expiration` - Expiration timestamp (ISO 8601)
  - `ttl` - Time-to-live in seconds

  ## Notes

  - Maximum session duration is limited by the IAM role's maximum session duration setting
  - The role must trust the AWS account/principal making the AssumeRole call
  - External ID is recommended for cross-account access to prevent confused deputy problem
  - Optional policy can only further restrict permissions, not expand them
  """

  @behaviour SecretHub.Core.Engines.Dynamic

  require Logger

  alias SecretHub.Core.Engines.Dynamic

  @default_ttl 3600
  @max_ttl 43_200
  @absolute_max_ttl 43_200
  @default_region "us-east-1"
  @default_session_prefix "secrethub"

  @impl Dynamic
  def generate_credentials(role_name, opts) do
    config = Keyword.fetch!(opts, :config)
    requested_ttl = Keyword.get(opts, :ttl)

    with {:ok, aws_config} <- build_aws_config(config),
         {:ok, ttl} <- determine_ttl(requested_ttl, config),
         {:ok, session_name} <- generate_session_name(role_name, config),
         {:ok, response} <- assume_role(aws_config, config, session_name, ttl) do
      credentials = response.credentials

      Logger.info("Generated AWS STS credentials",
        role: role_name,
        role_arn: config["role_arn"],
        session_name: session_name,
        ttl: ttl
      )

      {:ok,
       %{
         access_key_id: credentials.access_key_id,
         secret_access_key: credentials.secret_access_key,
         session_token: credentials.session_token,
         expiration: credentials.expiration,
         ttl: ttl,
         metadata: %{
           role_arn: config["role_arn"],
           session_name: session_name,
           region: aws_config[:region],
           role: role_name
         }
       }}
    else
      {:error, reason} = error ->
        Logger.error("Failed to generate AWS STS credentials",
          role: role_name,
          reason: inspect(reason)
        )

        error
    end
  end

  @impl Dynamic
  def revoke_credentials(_lease_id, _credentials) do
    # AWS STS credentials cannot be explicitly revoked.
    # They automatically expire based on their TTL.
    # We return :ok immediately since there's no action to take.
    Logger.debug("AWS STS credentials will auto-expire, no revocation needed")
    :ok
  end

  @impl Dynamic
  def renew_lease(lease_id, _opts) do
    # AWS STS credentials cannot be renewed.
    # Clients must request new credentials before expiry.
    Logger.debug("AWS STS credentials cannot be renewed",
      lease_id: lease_id
    )

    {:error, :not_renewable}
  end

  @impl Dynamic
  def validate_config(config) do
    errors =
      []
      |> validate_role_arn(config)
      |> validate_ttl_field(config, "default_ttl")
      |> validate_ttl_field(config, "max_ttl")
      |> validate_policy_json(config)

    if Enum.empty?(errors) do
      :ok
    else
      {:error, errors}
    end
  end

  # Private functions

  defp validate_role_arn(errors, config) do
    cond do
      is_nil(config["role_arn"]) or config["role_arn"] == "" ->
        ["role_arn is required" | errors]

      not valid_arn?(config["role_arn"]) ->
        ["role_arn must be a valid AWS ARN" | errors]

      true ->
        errors
    end
  end

  defp validate_ttl_field(errors, config, field) do
    case config[field] do
      nil ->
        errors

      ttl when is_integer(ttl) and ttl > 0 and ttl <= @absolute_max_ttl ->
        errors

      _ ->
        ["#{field} must be between 1 and #{@absolute_max_ttl} seconds" | errors]
    end
  end

  defp validate_policy_json(errors, config) do
    case config["policy"] do
      nil ->
        errors

      policy ->
        case Jason.decode(policy) do
          {:ok, _} -> errors
          {:error, _} -> ["policy must be valid JSON" | errors]
        end
    end
  end

  defp build_aws_config(config) do
    connection = config["connection"] || %{}

    base_config = [
      region: connection["region"] || @default_region
    ]

    config =
      if connection["access_key_id"] && connection["secret_access_key"] do
        Keyword.merge(base_config,
          access_key_id: connection["access_key_id"],
          secret_access_key: connection["secret_access_key"]
        )
      else
        base_config
      end

    config =
      if connection["session_token"] do
        Keyword.put(config, :session_token, connection["session_token"])
      else
        config
      end

    {:ok, config}
  end

  defp determine_ttl(requested_ttl, config) do
    default_ttl = config["default_ttl"] || @default_ttl
    max_ttl = min(config["max_ttl"] || @max_ttl, @absolute_max_ttl)

    ttl =
      case requested_ttl do
        nil -> default_ttl
        value when value > max_ttl -> max_ttl
        value when value < 900 -> 900
        value -> value
      end

    {:ok, ttl}
  end

  defp generate_session_name(role_name, config) do
    prefix = config["session_name_prefix"] || @default_session_prefix
    random = :crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)
    timestamp = System.system_time(:second)

    # Session names must be 2-64 characters, alphanumeric + =,.@-
    session_name =
      "#{prefix}-#{sanitize_role_name(role_name)}-#{random}-#{timestamp}"
      |> String.slice(0, 64)

    {:ok, session_name}
  end

  defp sanitize_role_name(role_name) do
    role_name
    |> String.downcase()
    |> String.replace(~r/[^a-z0-9@=,.-]/, "-")
    |> String.slice(0, 20)
  end

  defp assume_role(aws_config, config, session_name, duration_seconds) do
    role_arn = config["role_arn"]

    params = %{
      "RoleArn" => role_arn,
      "RoleSessionName" => session_name,
      "DurationSeconds" => duration_seconds
    }

    params =
      if config["external_id"] do
        Map.put(params, "ExternalId", config["external_id"])
      else
        params
      end

    params =
      if config["policy"] do
        Map.put(params, "Policy", config["policy"])
      else
        params
      end

    # Merge all parameters for assume_role/2
    options =
      Map.merge(params, %{
        "RoleSessionName" => session_name,
        "DurationSeconds" => duration_seconds
      })

    case ExAws.STS.assume_role(role_arn, options)
         |> ExAws.request(aws_config) do
      {:ok, response} ->
        {:ok, parse_assume_role_response(response)}

      {:error, {:http_error, status, response}} ->
        {:error, "AWS STS HTTP error #{status}: #{inspect(response)}"}

      {:error, reason} ->
        {:error, "AWS STS request failed: #{inspect(reason)}"}
    end
  end

  defp parse_assume_role_response(response) do
    credentials = response.body.assume_role_result.credentials

    %{
      credentials: %{
        access_key_id: credentials.access_key_id,
        secret_access_key: credentials.secret_access_key,
        session_token: credentials.session_token,
        expiration: credentials.expiration
      },
      assumed_role_user: %{
        arn: response.body.assume_role_result.assumed_role_user.arn,
        assumed_role_id: response.body.assume_role_result.assumed_role_user.assumed_role_id
      }
    }
  end

  defp valid_arn?(arn) do
    # Basic ARN validation: arn:partition:service:region:account-id:resource
    # For IAM roles: arn:aws:iam::123456789012:role/RoleName
    String.match?(arn, ~r/^arn:aws[a-z-]*:iam::\d{12}:role\/[\w+=,.@-]+$/)
  end
end
