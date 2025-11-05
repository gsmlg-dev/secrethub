defmodule SecretHub.Core.AutoUnseal.Providers.AWSKMS do
  @moduledoc """
  AWS KMS provider for auto-unseal.

  Encrypts and decrypts unseal keys using AWS Key Management Service.
  Supports multiple authentication methods and automatic retry logic.

  ## Configuration

  Requires:
  - `:kms_key_id` - ARN or alias of the KMS key (e.g., "arn:aws:kms:us-east-1:123456789012:key/...")
  - `:region` - AWS region (e.g., "us-east-1")

  Optional:
  - `:access_key_id` - AWS access key (not recommended, use IAM roles instead)
  - `:secret_access_key` - AWS secret key
  - `:session_token` - AWS session token (for temporary credentials)

  ## Authentication Methods (in order of precedence)

  1. **Explicit credentials** in config (not recommended for production)
  2. **Environment variables:**
     - AWS_ACCESS_KEY_ID
     - AWS_SECRET_ACCESS_KEY
     - AWS_SESSION_TOKEN (optional)
  3. **ECS container credentials** (via AWS_CONTAINER_CREDENTIALS_RELATIVE_URI)
  4. **EC2 instance profile** (IAM role attached to EC2 instance)

  **Recommended:** Use IAM roles for EC2/ECS/EKS instead of static credentials.

  ## KMS Permissions Required

  The IAM role or user must have the following KMS permissions:
  - `kms:Encrypt` - to encrypt unseal keys during initialization
  - `kms:Decrypt` - to decrypt unseal keys during auto-unseal

  ## Example KMS Policy

  ```json
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": [
          "kms:Encrypt",
          "kms:Decrypt"
        ],
        "Resource": "arn:aws:kms:us-east-1:123456789012:key/your-key-id"
      }
    ]
  }
  ```

  ## Error Handling

  The provider implements automatic retry logic with exponential backoff for:
  - Network errors
  - Throttling errors (TooManyRequestsException)
  - Temporary AWS service errors

  Does NOT retry for:
  - Invalid credentials (AccessDeniedException)
  - Invalid key ID (NotFoundException)
  - Disabled KMS key (DisabledException)
  """

  require Logger

  @max_retries 3
  @initial_retry_delay_ms 1000

  @doc """
  Encrypts data using AWS KMS.

  ## Parameters
    * `config` - Configuration map with :kms_key_id and :region
    * `plaintext` - Data to encrypt (binary)

  ## Returns
    * `{:ok, ciphertext_blob}` - Base64-encoded ciphertext on success
    * `{:error, reason}` - Error tuple with details

  ## Examples

      config = %{
        kms_key_id: "arn:aws:kms:us-east-1:123456789012:key/...",
        region: "us-east-1"
      }

      {:ok, ciphertext} = AWSKMS.encrypt(config, "my-secret-data")
  """
  @spec encrypt(map(), binary()) :: {:ok, binary()} | {:error, term()}
  def encrypt(config, plaintext) when is_binary(plaintext) do
    Logger.debug("AWS KMS encrypt: encrypting #{byte_size(plaintext)} bytes")

    kms_key_id = Map.fetch!(config, :kms_key_id)
    region = Map.get(config, :region, "us-east-1")

    params = %{
      "KeyId" => kms_key_id,
      "Plaintext" => Base.encode64(plaintext)
    }

    case perform_kms_operation(:encrypt, params, region, config) do
      {:ok, %{"CiphertextBlob" => ciphertext_blob}} ->
        Logger.debug("AWS KMS encrypt: success")
        {:ok, ciphertext_blob}

      {:error, reason} = error ->
        Logger.error("AWS KMS encrypt failed: #{inspect(reason)}")
        error
    end
  end

  @doc """
  Decrypts data using AWS KMS.

  ## Parameters
    * `config` - Configuration map with :kms_key_id and :region
    * `ciphertext_blob` - Base64-encoded ciphertext from encrypt/2

  ## Returns
    * `{:ok, plaintext}` - Decrypted plaintext on success
    * `{:error, reason}` - Error tuple with details

  ## Examples

      config = %{
        kms_key_id: "arn:aws:kms:us-east-1:123456789012:key/...",
        region: "us-east-1"
      }

      {:ok, plaintext} = AWSKMS.decrypt(config, ciphertext_blob)
  """
  @spec decrypt(map(), binary()) :: {:ok, binary()} | {:error, term()}
  def decrypt(config, ciphertext_blob) when is_binary(ciphertext_blob) do
    Logger.debug("AWS KMS decrypt: decrypting ciphertext")

    region = Map.get(config, :region, "us-east-1")

    params = %{
      "CiphertextBlob" => ciphertext_blob
    }

    case perform_kms_operation(:decrypt, params, region, config) do
      {:ok, %{"Plaintext" => plaintext_b64}} ->
        case Base.decode64(plaintext_b64) do
          {:ok, plaintext} ->
            Logger.debug("AWS KMS decrypt: success, #{byte_size(plaintext)} bytes")
            {:ok, plaintext}

          :error ->
            {:error, :invalid_base64_plaintext}
        end

      {:error, reason} = error ->
        Logger.error("AWS KMS decrypt failed: #{inspect(reason)}")
        error
    end
  end

  # Private Functions

  defp perform_kms_operation(operation, params, region, config, retry_count \\ 0) do
    # Build ExAws operation
    aws_config = build_aws_config(region, config)

    operation_result =
      case operation do
        :encrypt ->
          ExAws.KMS.encrypt(params)

        :decrypt ->
          ExAws.KMS.decrypt(params)
      end

    # Execute the request
    case ExAws.request(operation_result, aws_config) do
      {:ok, response} ->
        {:ok, response}

      {:error, {:http_error, status_code, _body}} = error ->
        if should_retry?(status_code, retry_count) do
          retry_operation(operation, params, region, config, retry_count)
        else
          error
        end

      {:error, reason} = error ->
        if is_retryable_error?(reason) && retry_count < @max_retries do
          retry_operation(operation, params, region, config, retry_count)
        else
          error
        end
    end
  end

  defp build_aws_config(region, provider_config) do
    base_config = [
      region: region,
      http_client: ExAws.Request.Hackney
    ]

    # Add explicit credentials if provided (not recommended for production)
    aws_config =
      if Map.has_key?(provider_config, :access_key_id) &&
           Map.has_key?(provider_config, :secret_access_key) do
        Keyword.merge(base_config,
          access_key_id: provider_config.access_key_id,
          secret_access_key: provider_config.secret_access_key
        )
      else
        base_config
      end

    # Add session token if provided (for temporary credentials)
    if Map.has_key?(provider_config, :session_token) do
      Keyword.put(aws_config, :session_token, provider_config.session_token)
    else
      aws_config
    end
  end

  defp should_retry?(status_code, retry_count) do
    # Retry on 429 (throttling) and 5xx (server errors)
    retry_count < @max_retries &&
      (status_code == 429 || (status_code >= 500 && status_code < 600))
  end

  defp is_retryable_error?(reason) do
    # Retry on network errors and throttling
    case reason do
      {:http_error, _, _} -> true
      :timeout -> true
      :econnrefused -> true
      _ -> false
    end
  end

  defp retry_operation(operation, params, region, config, retry_count) do
    delay_ms = calculate_retry_delay(retry_count)

    Logger.warning(
      "AWS KMS #{operation} failed, retrying in #{delay_ms}ms (attempt #{retry_count + 1}/#{@max_retries})"
    )

    Process.sleep(delay_ms)
    perform_kms_operation(operation, params, region, config, retry_count + 1)
  end

  defp calculate_retry_delay(retry_count) do
    # Exponential backoff: 1s, 2s, 4s
    (@initial_retry_delay_ms * :math.pow(2, retry_count)) |> round()
  end
end
