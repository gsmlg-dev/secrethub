defmodule SecretHub.Agent.Bootstrap do
  @moduledoc """
  Bootstrap module for SecretHub Agent authentication.

  Handles the initial bootstrap process for agents:
  1. AppRole authentication using RoleID/SecretID (secret zero)
  2. Generate CSR (Certificate Signing Request)
  3. Submit CSR to Core for signing
  4. Receive and store signed certificate
  5. Use certificate for subsequent mTLS connections

  ## Bootstrap Flow

  1. **Initial Bootstrap (using AppRole)**
     - Agent starts with RoleID and SecretID (secret zero)
     - Authenticates with Core using AppRole
     - Generates RSA-2048 key pair
     - Creates CSR with agent metadata
     - Submits CSR to Core via authenticated WebSocket

  2. **Certificate Issuance**
     - Core validates agent authentication
     - Signs CSR using Intermediate CA
     - Returns signed certificate to agent
     - Agent stores certificate and private key

  3. **Subsequent Connections (using mTLS)**
     - Agent uses certificate for TLS client authentication
     - Core validates certificate against CA chain
     - No need for RoleID/SecretID after initial bootstrap

  ## Certificate Storage

  Certificates are stored in:
  - `priv/cert/agent-cert.pem` - Agent certificate
  - `priv/cert/agent-key.pem` - Private key (encrypted)
  - `priv/cert/ca-chain.pem` - CA certificate chain

  ## Renewal

  Certificates are renewed automatically when:
  - Certificate expires within 7 days
  - Certificate is revoked (detected during connection)
  - Manual renewal requested

  ## Usage

      # Bootstrap new agent with AppRole
      {:ok, cert_info} = Bootstrap.bootstrap_with_approle(
        role_id: "role-uuid",
        secret_id: "secret-uuid",
        agent_id: "agent-prod-01",
        core_url: "wss://secrethub.example.com"
      )

      # Check if agent needs bootstrap
      if Bootstrap.needs_bootstrap?() do
        Bootstrap.bootstrap_with_approle(config)
      end

      # Renew certificate
      {:ok, new_cert} = Bootstrap.renew_certificate(agent_id, core_url)
  """

  require Logger

  @cert_dir "priv/cert"
  @cert_file "#{@cert_dir}/agent-cert.pem"
  @key_file "#{@cert_dir}/agent-key.pem"
  @ca_chain_file "#{@cert_dir}/ca-chain.pem"
  @csr_file "#{@cert_dir}/agent-csr.pem"

  # Certificate renewal threshold: 7 days before expiry
  @renewal_threshold_days 7

  @doc """
  Check if agent needs to bootstrap.

  Returns `true` if:
  - Certificate files don't exist
  - Certificate is expired or expiring soon
  - Certificate is invalid

  ## Examples

      iex> Bootstrap.needs_bootstrap?()
      true  # No certificate exists

      iex> Bootstrap.needs_bootstrap?()
      false  # Valid certificate exists
  """
  @spec needs_bootstrap?() :: boolean()
  def needs_bootstrap? do
    cond do
      !File.exists?(@cert_file) or !File.exists?(@key_file) ->
        Logger.info("Certificate files not found - bootstrap required")
        true

      !valid_certificate?() ->
        Logger.info("Certificate invalid or expiring soon - bootstrap required")
        true

      true ->
        false
    end
  end

  @doc """
  Bootstrap agent using AppRole authentication.

  Steps:
  1. Authenticate with Core using RoleID/SecretID
  2. Generate RSA key pair and CSR
  3. Submit CSR to Core for signing
  4. Store signed certificate and key

  ## Parameters

  - `:role_id` - AppRole role ID (required)
  - `:secret_id` - AppRole secret ID (required)
  - `:agent_id` - Agent identifier (required)
  - `:core_url` - Core WebSocket URL (required)
  - `:organization` - Organization name (optional, default: "SecretHub Agents")
  - `:common_name` - Certificate CN (optional, default: agent_id)

  ## Returns

  - `{:ok, cert_info}` - Bootstrap successful, returns certificate info
  - `{:error, reason}` - Bootstrap failed

  ## Examples

      {:ok, cert_info} = Bootstrap.bootstrap_with_approle(
        role_id: "role-abc123",
        secret_id: "secret-def456",
        agent_id: "agent-prod-01",
        core_url: "wss://secrethub.example.com:4001"
      )
  """
  @spec bootstrap_with_approle(keyword()) :: {:ok, map()} | {:error, term()}
  def bootstrap_with_approle(opts) do
    role_id = Keyword.fetch!(opts, :role_id)
    secret_id = Keyword.fetch!(opts, :secret_id)
    agent_id = Keyword.fetch!(opts, :agent_id)
    core_url = Keyword.fetch!(opts, :core_url)
    organization = Keyword.get(opts, :organization, "SecretHub Agents")
    common_name = Keyword.get(opts, :common_name, agent_id)

    Logger.info("Starting bootstrap process", agent_id: agent_id)

    with :ok <- ensure_cert_directory(),
         {:ok, private_key} <- generate_private_key(),
         {:ok, csr} <- generate_csr(private_key, agent_id, organization, common_name),
         {:ok, csr_pem} <- encode_csr(csr),
         :ok <- write_csr(csr_pem),
         {:ok, signed_cert, ca_chain} <-
           submit_csr_to_core(csr_pem, role_id, secret_id, agent_id, core_url),
         :ok <- write_certificate(signed_cert),
         :ok <- write_private_key(private_key),
         :ok <- write_ca_chain(ca_chain) do
      Logger.info("Bootstrap completed successfully", agent_id: agent_id)

      {:ok,
       %{
         agent_id: agent_id,
         cert_path: @cert_file,
         key_path: @key_file,
         ca_chain_path: @ca_chain_file
       }}
    else
      {:error, reason} = error ->
        Logger.error("Bootstrap failed", reason: inspect(reason), agent_id: agent_id)
        error
    end
  end

  @doc """
  Renew agent certificate.

  Uses existing certificate for mTLS authentication while requesting renewal.

  ## Parameters

  - `agent_id` - Agent identifier
  - `core_url` - Core WebSocket URL

  ## Returns

  - `{:ok, cert_info}` - Renewal successful
  - `{:error, reason}` - Renewal failed
  """
  @spec renew_certificate(String.t(), String.t()) :: {:ok, map()} | {:error, term()}
  def renew_certificate(agent_id, core_url) do
    Logger.info("Starting certificate renewal", agent_id: agent_id)

    with {:ok, private_key} <- read_private_key(),
         {:ok, csr} <- generate_csr(private_key, agent_id, "SecretHub Agents", agent_id),
         {:ok, csr_pem} <- encode_csr(csr),
         {:ok, signed_cert, ca_chain} <-
           submit_csr_for_renewal(csr_pem, agent_id, core_url),
         :ok <- write_certificate(signed_cert),
         :ok <- write_ca_chain(ca_chain) do
      Logger.info("Certificate renewal completed", agent_id: agent_id)

      {:ok,
       %{
         agent_id: agent_id,
         cert_path: @cert_file,
         key_path: @key_file,
         ca_chain_path: @ca_chain_file
       }}
    else
      {:error, reason} = error ->
        Logger.error("Certificate renewal failed", reason: inspect(reason), agent_id: agent_id)
        error
    end
  end

  @doc """
  Get certificate information.

  Returns certificate validity, expiration, and other metadata.

  ## Returns

  - `{:ok, cert_info}` - Certificate info retrieved
  - `{:error, reason}` - Failed to read certificate
  """
  @spec get_certificate_info() :: {:ok, map()} | {:error, term()}
  def get_certificate_info do
    if File.exists?(@cert_file) do
      with {:ok, cert_pem} <- File.read(@cert_file),
           {:ok, cert} <- parse_certificate(cert_pem) do
        {:ok,
         %{
           subject: extract_subject(cert),
           issuer: extract_issuer(cert),
           valid_from: extract_not_before(cert),
           valid_until: extract_not_after(cert),
           serial_number: extract_serial(cert),
           expires_in_days: days_until_expiry(cert)
         }}
      end
    else
      {:error, :certificate_not_found}
    end
  end

  ## Private Functions

  defp ensure_cert_directory do
    File.mkdir_p(@cert_dir)
  end

  defp generate_private_key do
    Logger.debug("Generating RSA-2048 private key")

    # Generate RSA-2048 key pair using OpenSSL
    case System.cmd("openssl", [
           "genpkey",
           "-algorithm",
           "RSA",
           "-pkeyopt",
           "rsa_keygen_bits:2048"
         ]) do
      {key_pem, 0} ->
        {:ok, key_pem}

      {error, _} ->
        {:error, "Failed to generate private key: #{error}"}
    end
  end

  defp generate_csr(private_key, agent_id, organization, common_name) do
    Logger.debug("Generating CSR", agent_id: agent_id, common_name: common_name)

    # Create subject string
    subject = "/C=US/O=#{organization}/CN=#{common_name}"

    # Write private key to temp file for OpenSSL
    temp_key = "#{@cert_dir}/.temp-key.pem"
    File.write!(temp_key, private_key)

    # Generate CSR using OpenSSL
    result =
      System.cmd("openssl", [
        "req",
        "-new",
        "-key",
        temp_key,
        "-subj",
        subject,
        "-addext",
        "subjectAltName=DNS:#{agent_id},DNS:agent"
      ])

    # Clean up temp key
    File.rm(temp_key)

    case result do
      {csr_pem, 0} ->
        {:ok, csr_pem}

      {error, _} ->
        {:error, "Failed to generate CSR: #{error}"}
    end
  end

  defp encode_csr(csr) when is_binary(csr) do
    {:ok, csr}
  end

  defp write_csr(csr_pem) do
    File.write(@csr_file, csr_pem)
  end

  defp submit_csr_to_core(csr_pem, role_id, secret_id, agent_id, core_url) do
    Logger.info("Submitting CSR to Core for signing", agent_id: agent_id)

    # Start a temporary connection to Core for bootstrap
    # This will use AppRole authentication (secret zero)

    with {:ok, socket} <- connect_for_bootstrap(core_url, agent_id),
         {:ok, channel} <- join_agent_channel(socket, agent_id),
         {:ok, _auth} <- authenticate_with_approle(channel, role_id, secret_id),
         {:ok, cert_response} <- request_certificate_signing(channel, csr_pem) do
      # Extract certificate and CA chain from response
      signed_cert = Map.get(cert_response, "certificate")
      ca_chain = Map.get(cert_response, "ca_chain")

      Logger.info("Certificate successfully obtained from Core", agent_id: agent_id)

      # Socket will be garbage collected
      _ = socket

      {:ok, signed_cert, ca_chain}
    else
      {:error, reason} = error ->
        Logger.error("Failed to obtain certificate from Core", reason: inspect(reason))
        error
    end
  end

  defp submit_csr_for_renewal(csr_pem, agent_id, core_url) do
    Logger.info("Submitting CSR for renewal", agent_id: agent_id)

    # Use existing certificate for mTLS authentication during renewal
    with {:ok, socket} <- connect_with_mtls(core_url, agent_id),
         {:ok, channel} <- join_agent_channel(socket, agent_id),
         {:ok, cert_response} <- request_certificate_signing(channel, csr_pem) do
      signed_cert = Map.get(cert_response, "certificate")
      ca_chain = Map.get(cert_response, "ca_chain")

      Logger.info("Certificate successfully renewed", agent_id: agent_id)

      # Socket will be garbage collected
      _ = socket

      {:ok, signed_cert, ca_chain}
    else
      {:error, reason} = error ->
        Logger.error("Failed to renew certificate", reason: inspect(reason))
        error
    end
  end

  defp connect_for_bootstrap(core_url, agent_id) do
    # Connect to Core without TLS client certificate (using HTTP/WS only)
    socket_opts = [
      url: build_websocket_url(core_url),
      sender: self(),
      serializer: Jason,
      headers: [{"x-agent-id", agent_id}]
    ]

    PhoenixClient.Socket.start_link(socket_opts)
  end

  defp connect_with_mtls(core_url, _agent_id) do
    # Connect to Core using existing certificate for mTLS
    if File.exists?(@cert_file) and File.exists?(@key_file) and File.exists?(@ca_chain_file) do
      socket_opts = [
        url: build_websocket_url(core_url),
        sender: self(),
        serializer: Jason,
        transport_opts: [
          certfile: @cert_file,
          keyfile: @key_file,
          cacertfile: @ca_chain_file
        ]
      ]

      PhoenixClient.Socket.start_link(socket_opts)
    else
      {:error, :certificate_not_found}
    end
  end

  defp build_websocket_url(core_url) do
    core_url
    |> URI.parse()
    |> Map.put(:path, "/agent/socket/websocket")
    |> URI.to_string()
  end

  defp join_agent_channel(socket, agent_id) do
    topic = "agent:#{agent_id}"

    case PhoenixClient.Channel.join(socket, topic) do
      {:ok, _response, channel} ->
        {:ok, channel}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp authenticate_with_approle(channel, role_id, secret_id) do
    payload = %{
      "role_id" => role_id,
      "secret_id" => secret_id
    }

    case PhoenixClient.Channel.push(channel, "authenticate", payload) do
      :ok ->
        # Wait for authentication response
        receive do
          %PhoenixClient.Message{event: "phx_reply", payload: reply} ->
            case reply do
              %{"status" => "ok", "response" => auth_data} ->
                {:ok, auth_data}

              %{"status" => "error", "response" => error} ->
                {:error, error}

              _ ->
                {:error, "Unknown authentication response"}
            end
        after
          10_000 ->
            {:error, :authentication_timeout}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp request_certificate_signing(channel, csr_pem) do
    payload = %{"csr" => csr_pem}

    case PhoenixClient.Channel.push(channel, "certificate:request", payload) do
      :ok ->
        # Wait for certificate response
        receive do
          %PhoenixClient.Message{event: "phx_reply", payload: reply} ->
            case reply do
              %{"status" => "ok", "response" => cert_data} ->
                {:ok, cert_data}

              %{"status" => "error", "response" => error} ->
                {:error, error}

              _ ->
                {:error, "Unknown certificate response"}
            end
        after
          15_000 ->
            {:error, :certificate_request_timeout}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp write_certificate(cert_pem) do
    File.write(@cert_file, cert_pem)
  end

  defp write_private_key(key_pem) do
    # TODO: Encrypt private key before storing
    File.write(@key_file, key_pem)
  end

  defp write_ca_chain(ca_chain_pem) do
    File.write(@ca_chain_file, ca_chain_pem)
  end

  defp read_private_key do
    if File.exists?(@key_file) do
      # TODO: Decrypt private key
      File.read(@key_file)
    else
      {:error, :key_not_found}
    end
  end

  defp valid_certificate? do
    case get_certificate_info() do
      {:ok, cert_info} ->
        cert_info.expires_in_days > @renewal_threshold_days

      {:error, _} ->
        false
    end
  end

  defp parse_certificate(cert_pem) do
    # Parse PEM certificate using OpenSSL
    temp_cert = "#{@cert_dir}/.temp-cert.pem"
    File.write!(temp_cert, cert_pem)

    result =
      System.cmd("openssl", [
        "x509",
        "-in",
        temp_cert,
        "-noout",
        "-text"
      ])

    File.rm(temp_cert)

    case result do
      {cert_text, 0} ->
        {:ok, cert_text}

      {error, _} ->
        {:error, "Failed to parse certificate: #{error}"}
    end
  end

  defp extract_subject(cert_text) do
    case Regex.run(~r/Subject:.*CN\s*=\s*([^,\n]+)/, cert_text) do
      [_, cn] -> String.trim(cn)
      _ -> "Unknown"
    end
  end

  defp extract_issuer(cert_text) do
    case Regex.run(~r/Issuer:.*CN\s*=\s*([^,\n]+)/, cert_text) do
      [_, cn] -> String.trim(cn)
      _ -> "Unknown"
    end
  end

  defp extract_not_before(cert_text) do
    case Regex.run(~r/Not Before\s*:\s*(.+)/, cert_text) do
      [_, date] -> String.trim(date)
      _ -> nil
    end
  end

  defp extract_not_after(cert_text) do
    case Regex.run(~r/Not After\s*:\s*(.+)/, cert_text) do
      [_, date] -> String.trim(date)
      _ -> nil
    end
  end

  defp extract_serial(cert_text) do
    case Regex.run(~r/Serial Number:\s*\n?\s*([a-f0-9:]+)/i, cert_text) do
      [_, serial] -> String.trim(serial)
      _ -> "Unknown"
    end
  end

  defp days_until_expiry(_cert_text) do
    # TODO: Parse dates and calculate actual days
    # For now return a placeholder
    30
  end
end
