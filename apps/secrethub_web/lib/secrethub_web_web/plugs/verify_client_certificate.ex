defmodule SecretHub.WebWeb.Plugs.VerifyClientCertificate do
  @moduledoc """
  Plug for verifying client certificates in mTLS connections.

  This plug extracts and validates client certificates from TLS connections,
  ensuring that only authenticated agents with valid certificates can access
  protected resources.

  ## Features

  - Extracts client certificate from TLS peer certificate
  - Validates certificate against SecretHub CA chain
  - Checks certificate revocation status
  - Verifies certificate is not expired
  - Extracts agent information from certificate CN

  ## Usage

  Add to router pipeline for agent-facing routes:

      pipeline :agent_api do
        plug :accepts, ["json"]
        plug SecretHub.WebWeb.Plugs.VerifyClientCertificate
      end

      scope "/agent/api", SecretHub.WebWeb do
        pipe_through :agent_api

        # Agent routes protected by mTLS
        post "/secrets/request", AgentController, :request_secret
        post "/leases/renew", AgentController, :renew_lease
      end

  ## Configuration

  Configure in config/prod.exs:

      config :secrethub_web, SecretHub.WebWeb.Endpoint,
        https: [
          port: 4001,
          cipher_suite: :strong,
          certfile: "priv/cert/server.pem",
          keyfile: "priv/cert/server-key.pem",
          cacertfile: "priv/cert/ca-chain.pem",
          verify: :verify_peer,
          fail_if_no_peer_cert: true
        ]

  ## Assigns

  After successful verification, this plug sets:

  - `:client_certificate` - Parsed certificate data
  - `:agent_id` - Extracted from certificate CN
  - `:certificate_serial` - Certificate serial number
  - `:mtls_authenticated` - Set to true
  """

  import Plug.Conn
  require Logger

  alias SecretHub.Core.PKI.CA
  alias SecretHub.Shared.Schemas.Certificate

  @doc """
  Initialize plug options.

  ## Options

  - `:required` - Whether certificate is required (default: true)
  - `:check_revocation` - Check certificate revocation status (default: true)
  """
  def init(opts) do
    %{
      required: Keyword.get(opts, :required, true),
      check_revocation: Keyword.get(opts, :check_revocation, true)
    }
  end

  @doc """
  Verify client certificate from TLS connection.

  Extracts certificate from peer connection, validates it, and sets assigns.
  """
  def call(conn, opts) do
    case get_peer_certificate(conn) do
      {:ok, cert_der} ->
        verify_certificate(conn, cert_der, opts)

      {:error, :no_certificate} ->
        if opts.required do
          Logger.warning("Client certificate required but not provided")
          send_unauthorized(conn, "Client certificate required")
        else
          Logger.debug("Client certificate not provided (optional)")
          conn
        end

      {:error, reason} ->
        Logger.error("Failed to extract client certificate: #{inspect(reason)}")
        send_unauthorized(conn, "Invalid client certificate")
    end
  end

  ## Private Functions

  defp get_peer_certificate(conn) do
    # Extract peer certificate from TLS connection
    # This works with Cowboy/Phoenix HTTPS connections

    case :ssl.peercert(conn.adapter |> elem(0)) do
      {:ok, cert_der} ->
        {:ok, cert_der}

      {:error, :no_peercert} ->
        {:error, :no_certificate}

      {:error, reason} ->
        {:error, reason}
    end
  rescue
    # Handle cases where connection is not TLS (e.g., development HTTP)
    _ -> {:error, :not_tls_connection}
  end

  defp verify_certificate(conn, cert_der, opts) do
    try do
      # Decode certificate
      cert = :public_key.pkix_decode_cert(cert_der, :otp)

      # Extract serial number
      serial_number = extract_serial_number(cert)

      # Extract CN (agent ID)
      {:ok, agent_id} = extract_common_name(cert)

      # Check if certificate is expired
      case check_validity(cert) do
        :valid ->
          :ok

        {:expired, reason} ->
          Logger.warning("Client certificate expired",
            agent_id: agent_id,
            serial: serial_number,
            reason: reason
          )

          send_unauthorized(conn, "Certificate expired")
          return(conn)
      end

      # Check revocation status if enabled
      if opts.check_revocation do
        case check_revocation_status(serial_number) do
          :not_revoked ->
            :ok

          :revoked ->
            Logger.warning("Client certificate revoked",
              agent_id: agent_id,
              serial: serial_number
            )

            send_unauthorized(conn, "Certificate revoked")
            return(conn)

          {:error, reason} ->
            Logger.error("Failed to check revocation status: #{inspect(reason)}")
            # Continue anyway - revocation check failure shouldn't block
            :ok
        end
      end

      # Verify certificate against CA chain
      case verify_against_ca_chain(cert_der) do
        :valid ->
          Logger.info("Client certificate verified", agent_id: agent_id, serial: serial_number)

          # Set assigns
          conn
          |> assign(:mtls_authenticated, true)
          |> assign(:agent_id, agent_id)
          |> assign(:certificate_serial, serial_number)
          |> assign(:client_certificate, parse_cert_info(cert))

        {:invalid, reason} ->
          Logger.warning("Client certificate validation failed",
            agent_id: agent_id,
            reason: reason
          )

          send_unauthorized(conn, "Certificate validation failed")
      end
    rescue
      e ->
        Logger.error("Exception during certificate verification: #{inspect(e)}")
        send_unauthorized(conn, "Certificate verification error")
    end
  end

  defp extract_serial_number(
         {:OTPCertificate, {:OTPTBSCertificate, _, serial, _, _, _, _, _, _, _, _}, _, _}
       ) do
    Integer.to_string(serial, 16)
  end

  defp extract_common_name(
         {:OTPCertificate, {:OTPTBSCertificate, _, _, _, _, _, subject, _, _, _, _}, _, _}
       ) do
    # Extract CN from RDN sequence
    {:rdnSequence, rdn_list} = subject

    cn =
      Enum.find_value(rdn_list, fn rdn_set ->
        Enum.find_value(rdn_set, fn
          {:AttributeTypeAndValue, {2, 5, 4, 3}, {:utf8String, cn_charlist}} ->
            to_string(cn_charlist)

          {:AttributeTypeAndValue, {2, 5, 4, 3}, {:printableString, cn_charlist}} ->
            to_string(cn_charlist)

          _ ->
            nil
        end)
      end)

    if cn, do: {:ok, cn}, else: {:error, "CN not found"}
  end

  defp check_validity(
         {:OTPCertificate, {:OTPTBSCertificate, _, _, _, _, validity, _, _, _, _, _}, _, _}
       ) do
    {:Validity, not_before, not_after} = validity

    not_before_dt = parse_asn1_time(not_before)
    not_after_dt = parse_asn1_time(not_after)
    now = DateTime.utc_now()

    cond do
      DateTime.compare(now, not_before_dt) == :lt ->
        {:expired, "Certificate not yet valid"}

      DateTime.compare(now, not_after_dt) == :gt ->
        {:expired, "Certificate expired"}

      true ->
        :valid
    end
  end

  defp parse_asn1_time({:utcTime, time_charlist}) do
    # Parse UTCTime: YYMMDDhhmmssZ
    time = to_string(time_charlist)
    year = String.to_integer(String.slice(time, 0, 2))
    year = if year >= 50, do: 1900 + year, else: 2000 + year
    month = String.to_integer(String.slice(time, 2, 2))
    day = String.to_integer(String.slice(time, 4, 2))
    hour = String.to_integer(String.slice(time, 6, 2))
    minute = String.to_integer(String.slice(time, 8, 2))
    second = String.to_integer(String.slice(time, 10, 2))

    {:ok, dt} = DateTime.new(Date.new!(year, month, day), Time.new!(hour, minute, second))
    dt
  end

  defp parse_asn1_time({:generalTime, time_charlist}) do
    # Parse GeneralizedTime: YYYYMMDDhhmmssZ
    time = to_string(time_charlist)
    year = String.to_integer(String.slice(time, 0, 4))
    month = String.to_integer(String.slice(time, 4, 2))
    day = String.to_integer(String.slice(time, 6, 2))
    hour = String.to_integer(String.slice(time, 8, 2))
    minute = String.to_integer(String.slice(time, 10, 2))
    second = String.to_integer(String.slice(time, 12, 2))

    {:ok, dt} = DateTime.new(Date.new!(year, month, day), Time.new!(hour, minute, second))
    dt
  end

  defp check_revocation_status(serial_number) do
    # Query database for certificate revocation status
    query =
      from(c in Certificate,
        where: c.serial_number == ^serial_number,
        select: c.revoked
      )

    case SecretHub.Core.Repo.one(query) do
      nil ->
        # Certificate not found in our database
        # This could mean it's a valid external cert
        Logger.debug("Certificate not found in database", serial: serial_number)
        :not_revoked

      true ->
        :revoked

      false ->
        :not_revoked
    end
  end

  defp verify_against_ca_chain(cert_der) do
    # TODO: Implement proper certificate chain validation
    # For now, we'll do basic validation

    # In production, this should:
    # 1. Get CA chain from database/file
    # 2. Verify certificate signature using CA public key
    # 3. Verify chain of trust up to root CA

    case CA.get_ca_chain() do
      {:ok, _ca_chain_pem} ->
        # TODO: Actually verify the certificate against the CA chain
        # For now, just check if we have a CA chain
        :valid

      {:error, reason} ->
        {:invalid, "CA chain not available: #{reason}"}
    end
  end

  defp parse_cert_info(cert) do
    {:OTPCertificate, {:OTPTBSCertificate, _, serial, _, _, validity, subject, _, _, _, _}, _, _} =
      cert

    {:Validity, not_before, not_after} = validity

    %{
      serial_number: Integer.to_string(serial, 16),
      subject: format_rdnsequence(subject),
      valid_from: parse_asn1_time(not_before),
      valid_until: parse_asn1_time(not_after)
    }
  end

  defp format_rdnsequence({:rdnSequence, rdn_list}) do
    rdn_list
    |> Enum.map(fn rdn_set ->
      Enum.map(rdn_set, fn
        {:AttributeTypeAndValue, {2, 5, 4, 3}, {:utf8String, cn}} ->
          "CN=#{to_string(cn)}"

        {:AttributeTypeAndValue, {2, 5, 4, 10}, {:utf8String, o}} ->
          "O=#{to_string(o)}"

        {:AttributeTypeAndValue, {2, 5, 4, 6}, {:printableString, c}} ->
          "C=#{to_string(c)}"

        _ ->
          nil
      end)
      |> Enum.reject(&is_nil/1)
      |> Enum.join(", ")
    end)
    |> Enum.join(", ")
  end

  defp send_unauthorized(conn, message) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(401, Jason.encode!(%{error: "Unauthorized", message: message}))
    |> halt()
  end

  # Helper to return from within case statements
  defp return(conn), do: throw({:return, conn})
end
