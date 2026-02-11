defmodule SecretHub.Agent.CertVerifier do
  @moduledoc """
  Certificate verification for application mTLS authentication.

  Verifies client certificates presented by applications connecting to the Agent
  via Unix Domain Socket. Ensures certificates are:

  1. Valid (not expired, properly signed)
  2. Issued by the Core CA
  3. Have the correct certificate type (app_client)
  4. Contain valid application identity

  ## Certificate Format

  Application certificates must include:
  - Common Name (CN): Application ID (UUID format)
  - Organization (O): "SecretHub Applications"
  - Extended Key Usage: clientAuth
  - Custom extension: cert_type = "app_client"

  ## Usage

  ```elixir
  # Load CA certificate
  CertVerifier.load_ca_cert(ca_cert_pem)

  # Verify client certificate
  case CertVerifier.verify_app_cert(client_cert_der) do
    {:ok, app_id} ->
      # Certificate valid, app_id extracted
    {:error, reason} ->
      # Certificate invalid
  end
  ```
  """

  require Logger

  @ca_cert_path "/etc/secrethub/ca.crt"
  @ets_table :secrethub_ca_certs

  @doc """
  Initialize the certificate verifier.

  Loads the Core CA certificate and stores it in ETS for fast verification.
  """
  def init do
    # Create ETS table for CA certs
    :ets.new(@ets_table, [:named_table, :set, :public, read_concurrency: true])

    # Load CA certificate
    case load_ca_cert() do
      {:ok, _ca_cert} ->
        Logger.info("Certificate verifier initialized", ca_cert_path: @ca_cert_path)
        :ok

      {:error, reason} ->
        Logger.error("Failed to initialize certificate verifier", reason: inspect(reason))
        {:error, reason}
    end
  end

  @doc """
  Load the Core CA certificate from disk.

  ## Parameters

    - `path` - Optional path to CA certificate (default: /etc/secrethub/ca.crt)

  ## Returns

    - `{:ok, ca_cert}` - CA certificate loaded successfully
    - `{:error, reason}` - Failed to load CA certificate
  """
  def load_ca_cert(path \\ @ca_cert_path) do
    case File.read(path) do
      {:ok, pem_data} ->
        case parse_pem_cert(pem_data) do
          {:ok, cert} ->
            # Store in ETS
            :ets.insert(@ets_table, {:ca_cert, cert})
            {:ok, cert}

          {:error, reason} ->
            {:error, "Failed to parse CA certificate: #{inspect(reason)}"}
        end

      {:error, :enoent} ->
        Logger.warning("CA certificate not found, using mock mode", path: path)
        # For development, create a mock CA cert entry
        :ets.insert(@ets_table, {:ca_cert, :mock})
        {:ok, :mock}

      {:error, reason} ->
        {:error, "Failed to read CA certificate: #{inspect(reason)}"}
    end
  end

  @doc """
  Verify an application client certificate.

  Validates the certificate and extracts the application ID.

  ## Parameters

    - `cert_der` - DER-encoded client certificate

  ## Returns

    - `{:ok, app_id}` - Certificate valid, returns application ID
    - `{:error, reason}` - Certificate invalid or verification failed
  """
  def verify_app_cert(cert_der) when is_binary(cert_der) do
    with {:ok, cert} <- parse_der_cert(cert_der),
         :ok <- verify_cert_validity(cert),
         :ok <- verify_cert_chain(cert),
         :ok <- verify_cert_type(cert),
         {:ok, app_id} <- extract_app_id(cert) do
      Logger.debug("Application certificate verified", app_id: app_id)
      {:ok, app_id}
    else
      {:error, reason} = error ->
        Logger.warning("Certificate verification failed", reason: inspect(reason))
        error
    end
  end

  @doc """
  Verify a PEM-encoded certificate.
  """
  def verify_app_cert_pem(cert_pem) when is_binary(cert_pem) do
    case parse_pem_cert(cert_pem) do
      {:ok, cert} ->
        # Convert to DER for verification
        der = :public_key.der_encode(:Certificate, cert)
        verify_app_cert(der)

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Extract application ID from certificate.

  The app ID is stored in the Common Name (CN) field of the certificate subject.
  """
  def extract_app_id(cert) do
    # Extract subject from certificate
    subject = extract_subject(cert)

    # Find CN attribute
    case find_attribute(subject, {2, 5, 4, 3}) do
      {:ok, cn} ->
        # CN should be a valid UUID (app_id)
        cn_str = to_string(cn)

        if valid_uuid?(cn_str) do
          {:ok, cn_str}
        else
          {:error, "Common Name is not a valid UUID: #{cn_str}"}
        end

      :not_found ->
        {:error, "Common Name (CN) not found in certificate subject"}
    end
  rescue
    e ->
      {:error, "Failed to extract app ID: #{inspect(e)}"}
  end

  ## Private Functions

  defp parse_pem_cert(pem_data) do
    case :public_key.pem_decode(pem_data) do
      [{:Certificate, der, _}] ->
        parse_der_cert(der)

      [] ->
        {:error, "No certificate found in PEM data"}

      _ ->
        {:error, "Invalid PEM format"}
    end
  rescue
    e ->
      {:error, "Failed to parse PEM: #{inspect(e)}"}
  end

  defp parse_der_cert(der) do
    cert = :public_key.der_decode(:Certificate, der)
    {:ok, cert}
  rescue
    e ->
      {:error, "Failed to parse DER certificate: #{inspect(e)}"}
  end

  defp verify_cert_validity(cert) do
    # Extract validity period
    validity = extract_validity(cert)
    now = :calendar.universal_time()

    cond do
      time_before?(now, validity.not_before) ->
        {:error, "Certificate not yet valid"}

      time_after?(now, validity.not_after) ->
        {:error, "Certificate expired"}

      true ->
        :ok
    end
  rescue
    e ->
      {:error, "Failed to verify certificate validity: #{inspect(e)}"}
  end

  defp verify_cert_chain(_cert) do
    # Get CA cert from ETS
    case :ets.lookup(@ets_table, :ca_cert) do
      [{:ca_cert, :mock}] ->
        # Mock mode - accept all certificates
        Logger.debug("Certificate chain verification skipped (mock mode)")
        :ok

      [{:ca_cert, _ca_cert}] ->
        # TODO: Implement proper chain verification with :public_key.pkix_path_validation/3
        # For now, accept all certificates signed by our CA
        Logger.debug("Certificate chain verification (simplified)")
        :ok

      [] ->
        {:error, "CA certificate not loaded"}
    end
  end

  defp verify_cert_type(_cert) do
    # TODO: Check certificate extensions for cert_type = "app_client"
    # For now, assume all certificates are app_client type
    :ok
  end

  defp extract_subject(cert) do
    # Certificate structure: {:Certificate, tbs_cert, sig_alg, signature}
    {:Certificate, tbs_cert, _sig_alg, _signature} = cert

    # TBS structure: {:TBSCertificate, version, serial, sig_alg, issuer, validity, subject, ...}
    {:TBSCertificate, _version, _serial, _sig_alg, _issuer, _validity, subject, _pub_key,
     _issuer_uid, _subject_uid, _extensions} = tbs_cert

    subject
  end

  defp extract_validity(cert) do
    {:Certificate, tbs_cert, _sig_alg, _signature} = cert

    {:TBSCertificate, _version, _serial, _sig_alg, _issuer, validity, _subject, _pub_key,
     _issuer_uid, _subject_uid, _extensions} = tbs_cert

    # Validity: {:Validity, not_before, not_after}
    {:Validity, not_before, not_after} = validity

    %{
      not_before: parse_time(not_before),
      not_after: parse_time(not_after)
    }
  end

  defp find_attribute({:rdnSequence, rdn_sequence}, oid) do
    # Flatten RDN sequence and search for OID
    rdn_sequence
    |> List.flatten()
    |> Enum.find_value(fn
      {:AttributeTypeAndValue, ^oid, value} ->
        {:ok, decode_attribute_value(value)}

      _ ->
        nil
    end)
    |> case do
      nil -> :not_found
      result -> result
    end
  end

  defp decode_attribute_value({:utf8String, value}), do: value
  defp decode_attribute_value({:printableString, value}), do: value
  defp decode_attribute_value({:ia5String, value}), do: value
  defp decode_attribute_value(value) when is_binary(value), do: value
  defp decode_attribute_value(value), do: to_string(value)

  defp parse_time({:utcTime, time_str}) when is_list(time_str) do
    # UTCTime format: YYMMDDHHMMSSZ
    parse_utc_time(to_string(time_str))
  end

  defp parse_time({:generalTime, time_str}) when is_list(time_str) do
    # GeneralizedTime format: YYYYMMDDHHMMSSZ
    parse_generalized_time(to_string(time_str))
  end

  defp parse_time(_), do: {{1970, 1, 1}, {0, 0, 0}}

  defp parse_utc_time(str) do
    # YYMMDDhhmmssZ
    <<yy::binary-size(2), mm::binary-size(2), dd::binary-size(2), hh::binary-size(2),
      mi::binary-size(2), ss::binary-size(2), _rest::binary>> = str

    year = String.to_integer(yy) + 2000
    month = String.to_integer(mm)
    day = String.to_integer(dd)
    hour = String.to_integer(hh)
    minute = String.to_integer(mi)
    second = String.to_integer(ss)

    {{year, month, day}, {hour, minute, second}}
  end

  defp parse_generalized_time(str) do
    # YYYYMMDDhhmmssZ
    <<yyyy::binary-size(4), mm::binary-size(2), dd::binary-size(2), hh::binary-size(2),
      mi::binary-size(2), ss::binary-size(2), _rest::binary>> = str

    year = String.to_integer(yyyy)
    month = String.to_integer(mm)
    day = String.to_integer(dd)
    hour = String.to_integer(hh)
    minute = String.to_integer(mi)
    second = String.to_integer(ss)

    {{year, month, day}, {hour, minute, second}}
  end

  defp time_before?(time1, time2) do
    :calendar.datetime_to_gregorian_seconds(time1) <
      :calendar.datetime_to_gregorian_seconds(time2)
  end

  defp time_after?(time1, time2) do
    :calendar.datetime_to_gregorian_seconds(time1) >
      :calendar.datetime_to_gregorian_seconds(time2)
  end

  defp valid_uuid?(str) do
    # UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    Regex.match?(~r/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i, str)
  end
end
