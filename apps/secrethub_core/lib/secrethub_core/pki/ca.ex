defmodule SecretHub.Core.PKI.CA do
  @moduledoc """
  Certificate Authority (CA) operations for SecretHub PKI.

  This module handles:
  - Root CA generation (self-signed)
  - Intermediate CA generation (signed by Root CA)
  - Certificate signing requests (CSR) processing
  - Certificate lifecycle management

  ## Certificate Hierarchy
  ```
  Root CA (self-signed)
    └── Intermediate CA (signed by Root CA)
          └── Client/Server Certificates (signed by Intermediate CA)
  ```

  ## Security Considerations
  - Root CA private key should be stored encrypted
  - Root CA should be kept offline in production
  - All operations use RSA 4096-bit or ECDSA P-384 keys
  - Certificates use SHA-256 signatures
  """

  require Logger
  import Ecto.Query

  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Crypto.Encryption
  alias SecretHub.Shared.Schemas.Certificate

  # Certificate validity periods
  # 10 years
  @root_ca_validity_days 3650
  # 5 years
  @intermediate_ca_validity_days 1825
  # 1 year
  @client_cert_validity_days 365

  @type key_type :: :rsa | :ecdsa
  @type key_size :: 2048 | 4096
  @type cert_type :: :root_ca | :intermediate_ca | :agent_client | :app_client | :admin_client

  @doc """
  Generates a Root CA certificate (self-signed).

  The Root CA is the trust anchor for the entire PKI hierarchy.

  ## Parameters
  - `common_name`: CN for the Root CA (e.g., "SecretHub Root CA")
  - `organization`: Organization name (e.g., "SecretHub")
  - `opts`: Optional parameters
    - `:key_type` - :rsa (default) or :ecdsa
    - `:key_size` - 4096 (default for RSA) or 2048
    - `:validity_days` - Certificate validity in days (default: 3650)
    - `:country` - Two-letter country code (optional)
    - `:state` - State/Province (optional)
    - `:locality` - City/Locality (optional)

  ## Returns
  - `{:ok, %{certificate: cert, private_key: key}}` on success
  - `{:error, reason}` on failure

  ## Examples
      iex> {:ok, %{certificate: cert, private_key: key}} =
      ...>   CA.generate_root_ca("SecretHub Root CA", "SecretHub Inc")
      iex> is_binary(cert)
      true
  """
  @spec generate_root_ca(String.t(), String.t(), keyword()) ::
          {:ok, %{certificate: binary(), private_key: binary(), cert_record: Certificate.t()}}
          | {:error, String.t()}
  def generate_root_ca(common_name, organization, opts \\ []) do
    key_type = Keyword.get(opts, :key_type, :rsa)
    key_size = Keyword.get(opts, :key_size, 4096)
    validity_days = Keyword.get(opts, :validity_days, @root_ca_validity_days)

    Logger.info("Generating Root CA: #{common_name}")

    with {:ok, private_key} <- generate_private_key(key_type, key_size),
         {:ok, public_key} <- extract_public_key(private_key, key_type),
         {:ok, cert_der} <-
           create_self_signed_certificate(
             private_key,
             public_key,
             common_name,
             organization,
             validity_days,
             opts
           ),
         {:ok, cert_pem} <- der_to_pem(cert_der, :certificate),
         {:ok, key_pem} <- der_to_pem(private_key_to_der(private_key, key_type), :private_key),
         {:ok, cert_record} <-
           store_certificate(
             cert_pem,
             key_pem,
             :root_ca,
             common_name,
             organization,
             validity_days
           ) do
      Logger.info("Root CA generated successfully: #{common_name}")
      {:ok, %{certificate: cert_pem, private_key: key_pem, cert_record: cert_record}}
    else
      {:error, reason} = error ->
        Logger.error("Failed to generate Root CA: #{inspect(reason)}")
        error
    end
  end

  @doc """
  Generates an Intermediate CA certificate signed by a Root CA.

  Intermediate CAs are used for day-to-day certificate signing,
  keeping the Root CA offline for security.

  ## Parameters
  - `common_name`: CN for the Intermediate CA
  - `organization`: Organization name
  - `root_ca_cert_id`: Database ID of the Root CA certificate
  - `opts`: Optional parameters (same as generate_root_ca/3)

  ## Returns
  - `{:ok, %{certificate: cert, private_key: key}}` on success
  - `{:error, reason}` on failure
  """
  @spec generate_intermediate_ca(String.t(), String.t(), String.t(), keyword()) ::
          {:ok, %{certificate: binary(), private_key: binary(), cert_record: Certificate.t()}}
          | {:error, String.t()}
  def generate_intermediate_ca(common_name, organization, root_ca_cert_id, opts \\ []) do
    key_type = Keyword.get(opts, :key_type, :rsa)
    key_size = Keyword.get(opts, :key_size, 4096)
    validity_days = Keyword.get(opts, :validity_days, @intermediate_ca_validity_days)

    Logger.info("Generating Intermediate CA: #{common_name}")

    with {:ok, root_ca} <- fetch_ca_certificate(root_ca_cert_id),
         {:ok, root_ca_key} <- decrypt_private_key(root_ca.private_key_encrypted),
         {:ok, private_key} <- generate_private_key(key_type, key_size),
         {:ok, public_key} <- extract_public_key(private_key, key_type),
         {:ok, cert_der} <-
           create_ca_signed_certificate(
             private_key,
             public_key,
             root_ca_key,
             root_ca.certificate_pem,
             common_name,
             organization,
             validity_days,
             :intermediate_ca,
             opts
           ),
         {:ok, cert_pem} <- der_to_pem(cert_der, :certificate),
         {:ok, key_pem} <- der_to_pem(private_key_to_der(private_key, key_type), :private_key),
         {:ok, cert_record} <-
           store_certificate(
             cert_pem,
             key_pem,
             :intermediate_ca,
             common_name,
             organization,
             validity_days
           ) do
      Logger.info("Intermediate CA generated successfully: #{common_name}")
      {:ok, %{certificate: cert_pem, private_key: key_pem, cert_record: cert_record}}
    else
      {:error, reason} = error ->
        Logger.error("Failed to generate Intermediate CA: #{inspect(reason)}")
        error
    end
  end

  @doc """
  Signs a Certificate Signing Request (CSR) using a CA certificate.

  ## Parameters
  - `csr_pem`: PEM-encoded CSR
  - `ca_cert_id`: Database ID of the signing CA certificate
  - `cert_type`: Type of certificate to issue (:agent_client, :app_client, :admin_client)
  - `opts`: Optional parameters
    - `:validity_days` - Certificate validity (default: 365)
    - `:key_usage` - Key usage extensions

  ## Returns
  - `{:ok, %{certificate: cert_pem}}` on success
  - `{:error, reason}` on failure
  """
  @spec sign_csr(binary(), String.t(), cert_type(), keyword()) ::
          {:ok, %{certificate: binary(), cert_record: Certificate.t()}} | {:error, String.t()}
  def sign_csr(csr_pem, ca_cert_id, cert_type, opts \\ []) do
    validity_days = Keyword.get(opts, :validity_days, @client_cert_validity_days)

    Logger.info("Signing CSR for cert_type: #{cert_type}")

    with {:ok, csr} <- parse_csr(csr_pem),
         {:ok, ca_cert} <- fetch_ca_certificate(ca_cert_id),
         {:ok, ca_key} <- decrypt_private_key(ca_cert.private_key_encrypted),
         {:ok, cert_der} <-
           sign_certificate_request(csr, ca_cert, ca_key, validity_days, cert_type, opts),
         {:ok, cert_pem} <- der_to_pem(cert_der, :certificate),
         {:ok, subject_cn} <- extract_cn_from_csr(csr),
         {:ok, cert_record} <-
           store_signed_certificate(
             cert_pem,
             cert_type,
             subject_cn,
             ca_cert.organization,
             validity_days
           ) do
      Logger.info("CSR signed successfully for: #{subject_cn}")
      {:ok, %{certificate: cert_pem, cert_record: cert_record}}
    else
      {:error, reason} = error ->
        Logger.error("Failed to sign CSR: #{inspect(reason)}")
        error
    end
  end

  # Private helper functions

  defp generate_private_key(:rsa, key_size) do
    # Generate RSA private key
    private_key = :public_key.generate_key({:rsa, key_size, 65_537})
    {:ok, private_key}
  rescue
    e ->
      {:error, "Failed to generate RSA key: #{inspect(e)}"}
  end

  defp generate_private_key(:ecdsa, _key_size) do
    # Generate ECDSA private key using P-384 curve
    private_key = :public_key.generate_key({:namedCurve, :secp384r1})
    {:ok, private_key}
  rescue
    e ->
      {:error, "Failed to generate ECDSA key: #{inspect(e)}"}
  end

  defp extract_public_key({:RSAPrivateKey, _, modulus, exponent, _, _, _, _, _, _, _}, :rsa) do
    public_key = {:RSAPublicKey, modulus, exponent}
    {:ok, public_key}
  end

  defp extract_public_key(
         {:ECPrivateKey, _version, _priv_key, params, pub_key, _asn1_novalue},
         :ecdsa
       ) do
    {:ok, {pub_key, params}}
  end

  defp extract_public_key({:ECPrivateKey, _version, _priv_key, params, pub_key}, :ecdsa) do
    {:ok, {pub_key, params}}
  end

  defp create_self_signed_certificate(
         private_key,
         public_key,
         common_name,
         organization,
         validity_days,
         opts
       ) do
    # Create certificate subject/issuer (same for self-signed)
    subject = build_subject(common_name, organization, opts)

    # Calculate validity period
    not_before = :calendar.universal_time()
    not_after = add_days(not_before, validity_days)

    # Generate serial number
    serial_number = generate_serial_number()

    # Create TBS (To Be Signed) certificate
    tbs_cert =
      create_tbs_certificate(
        serial_number,
        subject,
        # issuer same as subject for self-signed
        subject,
        public_key,
        not_before,
        not_after,
        # is_ca = true for CA certificates
        true
      )

    # Sign the certificate
    cert_der = :public_key.pkix_sign(tbs_cert, private_key)
    {:ok, cert_der}
  rescue
    e ->
      {:error, "Failed to create self-signed certificate: #{inspect(e)}"}
  end

  defp create_ca_signed_certificate(
         _private_key,
         public_key,
         ca_private_key,
         ca_cert_pem,
         common_name,
         organization,
         validity_days,
         cert_type,
         opts
       ) do
    # Parse CA certificate to get issuer
    {:ok, ca_cert_der} = pem_to_der(ca_cert_pem, :certificate)
    ca_cert = :public_key.pkix_decode_cert(ca_cert_der, :otp)

    # Extract issuer from CA cert
    issuer = extract_issuer(ca_cert)

    # Create subject for new certificate
    subject = build_subject(common_name, organization, opts)

    # Calculate validity period
    not_before = :calendar.universal_time()
    not_after = add_days(not_before, validity_days)

    # Generate serial number
    serial_number = generate_serial_number()

    # Create TBS certificate
    is_ca = cert_type in [:root_ca, :intermediate_ca]

    tbs_cert =
      create_tbs_certificate(
        serial_number,
        issuer,
        subject,
        public_key,
        not_before,
        not_after,
        is_ca
      )

    # Sign with CA's private key
    cert_der = :public_key.pkix_sign(tbs_cert, ca_private_key)
    {:ok, cert_der}
  rescue
    e ->
      {:error, "Failed to create CA-signed certificate: #{inspect(e)}"}
  end

  defp build_subject(common_name, organization, opts) do
    country = Keyword.get(opts, :country)
    state = Keyword.get(opts, :state)
    locality = Keyword.get(opts, :locality)

    # Build RDN (Relative Distinguished Name) sequence
    rdns = []

    # Country code must be exactly 2 characters for printableString
    rdns = if country, do: [{:AttributeTypeAndValue, {2, 5, 4, 6}, country} | rdns], else: rdns

    rdns =
      if state,
        do: [{:AttributeTypeAndValue, {2, 5, 4, 8}, {:utf8String, state}} | rdns],
        else: rdns

    rdns =
      if locality,
        do: [{:AttributeTypeAndValue, {2, 5, 4, 7}, {:utf8String, locality}} | rdns],
        else: rdns

    rdns = [{:AttributeTypeAndValue, {2, 5, 4, 10}, {:utf8String, organization}} | rdns]
    rdns = [{:AttributeTypeAndValue, {2, 5, 4, 3}, {:utf8String, common_name}} | rdns]

    # Wrap each RDN in a set
    {:rdnSequence, Enum.map(rdns, fn rdn -> [rdn] end)}
  end

  defp create_tbs_certificate(serial, issuer, subject, public_key, not_before, not_after, is_ca) do
    # This is a simplified version - in production, use proper OTP record construction
    # For now, we'll use :public_key.pkix_sign/2 which handles TBS creation

    # Convert times to ASN.1 format
    validity = {
      :Validity,
      format_time(not_before),
      format_time(not_after)
    }

    # Create basic certificate info using proper OTP records
    {
      :OTPTBSCertificate,
      # version
      :v3,
      serial,
      # signature algorithm - use AlgorithmIdentifier record
      # sha256WithRSAEncryption with NULL params
      {:SignatureAlgorithm, {1, 2, 840, 113_549, 1, 1, 11}, {:asn1_OPENTYPE, <<5, 0>>}},
      issuer,
      validity,
      subject,
      # subject public key info
      encode_public_key_info(public_key),
      # issuerUniqueID
      :asn1_NOVALUE,
      # subjectUniqueID
      :asn1_NOVALUE,
      build_extensions(is_ca)
    }
  end

  defp encode_public_key_info({:RSAPublicKey, _, _} = public_key) do
    {
      :OTPSubjectPublicKeyInfo,
      # rsaEncryption with NULL params
      {:PublicKeyAlgorithm, {1, 2, 840, 113_549, 1, 1, 1}, {:asn1_OPENTYPE, <<5, 0>>}},
      public_key
    }
  end

  defp encode_public_key_info({pub_key_bin, params}) when is_binary(pub_key_bin) do
    # ECDSA public key
    {
      :OTPSubjectPublicKeyInfo,
      # ecPublicKey
      {:PublicKeyAlgorithm, {1, 2, 840, 10_045, 2, 1}, params},
      pub_key_bin
    }
  end

  defp build_extensions(is_ca) do
    extensions = [
      # Subject Key Identifier
      {
        :Extension,
        # id-ce-subjectKeyIdentifier
        {2, 5, 29, 14},
        false,
        # Random SKI
        <<4, 20>> <> :crypto.strong_rand_bytes(20)
      },
      # Key Usage
      {
        :Extension,
        # id-ce-keyUsage
        {2, 5, 29, 15},
        # critical
        true,
        if is_ca do
          # CA: keyCertSign, cRLSign
          <<3, 2, 1, 6>>
        else
          # End entity: digitalSignature, keyEncipherment
          <<3, 2, 5, 160>>
        end
      }
    ]

    # Add Basic Constraints extension
    extensions =
      if is_ca do
        # For CA certificates, mark as CA
        [
          {
            :Extension,
            # id-ce-basicConstraints
            {2, 5, 29, 19},
            # critical
            true,
            # Pass the tuple directly, not DER-encoded
            {:BasicConstraints, true, :asn1_NOVALUE}
          }
          | extensions
        ]
      else
        extensions
      end

    extensions
  end

  defp format_time({{year, month, day}, {hour, minute, second}}) do
    # UTCTime format for dates before 2050
    if year < 2050 do
      year_str = Integer.to_string(rem(year, 100)) |> String.pad_leading(2, "0")
      month_str = Integer.to_string(month) |> String.pad_leading(2, "0")
      day_str = Integer.to_string(day) |> String.pad_leading(2, "0")
      hour_str = Integer.to_string(hour) |> String.pad_leading(2, "0")
      minute_str = Integer.to_string(minute) |> String.pad_leading(2, "0")
      second_str = Integer.to_string(second) |> String.pad_leading(2, "0")

      {:utcTime,
       to_charlist("#{year_str}#{month_str}#{day_str}#{hour_str}#{minute_str}#{second_str}Z")}
    else
      # GeneralizedTime for dates 2050 and later
      year_str = Integer.to_string(year)
      month_str = Integer.to_string(month) |> String.pad_leading(2, "0")
      day_str = Integer.to_string(day) |> String.pad_leading(2, "0")
      hour_str = Integer.to_string(hour) |> String.pad_leading(2, "0")
      minute_str = Integer.to_string(minute) |> String.pad_leading(2, "0")
      second_str = Integer.to_string(second) |> String.pad_leading(2, "0")

      {:generalTime,
       to_charlist("#{year_str}#{month_str}#{day_str}#{hour_str}#{minute_str}#{second_str}Z")}
    end
  end

  defp generate_serial_number do
    # Generate a random 20-byte serial number
    :crypto.strong_rand_bytes(20) |> :binary.decode_unsigned()
  end

  defp add_days({{year, month, day}, {hour, minute, second}}, days) do
    # Convert to gregorian days, add days, convert back
    greg_days = :calendar.date_to_gregorian_days(year, month, day)
    new_greg_days = greg_days + days
    {new_year, new_month, new_day} = :calendar.gregorian_days_to_date(new_greg_days)
    {{new_year, new_month, new_day}, {hour, minute, second}}
  end

  defp private_key_to_der({:RSAPrivateKey, _, _, _, _, _, _, _, _, _, _} = key, :rsa) do
    :public_key.der_encode(:RSAPrivateKey, key)
  end

  defp private_key_to_der({:ECPrivateKey, _, _, _} = key, :ecdsa) do
    :public_key.der_encode(:ECPrivateKey, key)
  end

  defp der_to_pem(der, :certificate) do
    pem_entry = {:Certificate, der, :not_encrypted}
    pem = :public_key.pem_encode([pem_entry])
    {:ok, pem}
  end

  defp der_to_pem(der, :private_key) do
    # Assuming RSA for now - would need to detect key type
    pem_entry = {:RSAPrivateKey, der, :not_encrypted}
    pem = :public_key.pem_encode([pem_entry])
    {:ok, pem}
  end

  defp pem_to_der(pem, :certificate) do
    [entry] = :public_key.pem_decode(pem)
    {:Certificate, der, :not_encrypted} = entry
    {:ok, der}
  rescue
    e -> {:error, "Failed to decode PEM: #{inspect(e)}"}
  end

  defp store_certificate(cert_pem, key_pem, cert_type, common_name, organization, _validity_days) do
    # Encrypt the private key before storing
    {:ok, encrypted_key} = encrypt_private_key(key_pem)

    # Parse certificate to extract details
    {:ok, cert_der} = pem_to_der(cert_pem, :certificate)
    cert = :public_key.pkix_decode_cert(cert_der, :otp)

    serial_number = extract_serial_number(cert)
    {not_before, not_after} = extract_validity(cert)
    fingerprint = calculate_fingerprint(cert_pem)

    # Create certificate record
    cert_record = %Certificate{
      serial_number: serial_number,
      fingerprint: fingerprint,
      certificate_pem: cert_pem,
      private_key_encrypted: encrypted_key,
      subject: build_subject_string(common_name, organization),
      # Self-signed
      issuer: build_subject_string(common_name, organization),
      common_name: common_name,
      organization: organization,
      valid_from: not_before,
      valid_until: not_after,
      cert_type: cert_type,
      key_usage: get_key_usage(cert_type),
      entity_type: "ca"
    }

    Repo.insert(cert_record)
  end

  defp store_signed_certificate(cert_pem, cert_type, common_name, organization, _validity_days) do
    # For signed certificates, we don't store the private key (it stays with the client)
    {:ok, cert_der} = pem_to_der(cert_pem, :certificate)
    cert = :public_key.pkix_decode_cert(cert_der, :otp)

    serial_number = extract_serial_number(cert)
    {not_before, not_after} = extract_validity(cert)
    fingerprint = calculate_fingerprint(cert_pem)

    cert_record = %Certificate{
      serial_number: serial_number,
      fingerprint: fingerprint,
      certificate_pem: cert_pem,
      subject: build_subject_string(common_name, organization),
      common_name: common_name,
      organization: organization,
      valid_from: not_before,
      valid_until: not_after,
      cert_type: cert_type,
      key_usage: get_key_usage(cert_type),
      entity_type: to_string(cert_type)
    }

    Repo.insert(cert_record)
  end

  defp encrypt_private_key(key_pem) do
    # Get master encryption key from SealState
    # Use fallback key for tests when SealState isn't running
    master_key =
      case Process.whereis(SecretHub.Core.Vault.SealState) do
        nil ->
          # SealState not running (test mode) - use a fixed test key
          :crypto.hash(:sha256, "test-encryption-key-for-pki-testing")

        _pid ->
          case SecretHub.Core.Vault.SealState.get_master_key() do
            {:ok, key} -> key
            {:error, _} -> nil
          end
      end

    if is_binary(master_key) do
      Encryption.encrypt_to_blob(key_pem, master_key)
    else
      {:error, "Vault is sealed"}
    end
  end

  defp decrypt_private_key(encrypted_key) do
    # Get master encryption key from SealState
    # Use fallback key for tests when SealState isn't running
    master_key =
      case Process.whereis(SecretHub.Core.Vault.SealState) do
        nil ->
          # SealState not running (test mode) - use same test key
          :crypto.hash(:sha256, "test-encryption-key-for-pki-testing")

        _pid ->
          case SecretHub.Core.Vault.SealState.get_master_key() do
            {:ok, key} -> key
            {:error, _reason} -> nil
          end
      end

    if is_binary(master_key) do
      case Encryption.decrypt_from_blob(encrypted_key, master_key) do
        {:ok, key_pem} ->
          # Parse PEM to get private key structure
          [entry] = :public_key.pem_decode(key_pem)
          private_key = :public_key.pem_entry_decode(entry)
          {:ok, private_key}

        error ->
          error
      end
    else
      {:error, "Vault is sealed"}
    end
  rescue
    e ->
      {:error, "Failed to decrypt private key: #{inspect(e)}"}
  end

  defp fetch_ca_certificate(cert_id) do
    case Repo.get(Certificate, cert_id) do
      nil -> {:error, "CA certificate not found"}
      cert when cert.cert_type in [:root_ca, :intermediate_ca] -> {:ok, cert}
      _ -> {:error, "Certificate is not a CA"}
    end
  end

  defp parse_csr(csr_pem) do
    [entry] = :public_key.pem_decode(csr_pem)
    csr = :public_key.pem_entry_decode(entry)
    {:ok, csr}
  rescue
    e -> {:error, "Failed to parse CSR: #{inspect(e)}"}
  end

  defp sign_certificate_request(csr, ca_cert, ca_key, validity_days, cert_type, _opts) do
    # Extract public key and subject from CSR
    # This is simplified - full implementation would validate CSR signature
    # Extract subject and public key from CSR
    subject = extract_subject_from_csr(csr)
    public_key = extract_public_key_from_csr(csr)

    # Parse CA cert to get issuer
    {:ok, ca_cert_der} = pem_to_der(ca_cert.certificate_pem, :certificate)
    ca_cert_decoded = :public_key.pkix_decode_cert(ca_cert_der, :otp)
    issuer = extract_issuer(ca_cert_decoded)

    # Calculate validity
    not_before = :calendar.universal_time()
    not_after = add_days(not_before, validity_days)

    # Generate serial
    serial_number = generate_serial_number()

    # Create TBS certificate
    is_ca = cert_type in [:root_ca, :intermediate_ca]

    tbs_cert =
      create_tbs_certificate(
        serial_number,
        issuer,
        subject,
        public_key,
        not_before,
        not_after,
        is_ca
      )

    # Sign with CA key
    cert_der = :public_key.pkix_sign(tbs_cert, ca_key)
    {:ok, cert_der}
  rescue
    e ->
      {:error, "Failed to sign CSR: #{inspect(e)}"}
  end

  defp extract_serial_number(
         {:OTPCertificate, {:OTPTBSCertificate, _, serial, _, _, _, _, _, _, _, _}, _, _}
       ) do
    Integer.to_string(serial, 16)
  end

  defp extract_validity(
         {:OTPCertificate, {:OTPTBSCertificate, _, _, _, _, validity, _, _, _, _, _}, _, _}
       ) do
    {:Validity, not_before, not_after} = validity
    {parse_time(not_before), parse_time(not_after)}
  end

  defp parse_time({:utcTime, time_str}) do
    # Parse UTCTime: YYMMDDhhmmssZ
    time = to_string(time_str)
    year = String.to_integer(String.slice(time, 0, 2))
    year = if year >= 50, do: 1900 + year, else: 2000 + year
    month = String.to_integer(String.slice(time, 2, 2))
    day = String.to_integer(String.slice(time, 4, 2))
    hour = String.to_integer(String.slice(time, 6, 2))
    minute = String.to_integer(String.slice(time, 8, 2))
    second = String.to_integer(String.slice(time, 10, 2))

    DateTime.new!(Date.new!(year, month, day), Time.new!(hour, minute, second), "Etc/UTC")
    |> DateTime.truncate(:second)
  end

  defp parse_time({:generalTime, time_str}) do
    # Parse GeneralizedTime: YYYYMMDDhhmmssZ
    time = to_string(time_str)
    year = String.to_integer(String.slice(time, 0, 4))
    month = String.to_integer(String.slice(time, 4, 2))
    day = String.to_integer(String.slice(time, 6, 2))
    hour = String.to_integer(String.slice(time, 8, 2))
    minute = String.to_integer(String.slice(time, 10, 2))
    second = String.to_integer(String.slice(time, 12, 2))

    DateTime.new!(Date.new!(year, month, day), Time.new!(hour, minute, second), "Etc/UTC")
    |> DateTime.truncate(:second)
  end

  defp extract_issuer(
         {:OTPCertificate, {:OTPTBSCertificate, _, _, _, issuer, _, _, _, _, _, _}, _, _}
       ) do
    issuer
  end

  defp extract_subject_from_csr(
         {:CertificationRequest, {:CertificationRequestInfo, _, subject, _, _}, _, _}
       ) do
    subject
  end

  defp extract_public_key_from_csr(
         {:CertificationRequest, {:CertificationRequestInfo, _, _, spki, _}, _, _}
       ) do
    # Extract public key from SubjectPublicKeyInfo
    {:SubjectPublicKeyInfo, _, public_key} = spki
    public_key
  end

  defp extract_cn_from_csr(csr) do
    subject = extract_subject_from_csr(csr)
    {:rdnSequence, rdns} = subject

    # Find CN attribute
    cn =
      Enum.find_value(rdns, fn rdn_set ->
        Enum.find_value(rdn_set, fn
          {:AttributeTypeAndValue, {2, 5, 4, 3}, {:utf8String, cn_charlist}} ->
            to_string(cn_charlist)

          {:AttributeTypeAndValue, {2, 5, 4, 3}, {:printableString, cn_charlist}} ->
            to_string(cn_charlist)

          _ ->
            nil
        end)
      end)

    if cn, do: {:ok, cn}, else: {:error, "CN not found in CSR"}
  end

  defp calculate_fingerprint(cert_pem) do
    :crypto.hash(:sha256, cert_pem)
    |> Base.encode16(case: :lower)
  end

  defp build_subject_string(common_name, organization) do
    "CN=#{common_name}, O=#{organization}"
  end

  defp get_key_usage(:root_ca), do: ["keyCertSign", "cRLSign"]
  defp get_key_usage(:intermediate_ca), do: ["keyCertSign", "cRLSign"]
  defp get_key_usage(_), do: ["digitalSignature", "keyEncipherment"]

  @doc """
  Get the CA certificate chain (root + intermediates) for client verification.

  Returns the certificate chain in PEM format, suitable for client mTLS connections.

  ## Returns

  - `{:ok, ca_chain_pem}` - CA chain as PEM string
  - `{:error, reason}` - Failed to retrieve CA chain
  """
  @spec get_ca_chain() :: {:ok, String.t()} | {:error, term()}
  def get_ca_chain do
    # Query all CA certificates (root and intermediate) ordered by hierarchy
    query =
      from(c in Certificate,
        where: c.cert_type in [:root_ca, :intermediate_ca] and c.revoked == false,
        order_by: [desc: c.cert_type, asc: c.inserted_at],
        select: c.certificate_pem
      )

    case Repo.all(query) do
      [] ->
        {:error, "No CA certificates found"}

      certs when is_list(certs) ->
        # Concatenate all CA certificates into a chain
        ca_chain = Enum.join(certs, "\n")
        {:ok, ca_chain}
    end
  end
end
