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

  alias SecretHub.Core.PKI.Events
  alias SecretHub.Core.Repo
  alias SecretHub.Core.Vault.SealState
  alias SecretHub.Shared.Crypto.Encryption
  alias SecretHub.Shared.Schemas.Certificate
  alias X509.Certificate.{Extension, Validity}

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

    with :ok <- validate_cn(common_name),
         :ok <- validate_org(organization),
         :ok <- validate_key_opts(key_type, key_size),
         {:ok, private_key} <- generate_private_key(key_type, key_size),
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
         {:ok, key_pem} <-
           der_to_pem(private_key_to_der(private_key, key_type), private_key_pem_type(key_type)),
         {:ok, cert_record} <-
           store_certificate(
             cert_pem,
             key_pem,
             :root_ca,
             common_name,
             organization,
             validity_days
           ),
         :ok <-
           record_ca_initialized_event(
             cert_record,
             key_type,
             key_size,
             validity_days,
             opts
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

    with :ok <- validate_cn(common_name),
         :ok <- validate_org(organization),
         :ok <- validate_key_opts(key_type, key_size),
         {:ok, root_ca} <- fetch_ca_certificate(root_ca_cert_id),
         {:ok, root_ca_key} <- decrypt_private_key(root_ca.private_key_encrypted),
         {:ok, private_key} <- generate_private_key(key_type, key_size),
         {:ok, public_key} <- extract_public_key(private_key, key_type),
         {:ok, cert_der} <-
           create_ca_signed_certificate(
             public_key,
             root_ca_key,
             root_ca.certificate_pem,
             common_name,
             organization,
             validity_days: validity_days,
             cert_type: :intermediate_ca,
             opts: opts
           ),
         {:ok, cert_pem} <- der_to_pem(cert_der, :certificate),
         {:ok, key_pem} <-
           der_to_pem(private_key_to_der(private_key, key_type), private_key_pem_type(key_type)),
         {:ok, cert_record} <-
           store_certificate(
             cert_pem,
             key_pem,
             :intermediate_ca,
             common_name,
             organization,
             validity_days,
             root_ca_cert_id,
             root_ca.subject
           ),
         :ok <-
           record_ca_initialized_event(
             cert_record,
             key_type,
             key_size,
             validity_days,
             Keyword.put(opts, :issuer_ca_id, root_ca_cert_id)
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
             validity_days,
             ca_cert.id,
             ca_cert.subject
           ),
         :ok <- record_certificate_issued_event(cert_record, ca_cert, validity_days, opts) do
      Logger.info("CSR signed successfully for: #{subject_cn}")
      {:ok, %{certificate: cert_pem, cert_record: cert_record}}
    else
      {:error, reason} = error ->
        Logger.error("Failed to sign CSR: #{inspect(reason)}")
        error
    end
  end

  @doc """
  Signs a canonical application client certificate from an already verified
  public key.

  The certificate identity and authorization extensions are owned entirely by
  Core. This helper does not persist the certificate or any private key.
  """
  @spec issue_canonical_app_certificate(term(), Ecto.UUID.t()) ::
          {:ok, %{certificate: binary(), ca_chain: [binary()], issuer: Certificate.t()}}
          | {:error, :ca_unavailable | :issuance_failed}
  def issue_canonical_app_certificate(public_key, app_id) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    with {:ok, ca, ca_chain, chain_valid_until} <- lock_validated_issuance_chain(now),
         {:ok, ca_key} <- decrypt_private_key(ca.private_key_encrypted),
         {:ok, certificate_pem} <-
           build_canonical_app_certificate(
             public_key,
             app_id,
             ca,
             ca_key,
             now,
             chain_valid_until
           ),
         :ok <- verify_issued_certificate(certificate_pem, ca) do
      {:ok, %{certificate: certificate_pem, ca_chain: ca_chain, issuer: ca}}
    else
      {:error, :issuance_failed} -> {:error, :issuance_failed}
      {:error, _reason} -> {:error, :ca_unavailable}
    end
  rescue
    _error -> {:error, :ca_unavailable}
  end

  @doc """
  Returns active, non-revoked CA certificates as individual PEM values.
  """
  @spec get_ca_chain_pems() :: {:ok, [binary()]} | {:error, :ca_unavailable}
  def get_ca_chain_pems do
    case Repo.all(active_ca_chain_query()) do
      [] -> {:error, :ca_unavailable}
      certificates -> {:ok, certificates}
    end
  end

  @doc """
  Returns the exact persisted issuer chain starting at a signing CA.
  """
  @spec get_ca_chain_pems(Certificate.t() | Ecto.UUID.t()) ::
          {:ok, [binary()]} | {:error, :ca_unavailable}
  def get_ca_chain_pems(%Certificate{} = signing_ca) do
    persisted_ca_chain(signing_ca, MapSet.new())
  end

  def get_ca_chain_pems(signing_ca_id) when is_binary(signing_ca_id) do
    case Repo.get(Certificate, signing_ca_id) do
      %Certificate{} = signing_ca -> get_ca_chain_pems(signing_ca)
      nil -> {:error, :ca_unavailable}
    end
  end

  # Private helper functions

  defp build_canonical_app_certificate(
         public_key,
         app_id,
         ca,
         ca_key,
         now,
         chain_valid_until
       ) do
    extensions = [
      basic_constraints: Extension.basic_constraints(false),
      key_usage: Extension.key_usage([:digitalSignature]),
      ext_key_usage: Extension.ext_key_usage([:clientAuth]),
      subject_alt_name:
        Extension.subject_alt_name([
          {:uniformResourceIdentifier, ~c"urn:secrethub:app:" ++ to_charlist(app_id)}
        ])
    ]

    certificate =
      X509.Certificate.new(
        public_key,
        "/O=SecretHub Applications/CN=#{app_id}",
        X509.Certificate.from_pem!(ca.certificate_pem),
        ca_key,
        extensions: extensions,
        validity: canonical_client_validity(now, chain_valid_until)
      )

    {:ok, X509.Certificate.to_pem(certificate)}
  rescue
    _error -> {:error, :issuance_failed}
  end

  defp lock_validated_issuance_chain(now) do
    case lock_preferred_signing_ca(now) do
      %Certificate{} = signing_ca ->
        with {:ok, chain} <-
               validate_issuance_chain(signing_ca, now, MapSet.new()),
             :ok <- validate_path_length_constraints(chain) do
          ca_chain = Enum.map(chain, fn {certificate, _parsed} -> certificate.certificate_pem end)

          chain_valid_until =
            chain
            |> Enum.flat_map(fn {certificate, parsed} ->
              [certificate.valid_until, parsed_valid_until(parsed)]
            end)
            |> Enum.min_by(&DateTime.to_unix/1)

          {:ok, signing_ca, ca_chain, chain_valid_until}
        end

      nil ->
        {:error, :ca_unavailable}
    end
  rescue
    _error -> {:error, :ca_unavailable}
  end

  defp lock_preferred_signing_ca(now) do
    lock_active_ca(:intermediate_ca, now) || lock_active_ca(:root_ca, now)
  end

  defp lock_active_ca(cert_type, now) do
    Repo.one(
      from(c in Certificate,
        where: c.cert_type == ^cert_type,
        where: c.revoked == false,
        where: c.valid_from <= ^now,
        where: c.valid_until > ^now,
        order_by: [desc: c.inserted_at, desc: c.id],
        limit: 1,
        lock: "FOR SHARE"
      )
    )
  end

  defp validate_issuance_chain(%Certificate{id: id} = certificate, now, seen) do
    with false <- MapSet.member?(seen, id),
         :ok <- validate_issuance_ca_record(certificate, now),
         {:ok, parsed} <- X509.Certificate.from_pem(certificate.certificate_pem) do
      validate_issuance_chain_link(
        certificate,
        parsed,
        now,
        MapSet.put(seen, id)
      )
    else
      _other -> {:error, :ca_unavailable}
    end
  rescue
    _error -> {:error, :ca_unavailable}
  end

  defp validate_issuance_chain_link(
         %Certificate{cert_type: :root_ca, issuer_id: nil} = root,
         parsed_root,
         now,
         _seen
       ) do
    with :ok <- validate_parsed_ca(parsed_root, now),
         true <- :public_key.pkix_is_self_signed(parsed_root),
         true <-
           :public_key.pkix_verify(
             X509.Certificate.to_der(parsed_root),
             X509.Certificate.public_key(parsed_root)
           ) do
      {:ok, [{root, parsed_root}]}
    else
      _other -> {:error, :ca_unavailable}
    end
  end

  defp validate_issuance_chain_link(
         %Certificate{cert_type: :intermediate_ca, issuer_id: issuer_id} = intermediate,
         parsed_intermediate,
         now,
         seen
       )
       when is_binary(issuer_id) do
    with :ok <- validate_parsed_ca(parsed_intermediate, now),
         %Certificate{} = issuer <- lock_ca(issuer_id),
         {:ok, [{_issuer, parsed_issuer} | _rest] = issuer_chain} <-
           validate_issuance_chain(issuer, now, seen),
         true <- :public_key.pkix_is_issuer(parsed_intermediate, parsed_issuer),
         true <-
           :public_key.pkix_verify(
             X509.Certificate.to_der(parsed_intermediate),
             X509.Certificate.public_key(parsed_issuer)
           ) do
      {:ok, [{intermediate, parsed_intermediate} | issuer_chain]}
    else
      _other -> {:error, :ca_unavailable}
    end
  end

  defp validate_issuance_chain_link(_certificate, _parsed, _now, _seen) do
    {:error, :ca_unavailable}
  end

  defp lock_ca(certificate_id) do
    Repo.one(
      from(c in Certificate,
        where: c.id == ^certificate_id,
        lock: "FOR SHARE"
      )
    )
  end

  defp validate_issuance_ca_record(
         %Certificate{
           cert_type: cert_type,
           certificate_pem: certificate_pem,
           key_usage: key_usage,
           revoked: false,
           revoked_at: nil,
           revocation_reason: nil,
           valid_from: valid_from,
           valid_until: valid_until
         },
         now
       )
       when cert_type in [:root_ca, :intermediate_ca] and is_binary(certificate_pem) and
              is_list(key_usage) do
    if "keyCertSign" in key_usage and datetime_contains?(valid_from, valid_until, now),
      do: :ok,
      else: {:error, :ca_unavailable}
  end

  defp validate_issuance_ca_record(_certificate, _now), do: {:error, :ca_unavailable}

  defp validate_path_length_constraints(chain) do
    case Enum.reduce_while(chain, 0, &validate_ca_path_length/2) do
      {:error, :ca_unavailable} = error -> error
      _non_self_issued_count -> :ok
    end
  end

  defp validate_ca_path_length({_certificate, parsed}, non_self_issued_below) do
    case parsed_ca_path_length(parsed) do
      {:ok, :unlimited} ->
        continue_path_length_validation(parsed, non_self_issued_below)

      {:ok, limit} when non_self_issued_below <= limit ->
        continue_path_length_validation(parsed, non_self_issued_below)

      _other ->
        {:halt, {:error, :ca_unavailable}}
    end
  end

  defp continue_path_length_validation(parsed, non_self_issued_below) do
    next_count =
      if :public_key.pkix_is_self_signed(parsed),
        do: non_self_issued_below,
        else: non_self_issued_below + 1

    {:cont, next_count}
  end

  defp parsed_ca_path_length(parsed_certificate) do
    case X509.Certificate.extension(parsed_certificate, :basic_constraints) do
      {:Extension, _, true, {:BasicConstraints, true, :asn1_NOVALUE}} ->
        {:ok, :unlimited}

      {:Extension, _, true, {:BasicConstraints, true, limit}}
      when is_integer(limit) and limit >= 0 ->
        {:ok, limit}

      _other ->
        {:error, :ca_unavailable}
    end
  end

  defp validate_parsed_ca(parsed_certificate, now) do
    with {:Extension, _, true, {:BasicConstraints, true, _path_length}} <-
           X509.Certificate.extension(parsed_certificate, :basic_constraints),
         {:Extension, _, true, key_usage} <-
           X509.Certificate.extension(parsed_certificate, :key_usage),
         true <- :keyCertSign in key_usage,
         {:Validity, not_before, not_after} <-
           X509.Certificate.validity(parsed_certificate),
         true <-
           datetime_contains?(
             X509.DateTime.to_datetime(not_before),
             X509.DateTime.to_datetime(not_after),
             now
           ) do
      :ok
    else
      _other -> {:error, :ca_unavailable}
    end
  end

  defp parsed_valid_until(parsed_certificate) do
    {:Validity, _not_before, not_after} =
      X509.Certificate.validity(parsed_certificate)

    X509.DateTime.to_datetime(not_after)
  end

  defp datetime_contains?(%DateTime{} = valid_from, %DateTime{} = valid_until, now) do
    DateTime.compare(valid_from, now) in [:lt, :eq] and
      DateTime.compare(valid_until, now) == :gt
  end

  defp datetime_contains?(_valid_from, _valid_until, _now), do: false

  defp canonical_client_validity(now, chain_valid_until) do
    requested_valid_until =
      DateTime.add(now, @client_cert_validity_days * 24 * 60 * 60, :second)

    valid_until =
      if DateTime.compare(requested_valid_until, chain_valid_until) == :gt,
        do: chain_valid_until,
        else: requested_valid_until

    Validity.new(now, valid_until)
  end

  defp verify_issued_certificate(certificate_pem, issuer) do
    with {:ok, parsed_certificate} <- X509.Certificate.from_pem(certificate_pem),
         {:ok, parsed_issuer} <- X509.Certificate.from_pem(issuer.certificate_pem),
         true <- :public_key.pkix_is_issuer(parsed_certificate, parsed_issuer),
         true <-
           :public_key.pkix_verify(
             X509.Certificate.to_der(parsed_certificate),
             X509.Certificate.public_key(parsed_issuer)
           ) do
      :ok
    else
      _other -> {:error, :ca_unavailable}
    end
  rescue
    _error -> {:error, :ca_unavailable}
  end

  defp persisted_ca_chain(
         %Certificate{
           id: id,
           certificate_pem: certificate_pem,
           cert_type: cert_type
         } = certificate,
         seen
       )
       when cert_type in [:root_ca, :intermediate_ca] and is_binary(certificate_pem) do
    if MapSet.member?(seen, id) do
      {:error, :ca_unavailable}
    else
      continue_persisted_ca_chain(certificate, MapSet.put(seen, id))
    end
  end

  defp persisted_ca_chain(_certificate, _seen), do: {:error, :ca_unavailable}

  defp continue_persisted_ca_chain(
         %Certificate{certificate_pem: certificate_pem, issuer_id: nil},
         _seen
       ) do
    {:ok, [certificate_pem]}
  end

  defp continue_persisted_ca_chain(
         %Certificate{certificate_pem: certificate_pem, issuer_id: issuer_id},
         seen
       ) do
    with %Certificate{} = issuer <- Repo.get(Certificate, issuer_id),
         {:ok, issuer_chain} <- persisted_ca_chain(issuer, seen) do
      {:ok, [certificate_pem | issuer_chain]}
    else
      _other -> {:error, :ca_unavailable}
    end
  end

  defp validate_cn(cn) when is_binary(cn) and byte_size(cn) > 0, do: :ok
  defp validate_cn(_), do: {:error, "Common name cannot be empty"}

  defp validate_org(org) when is_binary(org) and byte_size(org) > 0, do: :ok
  defp validate_org(_), do: {:error, "Organization cannot be empty"}

  defp validate_key_opts(:rsa, key_size) when key_size in [2048, 4096], do: :ok
  defp validate_key_opts(:ecdsa, _), do: :ok
  defp validate_key_opts(:rsa, _), do: {:error, "Invalid RSA key size (must be 2048 or 4096)"}
  defp validate_key_opts(type, _), do: {:error, "Invalid key type: #{inspect(type)}"}

  defp private_key_pem_type(:ecdsa), do: {:private_key, :ecdsa}
  defp private_key_pem_type(_), do: :private_key

  defp detect_key_type(key) when elem(key, 0) == :RSAPrivateKey, do: :rsa
  defp detect_key_type(key) when elem(key, 0) == :ECPrivateKey, do: :ecdsa
  defp detect_key_type(_), do: :rsa

  # sha256WithRSAEncryption
  defp signature_algorithm(:rsa) do
    {:SignatureAlgorithm, {1, 2, 840, 113_549, 1, 1, 11}, {:asn1_OPENTYPE, <<5, 0>>}}
  end

  # ecdsa-with-SHA256
  defp signature_algorithm(:ecdsa) do
    {:SignatureAlgorithm, {1, 2, 840, 10_045, 4, 3, 2}, :asn1_NOVALUE}
  end

  defp generate_private_key(:rsa, key_size) do
    # Generate RSA private key
    private_key = :public_key.generate_key({:rsa, key_size, 65_537})
    {:ok, private_key}
  rescue
    e ->
      {:error, "Failed to generate RSA key: #{inspect(e)}"}
  end

  defp generate_private_key(:ecdsa, _key_size) do
    # Generate ECDSA private key using P-384 curve (OID: 1.3.132.0.34)
    private_key = :public_key.generate_key({:namedCurve, {1, 3, 132, 0, 34}})
    {:ok, private_key}
  rescue
    e ->
      {:error, "Failed to generate ECDSA key: #{inspect(e)}"}
  end

  defp extract_public_key({:RSAPrivateKey, _, modulus, exponent, _, _, _, _, _, _, _}, :rsa) do
    public_key = {:RSAPublicKey, modulus, exponent}
    {:ok, public_key}
  end

  defp extract_public_key(ec_key, :ecdsa) when elem(ec_key, 0) == :ECPrivateKey do
    # ECPrivateKey has parameters at index 3 and public key point at index 4
    params = elem(ec_key, 3)
    public_key_point = elem(ec_key, 4)
    {:ok, {public_key_point, params}}
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

    # Determine key type from private key
    key_type = detect_key_type(private_key)

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
        true,
        key_type
      )

    # Sign the certificate
    cert_der = :public_key.pkix_sign(tbs_cert, private_key)
    {:ok, cert_der}
  rescue
    e ->
      {:error, "Failed to create self-signed certificate: #{inspect(e)}"}
  end

  defp create_ca_signed_certificate(
         public_key,
         ca_private_key,
         ca_cert_pem,
         common_name,
         organization,
         sign_opts
       ) do
    validity_days = Keyword.fetch!(sign_opts, :validity_days)
    cert_type = Keyword.fetch!(sign_opts, :cert_type)
    opts = Keyword.get(sign_opts, :opts, [])
    # Parse CA certificate to get issuer
    {:ok, ca_cert_der} = pem_to_der(ca_cert_pem, :certificate)
    ca_cert = :public_key.pkix_decode_cert(ca_cert_der, :otp)

    # The new certificate issuer is the signing CA's subject.
    issuer = extract_subject(ca_cert)

    # Create subject for new certificate
    subject = build_subject(common_name, organization, opts)

    # Calculate validity period
    not_before = :calendar.universal_time()
    not_after = add_days(not_before, validity_days)

    # Generate serial number
    serial_number = generate_serial_number()

    # Create TBS certificate
    is_ca = cert_type in [:root_ca, :intermediate_ca]
    ca_key_type = detect_key_type(ca_private_key)

    tbs_cert =
      create_tbs_certificate(
        serial_number,
        issuer,
        subject,
        public_key,
        not_before,
        not_after,
        is_ca,
        ca_key_type
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

  defp create_tbs_certificate(
         serial,
         issuer,
         subject,
         public_key,
         not_before,
         not_after,
         is_ca,
         key_type
       ) do
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
      signature_algorithm(key_type),
      issuer,
      validity,
      subject,
      # subject public key info
      encode_public_key_info(public_key),
      # issuerUniqueID
      :asn1_NOVALUE,
      # subjectUniqueID
      :asn1_NOVALUE,
      build_extensions(public_key, is_ca)
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
    # ECDSA public key - must be wrapped in {:ECPoint, binary} for OTP
    {
      :OTPSubjectPublicKeyInfo,
      # ecPublicKey
      {:PublicKeyAlgorithm, {1, 2, 840, 10_045, 2, 1}, params},
      {:ECPoint, pub_key_bin}
    }
  end

  # OTPTBSCertificate extensions must carry decoded extension values; the
  # X509 helpers produce them in the shape :public_key.pkix_sign/2 expects.
  # Hand-encoding DER here previously double-wrapped the values, yielding CA
  # certificates whose KeyUsage decoded without keyCertSign — strict
  # validators (e.g. OpenSSL) rejected the entire chain.
  defp build_extensions(public_key, is_ca) do
    extensions = [
      Extension.subject_key_identifier(ski_public_key(public_key)),
      if is_ca do
        Extension.key_usage([:keyCertSign, :cRLSign])
      else
        Extension.key_usage([:digitalSignature, :keyEncipherment])
      end
    ]

    if is_ca do
      [Extension.basic_constraints(true) | extensions]
    else
      extensions
    end
  end

  # X509 expects EC public keys as {ec_point, parameters}; this module
  # carries them as {point_binary, parameters} (see extract_public_key/2).
  defp ski_public_key({point, params}) when is_binary(point), do: {{:ECPoint, point}, params}
  defp ski_public_key(public_key), do: public_key

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

  defp private_key_to_der(key, :ecdsa) when elem(key, 0) == :ECPrivateKey do
    :public_key.der_encode(:ECPrivateKey, key)
  end

  defp der_to_pem(der, :certificate) do
    pem_entry = {:Certificate, der, :not_encrypted}
    pem = :public_key.pem_encode([pem_entry])
    {:ok, pem}
  end

  defp der_to_pem(der, {:private_key, :ecdsa}) do
    pem_entry = {:ECPrivateKey, der, :not_encrypted}
    pem = :public_key.pem_encode([pem_entry])
    {:ok, pem}
  end

  defp der_to_pem(der, :private_key) do
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

  defp store_certificate(
         cert_pem,
         key_pem,
         cert_type,
         common_name,
         organization,
         _validity_days,
         issuer_id \\ nil,
         issuer_subject \\ nil
       ) do
    with {:ok, encrypted_key} <- encrypt_private_key(key_pem),
         {:ok, cert_der} <- pem_to_der(cert_pem, :certificate) do
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
        issuer: issuer_subject || build_subject_string(common_name, organization),
        common_name: common_name,
        organization: organization,
        valid_from: not_before,
        valid_until: not_after,
        cert_type: cert_type,
        key_usage: get_key_usage(cert_type),
        issuer_id: issuer_id,
        entity_type: "ca"
      }

      Repo.insert(cert_record)
    end
  end

  defp store_signed_certificate(
         cert_pem,
         cert_type,
         common_name,
         organization,
         _validity_days,
         issuer_cert_id,
         issuer_subject
       ) do
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
      issuer: issuer_subject || build_subject_string(common_name, organization),
      common_name: common_name,
      organization: organization,
      valid_from: not_before,
      valid_until: not_after,
      cert_type: cert_type,
      key_usage: get_key_usage(cert_type),
      issuer_id: issuer_cert_id,
      entity_type: to_string(cert_type)
    }

    Repo.insert(cert_record)
  end

  defp encrypt_private_key(key_pem) do
    master_key = pki_master_key()

    if is_binary(master_key) do
      Encryption.encrypt_to_blob(key_pem, master_key)
    else
      {:error, "Vault is sealed"}
    end
  end

  defp decrypt_private_key(encrypted_key) do
    master_key = pki_master_key()

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

  defp pki_master_key do
    case Process.whereis(SealState) do
      nil ->
        dev_fallback_key()

      _pid ->
        case SealState.get_master_key() do
          {:ok, key} -> key
          {:error, _reason} -> if(dev_pki_unsealed_fallback?(), do: dev_fallback_key())
        end
    end
  end

  defp dev_pki_unsealed_fallback? do
    Application.get_env(:secrethub_core, :dev_pki_unsealed_fallback, false)
  end

  defp dev_fallback_key do
    :crypto.hash(:sha256, "test-encryption-key-for-pki-testing")
  end

  defp fetch_ca_certificate(cert_id) do
    case cert_id && Repo.get(Certificate, cert_id) do
      nil when is_nil(cert_id) -> {:error, "Root CA certificate is required"}
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

    # Parse CA cert to get the signing issuer subject.
    {:ok, ca_cert_der} = pem_to_der(ca_cert.certificate_pem, :certificate)
    ca_cert_decoded = :public_key.pkix_decode_cert(ca_cert_der, :otp)
    issuer = extract_subject(ca_cert_decoded)

    # Calculate validity
    not_before = :calendar.universal_time()
    not_after = add_days(not_before, validity_days)

    # Generate serial
    serial_number = generate_serial_number()

    # Create TBS certificate
    is_ca = cert_type in [:root_ca, :intermediate_ca]

    ca_key_type = detect_key_type(ca_key)

    tbs_cert =
      create_tbs_certificate(
        serial_number,
        issuer,
        subject,
        public_key,
        not_before,
        not_after,
        is_ca,
        ca_key_type
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

  defp extract_subject(
         {:OTPCertificate, {:OTPTBSCertificate, _, _, _, _, _, subject, _, _, _, _}, _, _}
       ) do
    subject
  end

  defp extract_subject_from_csr(
         {:CertificationRequest, {:CertificationRequestInfo, _, subject, _, _}, _, _}
       ) do
    # Convert CSR subject from raw DER to OTP-compatible format
    # CSR subjects may have raw binary values that need to be wrapped in tagged tuples
    convert_subject_for_otp(subject)
  end

  defp convert_subject_for_otp({:rdnSequence, rdn_sets}) do
    converted =
      Enum.map(rdn_sets, fn rdn_set ->
        Enum.map(rdn_set, fn {:AttributeTypeAndValue, oid, value} ->
          {:AttributeTypeAndValue, oid, convert_attribute_value(oid, value)}
        end)
      end)

    {:rdnSequence, converted}
  end

  # If value is already a tagged tuple, pass through
  defp convert_attribute_value(_oid, {:utf8String, _} = v), do: v
  defp convert_attribute_value(_oid, {:printableString, _} = v), do: v
  defp convert_attribute_value(_oid, {:ia5String, _} = v), do: v
  defp convert_attribute_value(_oid, {:teletexString, _} = v), do: v

  # If value is raw DER binary, decode the ASN.1 tag and wrap appropriately
  defp convert_attribute_value(_oid, value) when is_binary(value) do
    case value do
      # UTF8String (tag 0x0C)
      <<0x0C, rest::binary>> ->
        # Extract length and value
        {str_bytes, _} = decode_asn1_length_and_value(rest)
        {:utf8String, str_bytes}

      # PrintableString (tag 0x13)
      <<0x13, rest::binary>> ->
        {str_bytes, _} = decode_asn1_length_and_value(rest)
        {:printableString, str_bytes}

      # IA5String (tag 0x16)
      <<0x16, rest::binary>> ->
        {str_bytes, _} = decode_asn1_length_and_value(rest)
        {:ia5String, str_bytes}

      # Fallback: wrap as utf8String
      _ ->
        {:utf8String, value}
    end
  end

  defp convert_attribute_value(_oid, value), do: value

  defp decode_asn1_length_and_value(<<length, rest::binary>>) when length < 128 do
    <<value::binary-size(length), remaining::binary>> = rest
    {value, remaining}
  end

  defp decode_asn1_length_and_value(<<0x81, length, rest::binary>>) do
    <<value::binary-size(length), remaining::binary>> = rest
    {value, remaining}
  end

  defp decode_asn1_length_and_value(<<0x82, length::16, rest::binary>>) do
    <<value::binary-size(length), remaining::binary>> = rest
    {value, remaining}
  end

  defp extract_public_key_from_csr(
         {:CertificationRequest, {:CertificationRequestInfo, _, _, spki, _}, _, _}
       ) do
    # Extract public key from SubjectPublicKeyInfo
    case spki do
      {:CertificationRequestInfo_subjectPKInfo, algo_info, pub_key_der} ->
        case algo_info do
          {:CertificationRequestInfo_subjectPKInfo_algorithm, {1, 2, 840, 113_549, 1, 1, 1}, _} ->
            # RSA public key - decode from DER
            :public_key.der_decode(:RSAPublicKey, pub_key_der)

          {:CertificationRequestInfo_subjectPKInfo_algorithm, {1, 2, 840, 10_045, 2, 1}, params} ->
            # ECDSA public key
            {pub_key_der, params}

          _ ->
            pub_key_der
        end

      {:SubjectPublicKeyInfo, _, public_key} ->
        public_key
    end
  end

  defp extract_cn_from_csr(csr) do
    # Get the converted subject (already OTP-compatible)
    subject = extract_subject_from_csr(csr)
    {:rdnSequence, rdns} = subject

    # Find CN attribute (OID 2.5.4.3)
    cn =
      Enum.find_value(rdns, fn rdn_set ->
        Enum.find_value(rdn_set, fn
          {:AttributeTypeAndValue, {2, 5, 4, 3}, {:utf8String, cn_value}} ->
            to_string(cn_value)

          {:AttributeTypeAndValue, {2, 5, 4, 3}, {:printableString, cn_value}} ->
            to_string(cn_value)

          _ ->
            nil
        end)
      end)

    if cn, do: {:ok, cn}, else: {:error, "CN not found in CSR"}
  end

  defp calculate_fingerprint(cert_pem) do
    hash =
      :crypto.hash(:sha256, cert_pem)
      |> Base.encode16(case: :lower)
      |> String.graphemes()
      |> Enum.chunk_every(2)
      |> Enum.map_join(":", &Enum.join/1)

    "sha256:#{hash}"
  end

  defp build_subject_string(common_name, organization) do
    "CN=#{common_name}, O=#{organization}"
  end

  defp get_key_usage(:root_ca), do: ["keyCertSign", "cRLSign"]
  defp get_key_usage(:intermediate_ca), do: ["keyCertSign", "cRLSign"]
  defp get_key_usage(_), do: ["digitalSignature", "keyEncipherment"]

  defp record_ca_initialized_event(cert_record, key_type, key_size, validity_days, opts) do
    metadata =
      %{
        cert_id: cert_record.id,
        serial: cert_record.serial_number,
        fingerprint: cert_record.fingerprint,
        subject: cert_record.subject,
        issuer_subject: cert_record.issuer,
        common_name: cert_record.common_name,
        organization: cert_record.organization,
        certificate_type: cert_record.cert_type,
        key_type: to_string(key_type),
        key_size: key_size,
        validity_days: validity_days,
        not_before: DateTime.to_iso8601(cert_record.valid_from),
        not_after: DateTime.to_iso8601(cert_record.valid_until)
      }
      |> maybe_put(:issuer_ca_id, Keyword.get(opts, :issuer_ca_id))

    append_event(
      :ca_initialized,
      metadata,
      ca_id: cert_record.id,
      actor: Keyword.get(opts, :actor),
      correlation_id: Keyword.get(opts, :correlation_id)
    )
  end

  defp record_certificate_issued_event(cert_record, ca_cert, validity_days, opts) do
    append_event(
      :certificate_issued,
      %{
        cert_id: cert_record.id,
        serial: cert_record.serial_number,
        fingerprint: cert_record.fingerprint,
        subject: cert_record.subject,
        issuer_ca_id: ca_cert.id,
        issuer_subject: cert_record.issuer,
        certificate_type: cert_record.cert_type,
        validity_days: validity_days,
        not_before: DateTime.to_iso8601(cert_record.valid_from),
        not_after: DateTime.to_iso8601(cert_record.valid_until)
      },
      ca_id: ca_cert.id,
      actor: Keyword.get(opts, :actor),
      correlation_id: Keyword.get(opts, :correlation_id)
    )
  end

  defp record_certificate_revoked_event(cert_record, reason) do
    ca_id = cert_record.issuer_id || cert_record.id

    append_event(
      :certificate_revoked,
      %{
        cert_id: cert_record.id,
        serial: cert_record.serial_number,
        subject: cert_record.subject,
        issuer_ca_id: cert_record.issuer_id,
        issuer_subject: cert_record.issuer,
        reason: reason,
        revocation_date: DateTime.to_iso8601(cert_record.revoked_at)
      },
      ca_id: ca_id
    )
  end

  defp append_event(event_type, metadata, opts) do
    case Events.append(event_type, metadata, opts) do
      {:ok, _event} ->
        :ok

      {:error, reason} ->
        {:error, "Failed to record PKI event: #{inspect(reason)}"}
    end
  end

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  @doc """
  Get the CA certificate chain (root + intermediates) for client verification.

  Returns the certificate chain in PEM format, suitable for client mTLS connections.

  ## Returns

  - `{:ok, ca_chain_pem}` - CA chain as PEM string
  - `{:error, reason}` - Failed to retrieve CA chain
  """
  @spec get_ca_chain() :: {:ok, String.t()} | {:error, term()}
  def get_ca_chain do
    case get_ca_chain_pems() do
      {:ok, certificates} -> {:ok, Enum.join(certificates, "\n")}
      {:error, :ca_unavailable} -> {:error, "No CA certificates found"}
    end
  end

  defp active_ca_chain_query do
    from(c in Certificate,
      where: c.cert_type in [:root_ca, :intermediate_ca] and c.revoked == false,
      order_by: [desc: c.cert_type, asc: c.inserted_at],
      select: c.certificate_pem
    )
  end

  @doc """
  Get a certificate by ID.
  TODO: Implement proper certificate retrieval.
  """
  def get_certificate(cert_id) do
    case Repo.get(Certificate, cert_id) do
      nil -> {:error, :not_found}
      cert -> {:ok, cert}
    end
  end

  @doc """
  Revoke a certificate.
  TODO: Implement proper certificate revocation with CRL updates.
  """
  def revoke_certificate(cert_id, reason \\ "manual_revocation") do
    with {:ok, uuid} <- Ecto.UUID.cast(cert_id),
         %Certificate{} = cert <- Repo.get(Certificate, uuid) do
      cert
      |> Certificate.revoke_changeset(reason)
      |> Repo.update()
      |> case do
        {:ok, revoked_cert} ->
          with :ok <- record_certificate_revoked_event(revoked_cert, reason) do
            {:ok, revoked_cert}
          end

        {:error, _reason} = error ->
          error
      end
    else
      :error -> {:error, :not_found}
      nil -> {:error, :not_found}
    end
  end

  @doc """
  Permanently delete a certificate.
  """
  @spec delete_certificate(binary()) :: {:ok, Certificate.t()} | {:error, term()}
  def delete_certificate(cert_id) do
    with {:ok, uuid} <- Ecto.UUID.cast(cert_id),
         %Certificate{} = cert <- Repo.get(Certificate, uuid) do
      cert
      |> Ecto.Changeset.change()
      |> Ecto.Changeset.no_assoc_constraint(:issued_bootstrap_tokens)
      |> Ecto.Changeset.no_assoc_constraint(:renewals_from)
      |> Ecto.Changeset.no_assoc_constraint(:renewals_issued)
      |> Repo.delete()
    else
      :error -> {:error, :not_found}
      nil -> {:error, :not_found}
    end
  end

  @doc """
  List all certificates.
  TODO: Add pagination and filtering options.
  """
  def list_certificates do
    Repo.all(Certificate)
  end

  @doc """
  Issues an agent client certificate.

  Tries to sign with an active intermediate CA (preferred) or root CA.
  If no CA exists, generates a self-signed agent certificate.

  ## Parameters
  - `agent_id`: The agent's identifier (used as CN)
  - `opts`: Optional parameters
    - `:validity_days` - Certificate validity (default: 365)
    - `:key_type` - Key type (default: :rsa)
    - `:key_size` - Key size (default: 2048)

  ## Returns
  - `{:ok, %Certificate{}}` on success
  - `{:error, reason}` on failure
  """
  @spec issue_agent_certificate(String.t(), keyword()) ::
          {:ok, Certificate.t()} | {:error, String.t()}
  def issue_agent_certificate(agent_id, opts \\ []) do
    key_type = Keyword.get(opts, :key_type, :rsa)
    key_size = Keyword.get(opts, :key_size, 2048)
    validity_days = Keyword.get(opts, :validity_days, @client_cert_validity_days)
    organization = "SecretHub"

    Logger.info("Issuing agent certificate for: #{agent_id}")

    with {:ok, private_key} <- generate_private_key(key_type, key_size),
         {:ok, public_key} <- extract_public_key(private_key, key_type) do
      case find_active_ca() do
        {:ok, ca_cert} ->
          issue_ca_signed_agent_cert(
            agent_id,
            organization,
            public_key,
            ca_cert,
            validity_days,
            opts
          )

        {:error, _} ->
          issue_self_signed_agent_cert(
            agent_id,
            organization,
            private_key,
            public_key,
            validity_days,
            opts
          )
      end
    else
      {:error, reason} ->
        Logger.error("Failed to issue agent certificate for #{agent_id}: #{inspect(reason)}")
        {:error, "Failed to generate key: #{inspect(reason)}"}
    end
  end

  defp find_active_ca do
    # Prefer intermediate CA, fall back to root CA
    query =
      from(c in Certificate,
        where: c.cert_type in [:intermediate_ca, :root_ca] and c.revoked == false,
        where: c.valid_until > ^(DateTime.utc_now() |> DateTime.truncate(:second)),
        order_by: [desc: c.cert_type, desc: c.inserted_at],
        limit: 1
      )

    case Repo.one(query) do
      nil -> {:error, :no_ca_available}
      ca -> {:ok, ca}
    end
  end

  defp issue_ca_signed_agent_cert(
         agent_id,
         organization,
         public_key,
         ca_cert,
         validity_days,
         opts
       ) do
    with {:ok, ca_key} <- decrypt_private_key(ca_cert.private_key_encrypted),
         {:ok, cert_der} <-
           create_ca_signed_certificate(
             public_key,
             ca_key,
             ca_cert.certificate_pem,
             agent_id,
             organization,
             validity_days: validity_days,
             cert_type: :agent_client,
             opts: opts
           ),
         {:ok, cert_pem} <- der_to_pem(cert_der, :certificate),
         {:ok, cert_record} <-
           store_signed_certificate(
             cert_pem,
             :agent_client,
             agent_id,
             organization,
             validity_days,
             ca_cert.id,
             ca_cert.subject
           ) do
      Logger.info("CA-signed agent certificate issued for: #{agent_id}")
      {:ok, cert_record}
    end
  end

  defp issue_self_signed_agent_cert(
         agent_id,
         organization,
         private_key,
         public_key,
         validity_days,
         opts
       ) do
    with {:ok, cert_der} <-
           create_self_signed_certificate(
             private_key,
             public_key,
             agent_id,
             organization,
             validity_days,
             opts
           ),
         {:ok, cert_pem} <- der_to_pem(cert_der, :certificate),
         {:ok, cert_record} <-
           store_signed_certificate(
             cert_pem,
             :agent_client,
             agent_id,
             organization,
             validity_days,
             nil,
             nil
           ) do
      Logger.info("Self-signed agent certificate issued for: #{agent_id}")
      {:ok, cert_record}
    end
  end
end
