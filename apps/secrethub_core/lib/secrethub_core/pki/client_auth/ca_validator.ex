defmodule SecretHub.Core.PKI.ClientAuth.CAValidator do
  @moduledoc """
  Derives and validates all CA constraints, cryptographic properties,
  and validity windows directly from the parsed X.509 certificate and decrypted key.
  """

  alias SecretHub.Core.PKI.CertificateIdentity

  @oid_basic_constraints {2, 5, 29, 19}
  @oid_key_usage {2, 5, 29, 15}

  @doc """
  Validates an active Client Auth CA certificate and private key.

  Options:
  - `now`: DateTime (default UTC now)
  - `requested_ttl`: integer in seconds (default 0)
  - `clock_skew`: integer in seconds (default 60)
  """
  @spec validate(map(), any(), tuple() | term(), keyword()) :: :ok | {:error, atom(), String.t()}
  def validate(authority, ca_record, ca_key, opts \\ []) do
    now = Keyword.get(opts, :now, DateTime.utc_now())
    requested_ttl = Keyword.get(opts, :requested_ttl, 0)
    clock_skew = Keyword.get(opts, :clock_skew, 60)
    min_required_remaining = requested_ttl + clock_skew

    with {:ok, parsed_ca} <- parse_certificate_pem(ca_record.certificate_pem),
         :ok <- validate_validity_window(parsed_ca, now, min_required_remaining),
         :ok <- validate_self_signature(parsed_ca),
         :ok <- validate_basic_constraints(parsed_ca),
         :ok <- validate_key_usage(parsed_ca),
         :ok <- validate_key_match(ca_key, parsed_ca),
         :ok <- validate_algorithm_match(authority.key_algorithm, ca_key, parsed_ca),
         :ok <- validate_fingerprint_match(ca_record, parsed_ca) do
      :ok
    end
  end

  defp parse_certificate_pem(pem) when is_binary(pem) do
    case X509.Certificate.from_pem(pem) do
      {:ok, cert} -> {:ok, cert}
      _ -> {:error, :ca_parse_failed, "Failed to parse CA certificate PEM"}
    end
  end

  defp validate_validity_window(parsed_ca, now, min_required_remaining) do
    {:Validity, not_before_otp, not_after_otp} = X509.Certificate.validity(parsed_ca)
    not_before = otp_time_to_datetime(not_before_otp)
    not_after = otp_time_to_datetime(not_after_otp)

    cond do
      DateTime.compare(not_before, now) == :gt ->
        {:error, :ca_not_yet_valid, "CA certificate is not yet valid"}

      DateTime.compare(not_after, now) != :gt ->
        {:error, :ca_expired, "CA certificate has expired"}

      DateTime.diff(not_after, now) < min_required_remaining ->
        {:error, :ca_insufficient_lifetime,
         "CA certificate has insufficient remaining lifetime (#{DateTime.diff(not_after, now)}s < #{min_required_remaining}s required)"}

      true ->
        :ok
    end
  end

  defp validate_self_signature(parsed_ca) do
    ca_der = X509.Certificate.to_der(parsed_ca)
    ca_pub = X509.Certificate.public_key(parsed_ca)

    if :public_key.pkix_verify(ca_der, ca_pub) do
      :ok
    else
      {:error, :ca_signature_invalid, "CA certificate self-signature verification failed"}
    end
  end

  defp validate_basic_constraints(parsed_ca) do
    case X509.Certificate.extension(parsed_ca, @oid_basic_constraints) do
      {:Extension, @oid_basic_constraints, true, {:BasicConstraints, true, _path_len}} ->
        :ok

      _ ->
        {:error, :ca_basic_constraints_invalid,
         "CA certificate must have a critical BasicConstraints extension with CA:TRUE"}
    end
  end

  defp validate_key_usage(parsed_ca) do
    case X509.Certificate.extension(parsed_ca, @oid_key_usage) do
      {:Extension, @oid_key_usage, true, key_usages} when is_list(key_usages) ->
        if :keyCertSign in key_usages and :cRLSign in key_usages do
          :ok
        else
          {:error, :ca_key_usage_invalid,
           "CA certificate KeyUsage extension must include keyCertSign and cRLSign"}
        end

      _ ->
        {:error, :ca_key_usage_invalid, "CA certificate must have a critical KeyUsage extension"}
    end
  end

  defp validate_key_match(ca_key, parsed_ca) do
    derived_pub = X509.PublicKey.derive(ca_key)
    cert_pub = X509.Certificate.public_key(parsed_ca)

    if derived_pub == cert_pub do
      :ok
    else
      {:error, :ca_key_mismatch, "CA private key does not match CA certificate public key"}
    end
  end

  defp validate_algorithm_match(key_algorithm, ca_key, _parsed_ca) do
    case {key_algorithm, ca_key} do
      {"ecdsa_p384", {:ECPrivateKey, _, _, {:namedCurve, {1, 3, 132, 0, 34}}, _, _}} ->
        :ok

      {"rsa_4096", {:RSAPrivateKey, _, n, _, _, _, _, _, _, _, _}} ->
        if :erlang.byte_size(:binary.encode_unsigned(n)) * 8 >= 4096 do
          :ok
        else
          {:error, :ca_key_algorithm_mismatch, "RSA key size is less than 4096 bits"}
        end

      {algo, _} ->
        {:error, :ca_key_algorithm_mismatch,
         "Authority algorithm #{algo} does not match actual CA private key"}
    end
  end

  defp validate_fingerprint_match(ca_record, parsed_ca) do
    ca_der = X509.Certificate.to_der(parsed_ca)
    expected_fp = CertificateIdentity.canonical_fingerprint_from_der(ca_der)

    if ca_record.canonical_fingerprint == nil or ca_record.canonical_fingerprint == expected_fp do
      :ok
    else
      {:error, :ca_fingerprint_mismatch,
       "CA record canonical fingerprint does not match calculated certificate fingerprint"}
    end
  end

  defp otp_time_to_datetime({:utcTime, [y1, y2, m1, m2, d1, d2, h1, h2, min1, min2, s1, s2, ?Z]}) do
    y = List.to_integer([y1, y2])
    year = if y >= 50, do: 1900 + y, else: 2000 + y
    month = List.to_integer([m1, m2])
    day = List.to_integer([d1, d2])
    hour = List.to_integer([h1, h2])
    min = List.to_integer([min1, min2])
    sec = List.to_integer([s1, s2])
    {:ok, dt} = DateTime.new(Date.new!(year, month, day), Time.new!(hour, min, sec))
    dt
  end

  defp otp_time_to_datetime(
         {:generalTime, [y1, y2, y3, y4, m1, m2, d1, d2, h1, h2, min1, min2, s1, s2, ?Z]}
       ) do
    year = List.to_integer([y1, y2, y3, y4])
    month = List.to_integer([m1, m2])
    day = List.to_integer([d1, d2])
    hour = List.to_integer([h1, h2])
    min = List.to_integer([min1, min2])
    sec = List.to_integer([s1, s2])
    {:ok, dt} = DateTime.new(Date.new!(year, month, day), Time.new!(hour, min, sec))
    dt
  end

  defp otp_time_to_datetime(_), do: DateTime.utc_now()
end
