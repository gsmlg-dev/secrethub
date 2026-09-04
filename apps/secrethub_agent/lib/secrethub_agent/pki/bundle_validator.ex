defmodule SecretHub.Agent.PKI.BundleValidator do
  @moduledoc """
  Validates public trust bundles on the SecretHub Agent host before applying them to disk.

  Enforces:
  - Strict payload format and type validation
  - Cryptographic transcript hash integrity
  - CA PEM validity, self-signature, Basic Constraints (cA: true), Key Usage (keyCertSign, cRLSign),
    validity bounds, and matching canonical DER SHA-256 fingerprint (including pinned CA continuity)
  - Signed CRL PEM validity, matching DER SHA-256 fingerprint, signature verification against the CA
  - Match between declared metadata and signed ASN.1 CRL fields (crl_number, thisUpdate, nextUpdate)
  - Signed CRL thisUpdate and nextUpdate temporal validity bounds with clock skew tolerance
  """

  require Logger

  @schema_version 1
  @clock_skew_seconds 300

  @doc """
  Validates a trust bundle map.
  Returns `{:ok, validated_info}` or `{:error, error_code, detail_message}`.
  """
  @spec validate(map(), keyword()) ::
          {:ok, map()}
          | {:error, atom(), String.t()}
  def validate(bundle, opts \\ [])

  def validate(bundle, opts) when is_map(bundle) do
    now = Keyword.get(opts, :now, DateTime.utc_now() |> DateTime.truncate(:second))
    clock_skew = Keyword.get(opts, :clock_skew_seconds, @clock_skew_seconds)
    pinned_ca_fingerprint = Keyword.get(opts, :pinned_ca_fingerprint)

    with :ok <- validate_schema_and_types(bundle),
         :ok <- validate_transcript_hash(bundle),
         {:ok, parsed_ca} <-
           validate_ca_certificate(bundle, now, clock_skew, pinned_ca_fingerprint),
         {:ok, parsed_crl} <- validate_crl(bundle, parsed_ca, now, clock_skew) do
      {:ok,
       %{
         schema_version: bundle["schema_version"],
         authority: bundle["authority"],
         generation: bundle["generation"],
         crl_number: bundle["crl_number"],
         ca_fingerprint: bundle["ca_fingerprint"],
         crl_der_sha256: bundle["crl_der_sha256"],
         bundle_sha256: bundle["bundle_sha256"],
         ca_bundle_pem: bundle["ca_bundle_pem"],
         crl_pem: bundle["crl_pem"],
         this_update: bundle["this_update"],
         next_update: bundle["next_update"],
         parsed_ca: parsed_ca,
         parsed_crl: parsed_crl
       }}
    end
  rescue
    e ->
      {:error, :validation_exception, "Validation raised exception: #{Exception.message(e)}"}
  end

  def validate(_, _), do: {:error, :invalid_payload_format, "Bundle must be a map"}

  @doc """
  Validates trust bundle files directly from disk (<gen_dir>/ca.crt, crl.pem, manifest.json)
  or from base directory containing `current` symlink.
  """
  def validate_disk_bundle(target_dir, opts \\ []) do
    dir =
      if File.exists?(Path.join(target_dir, "manifest.json")) do
        target_dir
      else
        Path.join(target_dir, "current")
      end

    with {:ok, manifest_content} <- File.read(Path.join(dir, "manifest.json")),
         {:ok, manifest} <- Jason.decode(manifest_content),
         {:ok, ca_pem} <- File.read(Path.join(dir, "ca.crt")),
         {:ok, crl_pem} <- File.read(Path.join(dir, "crl.pem")) do
      bundle =
        manifest
        |> Map.put("ca_bundle_pem", ca_pem)
        |> Map.put("crl_pem", crl_pem)

      validate(bundle, opts)
    else
      {:error, reason} ->
        {:error, :disk_bundle_invalid, "Failed to read or decode disk bundle: #{inspect(reason)}"}
    end
  end

  # Schema and type checking

  defp validate_schema_and_types(bundle) do
    case bundle["schema_version"] do
      @schema_version ->
        required_string_fields = [
          "authority",
          "ca_fingerprint",
          "crl_der_sha256",
          "bundle_sha256",
          "ca_bundle_pem",
          "crl_pem",
          "this_update",
          "next_update"
        ]

        required_int_fields = ["generation", "crl_number"]

        missing_string =
          Enum.find(required_string_fields, fn f ->
            val = bundle[f]
            !is_binary(val) or byte_size(val) == 0
          end)

        missing_int =
          Enum.find(required_int_fields, fn f ->
            val = bundle[f]
            !is_integer(val) or val < 0
          end)

        cond do
          missing_string ->
            {:error, :invalid_payload_format,
             "Missing or invalid string field: #{missing_string}"}

          missing_int ->
            {:error, :invalid_payload_format, "Missing or invalid integer field: #{missing_int}"}

          true ->
            :ok
        end

      v when is_integer(v) ->
        {:error, :invalid_schema_version, "Unsupported schema version: #{inspect(v)}"}

      _ ->
        {:error, :invalid_schema_version, "Missing or invalid schema_version field"}
    end
  end

  defp validate_transcript_hash(bundle) do
    expected_hash = bundle["bundle_sha256"]

    if is_binary(expected_hash) and String.length(expected_hash) == 64 do
      transcript =
        [
          bundle["schema_version"],
          bundle["authority"],
          bundle["generation"],
          bundle["ca_fingerprint"],
          bundle["crl_number"],
          bundle["crl_der_sha256"],
          bundle["this_update"],
          bundle["next_update"],
          bundle["ca_bundle_pem"],
          bundle["crl_pem"]
        ]
        |> Enum.map(&to_string/1)
        |> Enum.join("|")

      calculated_hash =
        :crypto.hash(:sha256, transcript)
        |> Base.encode16(case: :lower)

      if Plug.Crypto.secure_compare(calculated_hash, expected_hash) do
        :ok
      else
        {:error, :transcript_hash_mismatch,
         "Calculated hash #{calculated_hash} does not match bundle_sha256 #{expected_hash}"}
      end
    else
      {:error, :transcript_hash_mismatch, "Missing or malformed bundle_sha256"}
    end
  end

  defp validate_ca_certificate(bundle, now, clock_skew, pinned_ca_fingerprint) do
    ca_pem = bundle["ca_bundle_pem"]
    expected_fingerprint = bundle["ca_fingerprint"]

    case X509.Certificate.from_pem(ca_pem) do
      {:ok, parsed_ca} ->
        ca_der = X509.Certificate.to_der(parsed_ca)

        calculated_fingerprint =
          :crypto.hash(:sha256, ca_der)
          |> Base.encode16(case: :lower)

        with :ok <- verify_ca_fingerprint(calculated_fingerprint, expected_fingerprint),
             :ok <- verify_pinned_ca(calculated_fingerprint, pinned_ca_fingerprint),
             :ok <- verify_ca_self_signature(parsed_ca, ca_der),
             :ok <- verify_ca_basic_constraints(parsed_ca),
             :ok <- verify_ca_key_usage(parsed_ca),
             :ok <- verify_ca_validity(parsed_ca, now, clock_skew) do
          {:ok, parsed_ca}
        end

      {:error, reason} ->
        {:error, :invalid_ca_bundle, "Failed to parse CA bundle PEM: #{inspect(reason)}"}
    end
  end

  defp verify_ca_fingerprint(calc, expected) do
    if Plug.Crypto.secure_compare(calc, String.downcase(expected)) do
      :ok
    else
      {:error, :ca_fingerprint_mismatch,
       "CA DER hash #{calc} does not match expected #{expected}"}
    end
  end

  defp verify_pinned_ca(_calc, nil), do: :ok

  defp verify_pinned_ca(calc, pinned) do
    if Plug.Crypto.secure_compare(calc, String.downcase(pinned)) do
      :ok
    else
      {:error, :ca_fingerprint_mismatch,
       "CA DER hash #{calc} does not match pinned CA fingerprint #{pinned}"}
    end
  end

  defp verify_ca_self_signature(parsed_ca, ca_der) do
    ca_pub_key = X509.Certificate.public_key(parsed_ca)

    case :public_key.pkix_verify(ca_der, ca_pub_key) do
      true ->
        :ok

      false ->
        {:error, :ca_signature_invalid, "CA certificate is not validly self-signed"}
    end
  rescue
    e ->
      {:error, :ca_signature_invalid, "CA self-signature check failed: #{Exception.message(e)}"}
  end

  defp verify_ca_basic_constraints(parsed_ca) do
    case X509.Certificate.extension(parsed_ca, :basic_constraints) do
      {:Extension, _oid, _crit, {:BasicConstraints, true, _}} ->
        :ok

      {:Extension, _oid, _crit, true} ->
        :ok

      nil ->
        {:error, :ca_not_a_ca, "CA certificate missing basic constraints extension"}

      _ ->
        {:error, :ca_not_a_ca, "CA certificate basic constraints must have cA: true"}
    end
  end

  defp verify_ca_key_usage(parsed_ca) do
    case X509.Certificate.extension(parsed_ca, :key_usage) do
      {:Extension, _oid, _crit, usages} when is_list(usages) ->
        if :keyCertSign in usages and :cRLSign in usages do
          :ok
        else
          {:error, :ca_invalid_key_usage,
           "CA certificate key usage must include keyCertSign and cRLSign"}
        end

      nil ->
        {:error, :ca_invalid_key_usage, "CA certificate missing key_usage extension"}

      _ ->
        {:error, :ca_invalid_key_usage, "Invalid key_usage extension on CA certificate"}
    end
  end

  defp verify_ca_validity(parsed_ca, now, clock_skew) do
    {:Validity, not_before_asn1, not_after_asn1} = X509.Certificate.validity(parsed_ca)
    not_before = X509.DateTime.to_datetime(not_before_asn1)
    not_after = X509.DateTime.to_datetime(not_after_asn1)

    skew_adjusted_now_earliest = DateTime.add(now, -clock_skew, :second)
    skew_adjusted_now_latest = DateTime.add(now, clock_skew, :second)

    cond do
      DateTime.compare(not_before, skew_adjusted_now_latest) == :gt ->
        {:error, :ca_not_yet_valid,
         "CA certificate notBefore #{DateTime.to_iso8601(not_before)} is in the future"}

      DateTime.compare(not_after, skew_adjusted_now_earliest) == :lt ->
        {:error, :ca_expired,
         "CA certificate has expired (valid until #{DateTime.to_iso8601(not_after)})"}

      true ->
        :ok
    end
  end

  defp validate_crl(bundle, parsed_ca, now, clock_skew) do
    crl_pem = bundle["crl_pem"]
    expected_crl_hash = bundle["crl_der_sha256"]

    with {:ok, parsed_crl} <- parse_crl(crl_pem),
         :ok <- verify_crl_hash(parsed_crl, expected_crl_hash),
         :ok <- verify_crl_signature(parsed_crl, parsed_ca),
         :ok <- verify_signed_crl_number(parsed_crl, bundle["crl_number"]),
         :ok <- verify_signed_crl_metadata_and_validity(parsed_crl, bundle, now, clock_skew) do
      {:ok, parsed_crl}
    end
  end

  defp parse_crl(crl_pem) do
    case X509.CRL.from_pem(crl_pem) do
      {:ok, parsed_crl} -> {:ok, parsed_crl}
      {:error, reason} -> {:error, :invalid_crl, "Failed to parse CRL PEM: #{inspect(reason)}"}
    end
  end

  defp verify_crl_hash(parsed_crl, expected_hash) do
    crl_der = X509.CRL.to_der(parsed_crl)

    calculated_crl_hash =
      :crypto.hash(:sha256, crl_der)
      |> Base.encode16(case: :lower)

    if Plug.Crypto.secure_compare(calculated_crl_hash, String.downcase(expected_hash)) do
      :ok
    else
      {:error, :crl_fingerprint_mismatch,
       "CRL DER hash #{calculated_crl_hash} does not match expected #{expected_hash}"}
    end
  end

  defp verify_crl_signature(parsed_crl, parsed_ca) do
    if X509.CRL.valid?(parsed_crl, parsed_ca) do
      :ok
    else
      {:error, :crl_signature_invalid, "CRL signature is invalid against issuing CA"}
    end
  rescue
    e ->
      {:error, :crl_signature_invalid, "CRL signature check failed: #{Exception.message(e)}"}
  end

  defp verify_signed_crl_number(parsed_crl, expected_crl_number) do
    signed_number = extract_signed_crl_number(parsed_crl)

    if signed_number != nil and signed_number == expected_crl_number do
      :ok
    else
      {:error, :crl_number_mismatch,
       "Signed CRL number #{inspect(signed_number)} does not match bundle crl_number #{inspect(expected_crl_number)}"}
    end
  end

  defp extract_signed_crl_number(parsed_crl) do
    case X509.CRL.extension(parsed_crl, :crl_number) do
      nil ->
        nil

      {:Extension, _oid, _crit, num} when is_integer(num) ->
        num

      {:Extension, _oid, _crit, der} when is_binary(der) ->
        case :public_key.der_decode(:CRLNumber, der) do
          num when is_integer(num) -> num
          _ -> nil
        end

      _ ->
        nil
    end
  rescue
    _ -> nil
  end

  defp verify_signed_crl_metadata_and_validity(parsed_crl, bundle, now, clock_skew) do
    signed_this_update = X509.CRL.this_update(parsed_crl)
    signed_next_update = X509.CRL.next_update(parsed_crl)

    with {:ok, declared_this_update, _} <- DateTime.from_iso8601(bundle["this_update"]),
         {:ok, declared_next_update, _} <- DateTime.from_iso8601(bundle["next_update"]) do
      skew_adjusted_now_earliest = DateTime.add(now, -clock_skew, :second)
      skew_adjusted_now_latest = DateTime.add(now, clock_skew, :second)

      cond do
        DateTime.diff(signed_this_update, declared_this_update, :second) != 0 ->
          {:error, :crl_metadata_mismatch,
           "Signed CRL thisUpdate (#{DateTime.to_iso8601(signed_this_update)}) does not match declared this_update (#{bundle["this_update"]})"}

        DateTime.diff(signed_next_update, declared_next_update, :second) != 0 ->
          {:error, :crl_metadata_mismatch,
           "Signed CRL nextUpdate (#{DateTime.to_iso8601(signed_next_update)}) does not match declared next_update (#{bundle["next_update"]})"}

        DateTime.compare(signed_this_update, skew_adjusted_now_latest) == :gt ->
          {:error, :crl_not_yet_valid,
           "CRL thisUpdate #{DateTime.to_iso8601(signed_this_update)} is in the future"}

        DateTime.compare(signed_next_update, skew_adjusted_now_earliest) == :lt ->
          {:error, :crl_expired,
           "CRL nextUpdate #{DateTime.to_iso8601(signed_next_update)} has already expired"}

        true ->
          :ok
      end
    else
      _ ->
        {:error, :invalid_crl, "Failed to parse this_update or next_update timestamps"}
    end
  end
end
