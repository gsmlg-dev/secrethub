defmodule SecretHub.Agent.PKI.BundleValidator do
  @moduledoc """
  Validates public trust bundles on the SecretHub Agent host before applying them to disk.

  Enforces:
  - Valid schema version (v1)
  - Cryptographic transcript hash integrity
  - CA PEM validity and matching canonical DER SHA-256 fingerprint
  - Signed CRL PEM validity, matching DER SHA-256 fingerprint, and signature verification against the CA
  - CRL thisUpdate and nextUpdate temporal validity bounds with clock skew tolerance
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
  def validate(bundle, opts \\ []) when is_map(bundle) do
    now = Keyword.get(opts, :now, DateTime.utc_now() |> DateTime.truncate(:second))
    clock_skew = Keyword.get(opts, :clock_skew_seconds, @clock_skew_seconds)

    with :ok <- validate_schema_version(bundle),
         :ok <- validate_transcript_hash(bundle),
         {:ok, parsed_ca} <- validate_ca_certificate(bundle),
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
  end

  defp validate_schema_version(%{"schema_version" => @schema_version}), do: :ok

  defp validate_schema_version(%{"schema_version" => v}),
    do: {:error, :invalid_schema_version, "Unsupported schema version: #{inspect(v)}"}

  defp validate_schema_version(_),
    do: {:error, :invalid_schema_version, "Missing schema_version field"}

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

  defp validate_ca_certificate(%{
         "ca_bundle_pem" => ca_pem,
         "ca_fingerprint" => expected_fingerprint
       })
       when is_binary(ca_pem) and is_binary(expected_fingerprint) do
    case X509.Certificate.from_pem(ca_pem) do
      {:ok, parsed_ca} ->
        ca_der = X509.Certificate.to_der(parsed_ca)

        calculated_fingerprint =
          :crypto.hash(:sha256, ca_der)
          |> Base.encode16(case: :lower)

        if Plug.Crypto.secure_compare(
             calculated_fingerprint,
             String.downcase(expected_fingerprint)
           ) do
          {:ok, parsed_ca}
        else
          {:error, :ca_fingerprint_mismatch,
           "CA DER hash #{calculated_fingerprint} does not match expected #{expected_fingerprint}"}
        end

      {:error, reason} ->
        {:error, :invalid_ca_bundle, "Failed to parse CA bundle PEM: #{inspect(reason)}"}
    end
  end

  defp validate_ca_certificate(_),
    do: {:error, :invalid_ca_bundle, "Missing ca_bundle_pem or ca_fingerprint"}

  defp validate_crl(
         %{"crl_pem" => crl_pem, "crl_der_sha256" => expected_crl_hash} = bundle,
         parsed_ca,
         now,
         clock_skew
       )
       when is_binary(crl_pem) and is_binary(expected_crl_hash) do
    with {:ok, parsed_crl} <- parse_crl(crl_pem),
         :ok <- verify_crl_hash(parsed_crl, expected_crl_hash),
         :ok <- verify_crl_signature(parsed_crl, parsed_ca),
         :ok <- verify_crl_temporal_validity(bundle, now, clock_skew) do
      {:ok, parsed_crl}
    end
  end

  defp validate_crl(_, _, _, _), do: {:error, :invalid_crl, "Missing crl_pem or crl_der_sha256"}

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

  defp verify_crl_temporal_validity(bundle, now, clock_skew) do
    with {:ok, this_update, _} <- DateTime.from_iso8601(bundle["this_update"]),
         {:ok, next_update, _} <- DateTime.from_iso8601(bundle["next_update"]) do
      skew_adjusted_now_earliest = DateTime.add(now, -clock_skew, :second)
      skew_adjusted_now_latest = DateTime.add(now, clock_skew, :second)

      cond do
        DateTime.compare(this_update, skew_adjusted_now_latest) == :gt ->
          {:error, :crl_not_yet_valid, "CRL thisUpdate #{bundle["this_update"]} is in the future"}

        DateTime.compare(next_update, skew_adjusted_now_earliest) == :lt ->
          {:error, :crl_expired, "CRL nextUpdate #{bundle["next_update"]} has already expired"}

        true ->
          :ok
      end
    else
      _ ->
        {:error, :invalid_crl, "Failed to parse this_update or next_update timestamps"}
    end
  end
end
