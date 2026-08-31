defmodule SecretHub.Core.PKI.ClientAuth.Issuer do
  @moduledoc """
  Handles canonical client certificate issuance for Client Auth PKI.

  Extracts the public key from the validated CSR and generates a certificate
  with a strict server-controlled profile (O=SecretHub Client Authentication,
  CN=<identity UUID>, URI SAN=urn:secrethub:client:<identity UUID>, clientAuth only).
  """

  require Logger
  import Ecto.Query

  alias SecretHub.Core.{Audit, Repo}
  alias SecretHub.Core.PKI.{CertificateIdentity, CSR}
  alias SecretHub.Core.Vault.SealState
  alias SecretHub.Shared.Crypto.Encryption

  alias SecretHub.Shared.Schemas.{
    Certificate,
    ClientAuthAuthority,
    ClientAuthIdentity,
    ClientAuthIssuanceRequest
  }

  alias X509.Certificate.Extension, as: CertExtension
  alias X509.Certificate.Validity

  @clock_skew_seconds 300
  @default_client_ttl_seconds 2_592_000
  @min_ttl_seconds 60
  @max_rsa_modulus_bits 8192
  @supported_ec_curves [
    # secp256r1 / P-256
    {1, 2, 840, 10_045, 3, 1, 7},
    # secp384r1 / P-384
    {1, 3, 132, 0, 34}
  ]

  @doc """
  Issues a client certificate for a given identity from a CSR.
  Includes full idempotency protection via request_id.
  """
  @spec issue_certificate(term(), binary(), term(), keyword()) ::
          {:ok,
           %{
             certificate: binary(),
             cert_record: Certificate.t(),
             ca_bundle_pem: binary(),
             replayed: boolean()
           }}
          | {:error,
             :invalid_request_id
             | :identity_not_found
             | :identity_disabled
             | :invalid_csr
             | :unsupported_key
             | :invalid_ttl
             | :idempotency_conflict
             | :vault_sealed
             | :vault_unavailable
             | :authority_not_initialized
             | term()}
  def issue_certificate(identity_id, csr_pem, request_id, opts \\ []) do
    with {:ok, normalized_request_id} <- cast_uuid(request_id, :invalid_request_id),
         {:ok, normalized_identity_id} <- cast_uuid(identity_id, :identity_not_found),
         :ok <- validate_csr_input(csr_pem),
         :ok <- check_unsealed() do
      transact_issuance(normalized_identity_id, csr_pem, normalized_request_id, opts)
    end
  end

  # Helpers

  defp transact_issuance(identity_id, csr_pem, request_id, opts) do
    now = Keyword.get(opts, :now, DateTime.utc_now() |> DateTime.truncate(:second))
    requested_ttl = Keyword.get(opts, :ttl_seconds)
    csr_sha256 = :crypto.hash(:sha256, csr_pem)
    actor = Keyword.get(opts, :actor, %{})

    Repo.transaction(fn ->
      authority = lock_authority()

      # 1. Check idempotency table
      case Repo.get_by(ClientAuthIssuanceRequest, request_id: request_id) do
        %ClientAuthIssuanceRequest{} = existing ->
          default_ttl =
            (authority && authority.default_ttl_seconds) || @default_client_ttl_seconds

          handle_replay(existing, identity_id, csr_sha256, requested_ttl, default_ttl)

        nil ->
          do_issue_new(
            identity_id,
            csr_pem,
            csr_sha256,
            request_id,
            requested_ttl,
            now,
            authority,
            actor
          )
      end
    end)
    |> case do
      {:ok, {:ok, result}} -> {:ok, result}
      {:ok, result} -> {:ok, result}
      {:error, reason} -> {:error, reason}
    end
  end

  defp handle_replay(existing, identity_id, csr_sha256, requested_ttl, default_ttl) do
    effective_requested_ttl = requested_ttl || default_ttl
    ttl_match = existing.requested_ttl_seconds == effective_requested_ttl

    if existing.identity_id == identity_id and
         :crypto.hash_equals(existing.csr_sha256, csr_sha256) and
         ttl_match do
      cert =
        Repo.get!(Certificate, existing.certificate_id) |> Repo.preload(:client_auth_authority)

      ca_id =
        (cert.client_auth_authority && cert.client_auth_authority.ca_certificate_id) ||
          cert.issuer_id

      ca_cert = Repo.get!(Certificate, ca_id)

      %{
        certificate: cert.certificate_pem,
        cert_record: cert,
        ca_bundle_pem: ca_cert.certificate_pem,
        replayed: true
      }
    else
      Repo.rollback(:idempotency_conflict)
    end
  end

  defp do_issue_new(
         identity_id,
         csr_pem,
         csr_sha256,
         request_id,
         requested_ttl,
         now,
         authority,
         actor
       ) do
    with %ClientAuthIdentity{status: "active"} = identity <- lock_identity(identity_id),
         %ClientAuthAuthority{status: "active"} <- authority || lock_authority(),
         {:ok, ca_key} <- decrypt_ca_key(authority.ca_certificate),
         {:ok, csr} <- parse_csr(csr_pem),
         {:ok, public_key} <- validate_csr_public_key(csr),
         {:ok, ttl_seconds} <- compute_ttl(requested_ttl, authority) do
      # Build certificate validity
      not_before = DateTime.add(now, -@clock_skew_seconds, :second)
      desired_not_after = DateTime.add(now, ttl_seconds, :second)

      # Clamp to CA validity
      not_after =
        if DateTime.compare(desired_not_after, authority.ca_certificate.valid_until) == :gt,
          do: authority.ca_certificate.valid_until,
          else: desired_not_after

      # Generate 160-bit random serial number
      serial_int = generate_160bit_serial()
      serial_hex = format_serial_hex(serial_int)

      # Build Subject and Extensions
      subject_str = "/O=SecretHub Client Authentication/CN=#{identity.id}"
      uri_san = ~c"urn:secrethub:client:" ++ to_charlist(identity.id)

      client_extensions = [
        basic_constraints: CertExtension.basic_constraints(false),
        key_usage: CertExtension.key_usage([:digitalSignature]),
        ext_key_usage: CertExtension.ext_key_usage([:clientAuth]),
        subject_alt_name: CertExtension.subject_alt_name([{:uniformResourceIdentifier, uri_san}])
      ]

      hash_algo = if authority.key_algorithm == "ecdsa_p384", do: :sha384, else: :sha256

      {:ok, parsed_ca} = X509.Certificate.from_pem(authority.ca_certificate.certificate_pem)

      cert_struct =
        X509.Certificate.new(
          public_key,
          subject_str,
          parsed_ca,
          ca_key,
          extensions: client_extensions,
          hash: hash_algo,
          serial: serial_int,
          validity: Validity.new(not_before, not_after)
        )

      cert_pem = X509.Certificate.to_pem(cert_struct)
      cert_der = X509.Certificate.to_der(cert_struct)

      canonical_fingerprint = CertificateIdentity.canonical_fingerprint_from_der(cert_der)
      legacy_fingerprint = Certificate.fingerprint(cert_der)

      # Validate newly issued certificate against CA before persisting
      if !:public_key.pkix_is_issuer(cert_struct, parsed_ca) or
           !:public_key.pkix_verify(cert_der, X509.Certificate.public_key(parsed_ca)) do
        Repo.rollback(:issuance_failed)
      end

      # Insert Certificate
      cert_attrs = %{
        serial_number: serial_hex,
        fingerprint: legacy_fingerprint,
        canonical_fingerprint: canonical_fingerprint,
        certificate_pem: cert_pem,
        subject: "O=SecretHub Client Authentication, CN=#{identity.id}",
        issuer: authority.ca_certificate.subject,
        common_name: identity.id,
        organization: "SecretHub Client Authentication",
        valid_from: not_before,
        valid_until: not_after,
        cert_type: :client_auth_client,
        key_usage: ["digitalSignature"],
        issuer_id: authority.ca_certificate.id,
        client_auth_authority_id: authority.id,
        client_auth_identity_id: identity.id,
        entity_id: identity.id,
        entity_type: "client_auth_client",
        metadata: %{
          "extended_key_usage" => ["clientAuth"],
          "san_uri" => ["urn:secrethub:client:#{identity.id}"]
        }
      }

      {:ok, cert_record} =
        %Certificate{}
        |> Certificate.changeset(cert_attrs)
        |> Repo.insert()

      # Record idempotency request
      stored_requested_ttl = requested_ttl || authority.default_ttl_seconds

      {:ok, _request_record} =
        %ClientAuthIssuanceRequest{}
        |> ClientAuthIssuanceRequest.changeset(%{
          request_id: request_id,
          identity_id: identity.id,
          csr_sha256: csr_sha256,
          requested_ttl_seconds: stored_requested_ttl,
          certificate_id: cert_record.id
        })
        |> Repo.insert()

      # Record audit
      :ok = record_issuance_audit(identity, cert_record, request_id, actor)

      %{
        certificate: cert_pem,
        cert_record: cert_record,
        ca_bundle_pem: authority.ca_certificate.certificate_pem,
        replayed: false
      }
    else
      nil -> Repo.rollback(:identity_not_found)
      %ClientAuthIdentity{status: "disabled"} -> Repo.rollback(:identity_disabled)
      {:error, reason} -> Repo.rollback(reason)
    end
  end

  defp lock_identity(identity_id) do
    Repo.one(
      from(i in ClientAuthIdentity,
        where: i.id == ^identity_id,
        lock: "FOR UPDATE"
      )
    )
  end

  defp lock_authority do
    Repo.one(
      from(a in ClientAuthAuthority,
        where: a.slug == "client-auth" and a.status == "active",
        preload: [:ca_certificate, :current_crl],
        lock: "FOR UPDATE"
      )
    )
  end

  defp parse_csr(csr_pem) do
    case CSR.parse(csr_pem) do
      {:ok, csr} -> {:ok, csr}
      {:error, _} -> {:error, :invalid_csr}
    end
  end

  defp validate_csr_public_key(csr) do
    case X509.CSR.public_key(csr) do
      {:RSAPublicKey, modulus, exponent} = key
      when is_integer(modulus) and is_integer(exponent) ->
        bits = :erlang.byte_size(:binary.encode_unsigned(modulus)) * 8

        if bits >= 2048 and bits <= @max_rsa_modulus_bits and exponent >= 3 and
             exponent < modulus and rem(exponent, 2) == 1 do
          {:ok, key}
        else
          {:error, :unsupported_key}
        end

      {{:ECPoint, point}, {:namedCurve, curve}} = key when is_binary(point) ->
        if curve in @supported_ec_curves,
          do: {:ok, key},
          else: {:error, :unsupported_key}

      {point, {:namedCurve, curve}} = key when is_binary(point) ->
        if curve in @supported_ec_curves,
          do: {:ok, key},
          else: {:error, :unsupported_key}

      _other ->
        {:error, :unsupported_key}
    end
  rescue
    _ -> {:error, :invalid_csr}
  end

  defp compute_ttl(nil, authority), do: {:ok, authority.default_ttl_seconds}

  defp compute_ttl(requested, authority) when is_integer(requested) do
    cond do
      requested < @min_ttl_seconds ->
        {:error, :invalid_ttl}

      requested > authority.max_ttl_seconds ->
        {:ok, authority.max_ttl_seconds}

      true ->
        {:ok, requested}
    end
  end

  defp compute_ttl(_, _), do: {:error, :invalid_ttl}

  defp generate_160bit_serial do
    # Generate 20 random bytes (160 bits) ensuring the highest bit is 0 so it's a positive integer
    <<first_byte, rest::binary-size(19)>> = :crypto.strong_rand_bytes(20)
    positive_first_byte = :erlang.band(first_byte, 0x7F)
    :binary.decode_unsigned(<<positive_first_byte, rest::binary>>)
  end

  defp format_serial_hex(serial) when is_integer(serial) do
    serial
    |> :binary.encode_unsigned()
    |> Base.encode16(case: :lower)
    |> String.graphemes()
    |> Enum.chunk_every(2)
    |> Enum.join(":")
  end

  defp validate_csr_input(pem) when is_binary(pem) and byte_size(pem) > 0, do: :ok
  defp validate_csr_input(_), do: {:error, :invalid_csr}

  defp cast_uuid(val, err) when is_binary(val) and val != "" do
    case Ecto.UUID.cast(val) do
      {:ok, uuid} -> {:ok, uuid}
      _ -> {:error, err}
    end
  end

  defp cast_uuid(_, err), do: {:error, err}

  defp decrypt_ca_key(%Certificate{private_key_encrypted: encrypted_key})
       when is_binary(encrypted_key) do
    with {:ok, master_key} <- get_pki_master_key() do
      case Encryption.decrypt_from_blob(encrypted_key, master_key) do
        {:ok, key_pem} -> {:ok, X509.PrivateKey.from_pem!(key_pem)}
        {:error, _} -> {:error, :vault_unavailable}
      end
    end
  end

  defp get_pki_master_key do
    case Process.whereis(SealState) do
      nil ->
        if dev_pki_unsealed_fallback?(),
          do: {:ok, dev_fallback_key()},
          else: {:error, :vault_unavailable}

      _pid ->
        case SealState.get_master_key() do
          {:ok, key} ->
            {:ok, key}

          {:error, _} ->
            if dev_pki_unsealed_fallback?(),
              do: {:ok, dev_fallback_key()},
              else: {:error, :vault_sealed}
        end
    end
  end

  defp check_unsealed do
    case Process.whereis(SealState) do
      nil ->
        if dev_pki_unsealed_fallback?(), do: :ok, else: {:error, :vault_unavailable}

      _pid ->
        if SealState.sealed?() do
          if dev_pki_unsealed_fallback?(), do: :ok, else: {:error, :vault_sealed}
        else
          :ok
        end
    end
  end

  defp dev_pki_unsealed_fallback? do
    Application.get_env(:secrethub_core, :dev_pki_unsealed_fallback, false)
  end

  defp dev_fallback_key do
    :crypto.hash(:sha256, "test-encryption-key-for-pki-testing")
  end

  defp record_issuance_audit(identity, cert, request_id, actor) do
    actor_type = Map.get(actor, :actor_type) || Map.get(actor, "actor_type") || "admin"
    actor_id = Map.get(actor, :actor_id) || Map.get(actor, "actor_id") || "admin"

    source_ip =
      Map.get(actor, :source_ip) || Map.get(actor, "source_ip") || Map.get(actor, :client_ip)

    attrs = %{
      event_type: "pki.client_auth.certificate_issued",
      actor_type: actor_type,
      actor_id: actor_id,
      source_ip: source_ip,
      access_granted: true,
      correlation_id: request_id,
      event_data: %{
        "identity_id" => identity.id,
        "identity_name" => identity.name,
        "certificate_id" => cert.id,
        "serial_number" => cert.serial_number,
        "canonical_fingerprint" => cert.canonical_fingerprint,
        "valid_from" => DateTime.to_iso8601(cert.valid_from),
        "valid_until" => DateTime.to_iso8601(cert.valid_until),
        "request_id" => request_id
      }
    }

    Audit.log_event(attrs)
    :ok
  end
end
