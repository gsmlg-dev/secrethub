defmodule SecretHub.Core.PKI.AppCertificates do
  @moduledoc """
  Transactional canonical application-certificate issuance.

  Bootstrap tokens select the application identity. CSR identity fields and
  requested extensions are never copied into the issued certificate.
  """

  import Ecto.Query
  require Logger

  alias SecretHub.Core.{Apps, Audit, Repo}
  alias SecretHub.Core.PKI.{CA, CertificateIdentity, CSR}

  alias SecretHub.Shared.Schemas.{
    Agent,
    AppBootstrapToken,
    AppCertificate,
    AppCertificateRenewal,
    AuditLog,
    Certificate
  }

  alias SecretHub.Shared.Schemas.Application, as: App

  @runtime_agent_statuses [:active, :trusted_connected]
  @renewal_domain "secrethub-app-cert-renewal-v1"
  @supported_ec_curves [
    {1, 2, 840, 10_045, 3, 1, 7},
    {1, 3, 132, 0, 34}
  ]
  @proof_algorithms ~w(rsa-pss-sha256 ecdsa-sha256)
  @revocation_reasons ~w(superseded compromised operator_revoked app_suspended)
  @renewal_request_keys ~w(app_id current_fingerprint csr request_id signature_algorithm proof)
  @renewal_stable_errors [
    :invalid_request,
    :invalid_app_id,
    :invalid_fingerprint,
    :invalid_request_id,
    :unsupported_algorithm,
    :invalid_proof,
    :idempotency_conflict,
    :invalid_current_certificate,
    :invalid_agent_assignment,
    :invalid_csr,
    :unsupported_key,
    :ca_unavailable,
    :renewal_failed
  ]
  @renewal_denied_errors @renewal_stable_errors -- [:ca_unavailable, :renewal_failed]
  @denied_errors [
    :invalid_request_id,
    :invalid_token,
    :idempotency_conflict,
    :invalid_csr,
    :unsupported_key,
    :invalid_agent_assignment
  ]
  @stable_errors [
    :invalid_request_id,
    :invalid_token,
    :idempotency_conflict,
    :invalid_csr,
    :unsupported_key,
    :invalid_agent_assignment,
    :ca_unavailable,
    :issuance_failed
  ]

  @type issuance_result :: %{
          certificate: binary(),
          ca_chain: [binary()],
          cert_record: Certificate.t(),
          app_certificate: AppCertificate.t(),
          replayed: boolean()
        }

  @type renewal_result :: issuance_result()

  @doc """
  Builds the deterministic proof transcript for application-certificate renewal.
  """
  @spec renewal_signing_payload(term(), term(), term(), term()) ::
          {:ok, binary()}
          | {:error, :invalid_app_id | :invalid_fingerprint | :invalid_csr | :invalid_request_id}
  def renewal_signing_payload(app_id, current_fingerprint, csr_pem, request_id) do
    with {:ok, normalized_app_id} <- cast_uuid(app_id, :invalid_app_id),
         {:ok, fingerprint_bytes} <-
           CertificateIdentity.decode_fingerprint(current_fingerprint),
         true <- is_binary(csr_pem),
         {:ok, normalized_request_id} <- cast_uuid(request_id, :invalid_request_id) do
      csr_sha256 = :crypto.hash(:sha256, csr_pem)

      canonical_json =
        canonical_renewal_json(
          normalized_app_id,
          current_fingerprint,
          csr_sha256,
          normalized_request_id
        )

      normalized_payload_sha256 = :crypto.hash(:sha256, canonical_json)

      {:ok,
       [
         @renewal_domain,
         normalized_app_id,
         fingerprint_bytes,
         csr_sha256,
         normalized_request_id,
         normalized_payload_sha256
       ]
       |> Enum.map(&length_prefix/1)
       |> IO.iodata_to_binary()}
    else
      false -> {:error, :invalid_csr}
      {:error, :invalid_fingerprint} = error -> error
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Renews a canonical application certificate after verifying possession of the
  current certificate's private key.
  """
  @spec renew(map()) ::
          {:ok, renewal_result()}
          | {:error,
             :invalid_request
             | :invalid_app_id
             | :invalid_fingerprint
             | :invalid_request_id
             | :unsupported_algorithm
             | :invalid_proof
             | :idempotency_conflict
             | :invalid_current_certificate
             | :invalid_agent_assignment
             | :invalid_csr
             | :unsupported_key
             | :ca_unavailable
             | :renewal_failed}
  def renew(attrs) do
    case normalize_renewal_request(attrs) do
      {:ok, request} ->
        result =
          try do
            Repo.transaction(fn -> renew_locked(request) end)
          rescue
            _error -> {:error, :renewal_failed}
          catch
            :exit, _reason -> {:error, :renewal_failed}
          end

        case result do
          {:ok, renewal} ->
            {:ok, renewal}

          {:error, reason} ->
            stable_reason = normalize_renewal_error(reason)
            record_renewal_error_audit(stable_reason, request.request_id)
            {:error, stable_reason}
        end

      {:error, reason} ->
        stable_reason = normalize_renewal_error(reason)
        record_renewal_error_audit(stable_reason, renewal_request_id(attrs))
        {:error, stable_reason}
    end
  end

  @doc """
  Atomically revokes one active application-certificate association and its
  underlying canonical certificate.
  """
  @spec revoke(term(), term(), term()) ::
          {:ok, AppCertificate.t()}
          | {:error, :not_found | :invalid_reason | :revocation_failed}
  def revoke(app_id, certificate_id, reason) do
    with {:ok, app_id} <- cast_uuid(app_id, :not_found),
         {:ok, certificate_id} <- cast_uuid(certificate_id, :not_found),
         {:ok, reason} <- normalize_revocation_reason(reason) do
      transact_revocation(fn -> revoke_one_locked(app_id, certificate_id, reason) end)
    end
  end

  @doc """
  Atomically revokes every active certificate association for an application.
  """
  @spec revoke_all(term(), term()) ::
          {:ok, non_neg_integer()}
          | {:error, :not_found | :invalid_reason | :revocation_failed}
  def revoke_all(app_id, reason) do
    with {:ok, app_id} <- cast_uuid(app_id, :not_found),
         {:ok, reason} <- normalize_revocation_reason(reason) do
      transact_revocation(fn -> revoke_all_locked(app_id, reason) end)
    end
  end

  @spec issue_from_bootstrap(term(), term(), term()) ::
          {:ok, issuance_result()}
          | {:error,
             :invalid_request_id
             | :invalid_token
             | :idempotency_conflict
             | :invalid_csr
             | :unsupported_key
             | :invalid_agent_assignment
             | :ca_unavailable
             | :issuance_failed}
  def issue_from_bootstrap(token, csr_pem, request_id) do
    case Ecto.UUID.cast(request_id) do
      {:ok, normalized_request_id} ->
        transact_issuance(token, csr_pem, normalized_request_id)

      :error ->
        reject_invalid_request_id()
    end
  end

  defp cast_uuid(value, error) do
    case Ecto.UUID.cast(value) do
      {:ok, normalized} -> {:ok, normalized}
      :error -> {:error, error}
    end
  end

  defp normalize_renewal_request(attrs) when is_map(attrs) do
    with {:ok, values} <- exact_renewal_request(attrs),
         {:ok, request_id} <- cast_uuid(values["request_id"], :invalid_request_id),
         {:ok, app_id} <- cast_uuid(values["app_id"], :invalid_app_id),
         {:ok, _fingerprint_bytes} <-
           CertificateIdentity.decode_fingerprint(values["current_fingerprint"]),
         true <- values["signature_algorithm"] in @proof_algorithms,
         true <- is_binary(values["csr"]),
         true <- is_binary(values["proof"]) and byte_size(values["proof"]) > 0,
         {:ok, payload} <-
           renewal_signing_payload(
             app_id,
             values["current_fingerprint"],
             values["csr"],
             request_id
           ) do
      csr_sha256 = :crypto.hash(:sha256, values["csr"])

      normalized_payload_sha256 =
        app_id
        |> canonical_renewal_json(
          values["current_fingerprint"],
          csr_sha256,
          request_id
        )
        |> then(&:crypto.hash(:sha256, &1))

      {:ok,
       %{
         app_id: app_id,
         current_fingerprint: values["current_fingerprint"],
         csr: values["csr"],
         csr_sha256: csr_sha256,
         normalized_payload_sha256: normalized_payload_sha256,
         request_id: request_id,
         signature_algorithm: values["signature_algorithm"],
         proof: values["proof"],
         payload: payload
       }}
    else
      false -> normalize_renewal_request_error(attrs)
      {:error, reason} -> {:error, reason}
    end
  end

  defp normalize_renewal_request(_attrs), do: {:error, :invalid_request}

  defp renewal_request_id(attrs) when is_map(attrs) do
    request_id = Map.get(attrs, :request_id) || Map.get(attrs, "request_id")

    case Ecto.UUID.cast(request_id) do
      {:ok, normalized} -> normalized
      :error -> nil
    end
  end

  defp renewal_request_id(_attrs), do: nil

  defp exact_renewal_request(attrs) do
    pairs =
      Enum.map(attrs, fn
        {key, value} when is_binary(key) -> {key, value}
        {key, value} when is_atom(key) -> {Atom.to_string(key), value}
        {_key, _value} -> {:invalid, nil}
      end)

    keys = Enum.map(pairs, &elem(&1, 0))

    if Enum.sort(keys) == Enum.sort(@renewal_request_keys) and
         length(Enum.uniq(keys)) == length(keys) do
      {:ok, Map.new(pairs)}
    else
      {:error, :invalid_request}
    end
  end

  defp normalize_revocation_reason(reason) when is_atom(reason) do
    reason |> Atom.to_string() |> normalize_revocation_reason()
  end

  defp normalize_revocation_reason(reason) when reason in @revocation_reasons,
    do: {:ok, reason}

  defp normalize_revocation_reason(_reason), do: {:error, :invalid_reason}

  defp transact_revocation(operation) do
    result =
      try do
        Repo.transaction(operation)
      rescue
        _error -> {:error, :revocation_failed}
      catch
        :exit, _reason -> {:error, :revocation_failed}
      end

    case result do
      {:ok, value} -> {:ok, value}
      {:error, reason} when reason in [:not_found, :revocation_failed] -> {:error, reason}
      {:error, _reason} -> {:error, :revocation_failed}
    end
  end

  defp revoke_one_locked(app_id, certificate_id, reason) do
    case lock_app(app_id) do
      %App{} ->
        association = lock_active_association(app_id, certificate_id)
        certificate = lock_certificate(certificate_id)

        case {association, certificate} do
          {%AppCertificate{} = association, %Certificate{} = certificate} ->
            now = DateTime.utc_now() |> DateTime.truncate(:second)

            with {:ok, revoked_association, _revoked_certificate} <-
                   revoke_pair(association, certificate, reason, now) do
              revoked_association
            else
              {:error, _reason} -> Repo.rollback(:revocation_failed)
            end

          _other ->
            Repo.rollback(:not_found)
        end

      nil ->
        Repo.rollback(:not_found)
    end
  end

  defp revoke_all_locked(app_id, reason) do
    case lock_app(app_id) do
      %App{} ->
        associations = lock_active_associations(app_id)
        certificates = lock_certificates(Enum.map(associations, & &1.certificate_id))

        if length(certificates) == length(associations) do
          certificates_by_id = Map.new(certificates, &{&1.id, &1})
          now = DateTime.utc_now() |> DateTime.truncate(:second)

          Enum.each(associations, fn association ->
            certificate = Map.fetch!(certificates_by_id, association.certificate_id)

            case revoke_pair(association, certificate, reason, now) do
              {:ok, _revoked_association, _revoked_certificate} -> :ok
              {:error, _reason} -> Repo.rollback(:revocation_failed)
            end
          end)

          length(associations)
        else
          Repo.rollback(:revocation_failed)
        end

      nil ->
        Repo.rollback(:not_found)
    end
  end

  defp lock_active_association(app_id, certificate_id) do
    Repo.one(
      from(ac in AppCertificate,
        where: ac.app_id == ^app_id,
        where: ac.certificate_id == ^certificate_id,
        where: is_nil(ac.revoked_at),
        lock: "FOR UPDATE"
      )
    )
  end

  defp lock_active_associations(app_id) do
    Repo.all(
      from(ac in AppCertificate,
        where: ac.app_id == ^app_id,
        where: is_nil(ac.revoked_at),
        order_by: [asc: ac.certificate_id],
        lock: "FOR UPDATE"
      )
    )
  end

  defp lock_certificate(certificate_id) do
    Repo.one(
      from(c in Certificate,
        where: c.id == ^certificate_id,
        lock: "FOR UPDATE"
      )
    )
  end

  defp lock_certificates([]), do: []

  defp lock_certificates(certificate_ids) do
    Repo.all(
      from(c in Certificate,
        where: c.id in ^certificate_ids,
        order_by: [asc: c.id],
        lock: "FOR UPDATE"
      )
    )
  end

  defp revoke_pair(association, certificate, reason, now) do
    with {:ok, revoked_association} <- revoke_association(association, reason, now),
         {:ok, revoked_certificate} <-
           certificate |> Certificate.revoke_changeset(reason) |> Repo.update(),
         :ok <- record_revocation_audit(association.app_id, certificate.id, reason) do
      {:ok, revoked_association, revoked_certificate}
    end
  end

  defp record_renewal_allowed_audit(
         request,
         current_certificate_id,
         issued_certificate_id,
         result_code
       ) do
    attrs = %{
      event_type: "auth.app_certificate_renewal_allowed",
      actor_type: "app",
      actor_id: request.app_id,
      app_id: request.app_id,
      access_granted: true,
      correlation_id: request.request_id,
      event_data: %{
        "app_certificate_renewal" => %{
          "app_id" => request.app_id,
          "current_certificate_id" => current_certificate_id,
          "issued_certificate_id" => issued_certificate_id,
          "request_id" => request.request_id,
          "result_code" => result_code
        }
      }
    }

    with :ok <- maybe_inject_renewal_fault(:success_audit),
         {:ok, _audit_log} <- Audit.log_event(attrs) do
      :ok
    else
      {:error, _reason} -> {:error, :renewal_failed}
    end
  end

  defp record_revocation_audit(app_id, certificate_id, reason, correlation_id \\ nil) do
    attrs = %{
      event_type: "auth.app_certificate_revoked",
      actor_type: "app",
      actor_id: app_id,
      app_id: app_id,
      access_granted: true,
      event_data: %{
        "app_certificate_revocation" => %{
          "app_id" => app_id,
          "certificate_id" => certificate_id,
          "reason" => reason,
          "result_code" => "revoked"
        }
      }
    }

    attrs = if correlation_id, do: Map.put(attrs, :correlation_id, correlation_id), else: attrs

    with :ok <- maybe_inject_revocation_fault(:success_audit),
         {:ok, _audit_log} <- Audit.log_event(attrs) do
      :ok
    else
      {:error, _reason} -> {:error, :revocation_failed}
    end
  end

  defp record_renewal_error_audit(reason, request_id) do
    event_type =
      if reason in @renewal_denied_errors,
        do: "auth.app_certificate_renewal_denied",
        else: "auth.app_certificate_renewal_failed"

    request_id =
      if reason in [:invalid_request, :invalid_request_id], do: nil, else: request_id

    evidence = %{"result_code" => Atom.to_string(reason)}
    evidence = if request_id, do: Map.put(evidence, "request_id", request_id), else: evidence

    attrs = %{
      event_type: event_type,
      actor_type: "app",
      access_granted: false,
      denial_reason: Atom.to_string(reason),
      event_data: %{"app_certificate_renewal" => evidence}
    }

    attrs = if request_id, do: Map.put(attrs, :correlation_id, request_id), else: attrs
    record_renewal_post_rollback_audit(attrs)
  end

  defp record_renewal_post_rollback_audit(attrs) do
    maybe_inject_renewal_post_rollback_audit_fault()

    case Audit.log_event(attrs) do
      {:ok, _audit_log} -> :ok
      {:error, _reason} -> log_post_rollback_audit_failure()
    end
  rescue
    _error -> log_post_rollback_audit_failure()
  catch
    :exit, _reason -> log_post_rollback_audit_failure()
  end

  defp normalize_renewal_request_error(attrs) do
    algorithm = Map.get(attrs, :signature_algorithm) || Map.get(attrs, "signature_algorithm")
    csr = Map.get(attrs, :csr) || Map.get(attrs, "csr")
    proof = Map.get(attrs, :proof) || Map.get(attrs, "proof")

    cond do
      algorithm not in @proof_algorithms -> {:error, :unsupported_algorithm}
      not is_binary(csr) -> {:error, :invalid_csr}
      not is_binary(proof) or byte_size(proof) == 0 -> {:error, :invalid_proof}
      true -> {:error, :invalid_request}
    end
  end

  defp canonical_renewal_json(app_id, fingerprint, csr_sha256, request_id) do
    csr_sha256_hex = Base.encode16(csr_sha256, case: :lower)

    ~s({"app_id":"#{app_id}","csr_sha256":"#{csr_sha256_hex}","current_fingerprint":"#{fingerprint}","request_id":"#{request_id}"})
  end

  defp length_prefix(value), do: <<byte_size(value)::unsigned-big-32, value::binary>>

  defp renew_locked(request) do
    app = lock_app(request.app_id)

    case lock_app_certificate_renewal(request.app_id, request.request_id) do
      nil -> renew_new_locked(app, request)
      %AppCertificateRenewal{} = evidence -> replay_renewal_locked(evidence, request)
    end
  end

  defp lock_app_certificate_renewal(app_id, request_id) do
    Repo.one(
      from(r in AppCertificateRenewal,
        where: r.app_id == ^app_id and r.request_id == ^request_id,
        lock: "FOR UPDATE"
      )
    )
  end

  defp replay_renewal_locked(evidence, request) do
    if matching_renewal_evidence?(evidence, request) do
      with %Certificate{} = original <-
             Repo.get(Certificate, evidence.current_certificate_id),
           {:ok, %{public_key: public_key, canonical_fingerprint: fingerprint}} <-
             CertificateIdentity.validate_app_certificate(
               original.certificate_pem,
               request.app_id
             ),
           true <- fingerprint == evidence.original_fingerprint,
           :ok <- verify_renewal_proof(request, public_key),
           %Certificate{} = issued <- Repo.get(Certificate, evidence.issued_certificate_id),
           %AppCertificate{} = association <-
             Repo.get_by(AppCertificate,
               app_id: request.app_id,
               certificate_id: evidence.issued_certificate_id
             ),
           {:ok, ca_chain} <- CA.get_ca_chain_pems(issued.issuer_id),
           :ok <-
             record_renewal_allowed_audit(
               request,
               evidence.current_certificate_id,
               evidence.issued_certificate_id,
               "replayed"
             ) do
        %{
          certificate: issued.certificate_pem,
          ca_chain: ca_chain,
          cert_record: issued,
          app_certificate: association,
          replayed: true
        }
      else
        {:error, :invalid_proof} -> Repo.rollback(:invalid_proof)
        _other -> Repo.rollback(:renewal_failed)
      end
    else
      Repo.rollback(:idempotency_conflict)
    end
  end

  defp matching_renewal_evidence?(evidence, request) do
    evidence.original_fingerprint == request.current_fingerprint and
      evidence.proof_algorithm == request.signature_algorithm and
      secure_equal?(evidence.csr_sha256, request.csr_sha256) and
      secure_equal?(
        evidence.normalized_payload_sha256,
        request.normalized_payload_sha256
      ) and secure_equal?(evidence.proof, request.proof)
  end

  defp secure_equal?(left, right)
       when is_binary(left) and is_binary(right) and byte_size(left) == byte_size(right),
       do: :crypto.hash_equals(left, right)

  defp secure_equal?(_left, _right), do: false

  defp renew_new_locked(app, request) do
    agent = lock_agent(app && app.agent_id)
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    with :ok <- validate_active_assignment(app, agent),
         {:ok, association, current_certificate} <-
           lock_current_app_certificate(request),
         {:ok, current_public_key} <-
           validate_current_certificate(current_certificate, association, request, now),
         :ok <- verify_renewal_proof(request, current_public_key),
         {:ok, csr} <- parse_csr(request.csr),
         {:ok, replacement_public_key} <- supported_public_key(csr),
         {:ok, signed} <-
           CA.issue_canonical_app_certificate(replacement_public_key, request.app_id),
         {:ok, certificate_attrs} <- persisted_certificate_attrs(signed, request.app_id),
         {:ok, replacement} <-
           %Certificate{} |> Certificate.changeset(certificate_attrs) |> Repo.insert(),
         {:ok, replacement_association} <-
           Apps.associate_certificate(
             request.app_id,
             replacement.id,
             replacement.valid_until
           ),
         {:ok, _evidence} <-
           persist_renewal_evidence(
             request,
             current_certificate.id,
             replacement.id
           ),
         :ok <- maybe_inject_renewal_fault(:before_original_revocation),
         {:ok, _revoked_association} <-
           revoke_association(association, "superseded", now),
         {:ok, _revoked_certificate} <-
           current_certificate
           |> Certificate.revoke_changeset("superseded")
           |> Repo.update(),
         :ok <-
           record_revocation_audit(
             request.app_id,
             current_certificate.id,
             "superseded",
             request.request_id
           ),
         :ok <-
           record_renewal_allowed_audit(
             request,
             current_certificate.id,
             replacement.id,
             "renewed"
           ) do
      %{
        certificate: signed.certificate,
        ca_chain: signed.ca_chain,
        cert_record: replacement,
        app_certificate: replacement_association,
        replayed: false
      }
    else
      {:error, reason} -> Repo.rollback(normalize_renewal_error(reason))
      _other -> Repo.rollback(:renewal_failed)
    end
  end

  defp lock_current_app_certificate(request) do
    certificate_id =
      Repo.one(
        from(ac in AppCertificate,
          join: c in Certificate,
          on: c.id == ac.certificate_id,
          where: ac.app_id == ^request.app_id,
          where: c.canonical_fingerprint == ^request.current_fingerprint,
          select: ac.certificate_id
        )
      )

    if certificate_id do
      association =
        Repo.one(
          from(ac in AppCertificate,
            where: ac.app_id == ^request.app_id,
            where: ac.certificate_id == ^certificate_id,
            lock: "FOR UPDATE"
          )
        )

      certificate = lock_certificate(certificate_id)

      case {association, certificate} do
        {%AppCertificate{} = association, %Certificate{} = certificate} ->
          {:ok, association, certificate}

        _other ->
          {:error, :invalid_current_certificate}
      end
    else
      {:error, :invalid_current_certificate}
    end
  end

  defp validate_current_certificate(certificate, association, request, now) do
    with true <- association.revoked_at == nil,
         true <- association.revocation_reason == nil,
         :gt <- DateTime.compare(association.expires_at, now),
         false <- certificate.revoked,
         true <- certificate.revoked_at == nil,
         true <- certificate.revocation_reason == nil,
         true <- certificate.cert_type == :app_client,
         true <- certificate.entity_type == "app",
         true <- certificate.entity_id == request.app_id,
         true <- certificate.canonical_fingerprint == request.current_fingerprint,
         comparison when comparison in [:lt, :eq] <-
           DateTime.compare(certificate.valid_from, now),
         :gt <- DateTime.compare(certificate.valid_until, now),
         {:ok,
          %{
            canonical_fingerprint: fingerprint,
            public_key: public_key
          }} <-
           CertificateIdentity.validate_app_certificate(
             certificate.certificate_pem,
             request.app_id
           ),
         true <- fingerprint == request.current_fingerprint do
      {:ok, public_key}
    else
      _other -> {:error, :invalid_current_certificate}
    end
  end

  defp verify_renewal_proof(
         %{signature_algorithm: "rsa-pss-sha256", payload: payload, proof: proof},
         {:RSAPublicKey, _modulus, _exponent} = public_key
       ) do
    verify_signature(payload, proof, public_key,
      rsa_padding: :rsa_pkcs1_pss_padding,
      rsa_pss_saltlen: 32,
      rsa_mgf1_md: :sha256
    )
  end

  defp verify_renewal_proof(
         %{signature_algorithm: "ecdsa-sha256", payload: payload, proof: proof},
         {point, {:namedCurve, _curve}} = public_key
       )
       when is_binary(point) do
    verify_signature(payload, proof, public_key, [])
  end

  defp verify_renewal_proof(
         %{signature_algorithm: "ecdsa-sha256", payload: payload, proof: proof},
         {{:ECPoint, point}, {:namedCurve, _curve}} = public_key
       )
       when is_binary(point) do
    verify_signature(payload, proof, public_key, [])
  end

  defp verify_renewal_proof(_request, _public_key), do: {:error, :invalid_proof}

  defp verify_signature(payload, proof, public_key, opts) do
    if :public_key.verify(payload, :sha256, proof, public_key, opts),
      do: :ok,
      else: {:error, :invalid_proof}
  rescue
    _error -> {:error, :invalid_proof}
  end

  defp persist_renewal_evidence(request, current_certificate_id, issued_certificate_id) do
    %AppCertificateRenewal{}
    |> AppCertificateRenewal.changeset(%{
      app_id: request.app_id,
      current_certificate_id: current_certificate_id,
      issued_certificate_id: issued_certificate_id,
      request_id: request.request_id,
      original_fingerprint: request.current_fingerprint,
      csr_sha256: request.csr_sha256,
      normalized_payload_sha256: request.normalized_payload_sha256,
      proof: request.proof,
      proof_algorithm: request.signature_algorithm
    })
    |> Repo.insert()
  end

  defp revoke_association(association, reason, now) do
    association
    |> AppCertificate.changeset(%{
      revoked_at: now,
      revocation_reason: reason
    })
    |> Repo.update()
  end

  defp normalize_renewal_error(reason) when reason in @renewal_stable_errors, do: reason
  defp normalize_renewal_error(_reason), do: :renewal_failed

  defp reject_invalid_request_id do
    {:error, :invalid_request_id} =
      Repo.transaction(fn -> Repo.rollback(:invalid_request_id) end)

    record_invalid_request_id_audit()
    {:error, :invalid_request_id}
  end

  defp transact_issuance(token, csr_pem, request_id) do
    result =
      try do
        Repo.transaction(fn ->
          case lock_issuance_rows(token) do
            {:ok, locked_token, app, agent} ->
              issue_locked(locked_token, app, agent, csr_pem, request_id)

            {:error, reason} ->
              Repo.rollback(reason)
          end
        end)
      rescue
        _error -> {:error, :issuance_failed}
      catch
        :exit, _reason -> {:error, :issuance_failed}
      end

    case result do
      {:ok, issuance} ->
        {:ok, issuance}

      {:error, reason} ->
        stable_reason = normalize_error(reason)
        record_error_audit(stable_reason, request_id)
        {:error, stable_reason}
    end
  end

  defp lock_issuance_rows(token) when is_binary(token) do
    token_hash = Apps.bootstrap_token_hash(token)

    case lookup_bootstrap_token(token_hash) do
      %{id: token_id, app_id: app_id} ->
        app = lock_app(app_id)
        agent = lock_agent(app && app.agent_id)
        locked_token = lock_bootstrap_token(token_id, app_id, token_hash)
        validate_locked_rows(locked_token, app, agent)

      nil ->
        {:error, :invalid_token}
    end
  end

  defp lock_issuance_rows(_token), do: {:error, :invalid_token}

  defp lookup_bootstrap_token(token_hash) do
    Repo.one(
      from(t in AppBootstrapToken,
        where: t.token_hash == ^token_hash,
        select: %{id: t.id, app_id: t.app_id}
      )
    )
  end

  defp lock_app(app_id) do
    Repo.one(
      from(a in App,
        where: a.id == ^app_id,
        lock: "FOR UPDATE"
      )
    )
  end

  defp lock_agent(nil), do: nil

  defp lock_agent(agent_id) do
    Repo.one(
      from(a in Agent,
        where: a.id == ^agent_id,
        lock: "FOR UPDATE"
      )
    )
  end

  defp lock_bootstrap_token(token_id, app_id, token_hash) do
    Repo.one(
      from(t in AppBootstrapToken,
        where: t.id == ^token_id,
        where: t.app_id == ^app_id,
        where: t.token_hash == ^token_hash,
        lock: "FOR UPDATE"
      )
    )
  end

  defp validate_locked_rows(nil, _app, _agent), do: {:error, :invalid_token}
  defp validate_locked_rows(token, app, agent), do: {:ok, token, app, agent}

  defp issue_locked(
         %AppBootstrapToken{
           used: true,
           used_at: %DateTime{},
           issuance_request_id: stored_request_id,
           issued_certificate_id: certificate_id
         } = token,
         _app,
         _agent,
         _csr_pem,
         request_id
       )
       when is_binary(stored_request_id) and is_binary(certificate_id) do
    replay_locked(token, request_id)
  end

  defp issue_locked(
         %AppBootstrapToken{
           used: false,
           used_at: nil,
           issuance_request_id: nil,
           issued_certificate_id: nil
         } = token,
         app,
         agent,
         csr_pem,
         request_id
       ) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    if DateTime.compare(token.expires_at, now) == :gt do
      issue_new_locked(token, app, agent, csr_pem, request_id, now)
    else
      Repo.rollback(:invalid_token)
    end
  end

  defp issue_locked(%AppBootstrapToken{}, _app, _agent, _csr_pem, _request_id) do
    Repo.rollback(:issuance_failed)
  end

  defp replay_locked(
         %AppBootstrapToken{
           issuance_request_id: request_id,
           issued_certificate_id: certificate_id,
           app_id: app_id
         },
         request_id
       )
       when is_binary(certificate_id) do
    with %Certificate{} = certificate <- Repo.get(Certificate, certificate_id),
         %AppCertificate{} = app_certificate <-
           Repo.get_by(AppCertificate, app_id: app_id, certificate_id: certificate_id),
         {:ok, ca_chain} <- CA.get_ca_chain_pems(certificate.issuer_id),
         {:ok, agent_id} <-
           original_issuance_agent_id(app_id, certificate_id, request_id),
         :ok <-
           record_allowed_audit(
             app_id,
             agent_id,
             certificate_id,
             request_id,
             "replayed"
           ) do
      %{
        certificate: certificate.certificate_pem,
        ca_chain: ca_chain,
        cert_record: certificate,
        app_certificate: app_certificate,
        replayed: true
      }
    else
      _other -> Repo.rollback(:issuance_failed)
    end
  end

  defp replay_locked(
         %AppBootstrapToken{
           issuance_request_id: stored_request_id,
           issued_certificate_id: certificate_id
         },
         request_id
       )
       when is_binary(stored_request_id) and is_binary(certificate_id) and
              stored_request_id != request_id do
    Repo.rollback(:idempotency_conflict)
  end

  defp replay_locked(_token, _request_id), do: Repo.rollback(:issuance_failed)

  defp issue_new_locked(token, app, agent, csr_pem, request_id, now) do
    with :ok <- validate_active_assignment(app, agent),
         {:ok, csr} <- parse_csr(csr_pem),
         {:ok, public_key} <- supported_public_key(csr),
         {:ok, signed} <- CA.issue_canonical_app_certificate(public_key, app.id),
         {:ok, certificate_attrs} <- persisted_certificate_attrs(signed, app.id),
         :ok <- maybe_inject_fault(:before_certificate_insert),
         {:ok, certificate} <-
           %Certificate{} |> Certificate.changeset(certificate_attrs) |> Repo.insert(),
         :ok <- maybe_inject_fault(:before_app_certificate_insert),
         {:ok, app_certificate} <-
           Apps.associate_certificate(app.id, certificate.id, certificate.valid_until),
         :ok <- record_success_audit(app, agent, certificate, request_id),
         :ok <- maybe_inject_fault(:before_token_consumption),
         {:ok, _consumed_token} <-
           consume_token_last(token, request_id, certificate.id, now) do
      %{
        certificate: signed.certificate,
        ca_chain: signed.ca_chain,
        cert_record: certificate,
        app_certificate: app_certificate,
        replayed: false
      }
    else
      {:error, reason} -> Repo.rollback(normalize_error(reason))
      _other -> Repo.rollback(:issuance_failed)
    end
  end

  defp validate_active_assignment(
         %App{status: "active", agent_id: agent_id},
         %Agent{id: agent_id, status: status}
       )
       when status in @runtime_agent_statuses,
       do: :ok

  defp validate_active_assignment(_app, _agent), do: {:error, :invalid_agent_assignment}

  defp parse_csr(csr_pem) do
    case CSR.parse(csr_pem) do
      {:ok, csr} -> {:ok, csr}
      {:error, _reason} -> {:error, :invalid_csr}
    end
  end

  defp supported_public_key(csr) do
    csr
    |> X509.CSR.public_key()
    |> validate_public_key()
  rescue
    _error -> {:error, :invalid_csr}
  end

  defp validate_public_key({:RSAPublicKey, modulus, exponent} = public_key)
       when is_integer(modulus) and modulus > 0 and is_integer(exponent) do
    if rsa_modulus_bits(modulus) >= 2048 and exponent >= 3 and exponent < modulus and
         rem(exponent, 2) == 1,
       do: {:ok, public_key},
       else: {:error, :unsupported_key}
  end

  defp validate_public_key({{:ECPoint, point}, {:namedCurve, curve}} = public_key)
       when is_binary(point) do
    if curve in @supported_ec_curves,
      do: {:ok, public_key},
      else: {:error, :unsupported_key}
  end

  defp validate_public_key({point, {:namedCurve, curve}} = public_key)
       when is_binary(point) do
    if curve in @supported_ec_curves,
      do: {:ok, public_key},
      else: {:error, :unsupported_key}
  end

  defp validate_public_key(_public_key), do: {:error, :unsupported_key}

  defp rsa_modulus_bits(modulus) do
    modulus
    |> :binary.encode_unsigned()
    |> then(fn <<first, _rest::binary>> = bytes ->
      byte_size(bytes) * 8 - leading_zero_bits(first)
    end)
  end

  defp leading_zero_bits(byte) when byte >= 128, do: 0
  defp leading_zero_bits(byte) when byte >= 64, do: 1
  defp leading_zero_bits(byte) when byte >= 32, do: 2
  defp leading_zero_bits(byte) when byte >= 16, do: 3
  defp leading_zero_bits(byte) when byte >= 8, do: 4
  defp leading_zero_bits(byte) when byte >= 4, do: 5
  defp leading_zero_bits(byte) when byte >= 2, do: 6
  defp leading_zero_bits(1), do: 7

  defp persisted_certificate_attrs(signed, app_id) do
    with {:ok, parsed} <- Certificate.from_pem(signed.certificate),
         {:ok, canonical_fingerprint} <-
           CertificateIdentity.canonical_fingerprint_from_pem(signed.certificate) do
      {:ok,
       %{
         serial_number: parsed.serial_number,
         fingerprint: parsed.fingerprint,
         canonical_fingerprint: canonical_fingerprint,
         certificate_pem: signed.certificate,
         subject: parsed.subject,
         issuer: parsed.issuer,
         common_name: app_id,
         organization: "SecretHub Applications",
         organizational_unit: nil,
         valid_from: parsed.valid_from,
         valid_until: parsed.valid_until,
         cert_type: :app_client,
         key_usage: ["digitalSignature"],
         issuer_id: signed.issuer.id,
         entity_id: app_id,
         entity_type: "app",
         metadata: %{
           "extended_key_usage" => ["clientAuth"],
           "san_uri" => ["urn:secrethub:app:#{app_id}"]
         }
       }}
    else
      _other -> {:error, :issuance_failed}
    end
  end

  defp record_success_audit(app, agent, certificate, request_id) do
    record_allowed_audit(app.id, agent.id, certificate.id, request_id, "issued")
  end

  defp record_allowed_audit(app_id, agent_id, certificate_id, request_id, result_code) do
    attrs = %{
      event_type: "auth.app_certificate_issuance_allowed",
      actor_type: "app",
      actor_id: app_id,
      app_id: app_id,
      agent_id: agent_id,
      access_granted: true,
      correlation_id: request_id,
      event_data: %{
        "app_certificate_issuance" => %{
          "agent_id" => agent_id,
          "app_id" => app_id,
          "certificate_id" => certificate_id,
          "request_id" => request_id,
          "result_code" => result_code
        }
      }
    }

    case Audit.log_event(attrs) do
      {:ok, _audit_log} -> :ok
      {:error, _reason} -> {:error, :issuance_failed}
    end
  end

  defp original_issuance_agent_id(app_id, certificate_id, request_id) do
    original_audit =
      Repo.one(
        from(a in AuditLog,
          where: a.event_type == "auth.app_certificate_issuance_allowed",
          where: a.app_id == ^app_id,
          where: a.correlation_id == ^request_id,
          where:
            fragment(
              "?->'app_certificate_issuance'->>'certificate_id' = ?",
              a.event_data,
              ^certificate_id
            ),
          where:
            fragment(
              "?->'app_certificate_issuance'->>'result_code' = 'issued'",
              a.event_data
            ),
          order_by: [asc: a.sequence_number],
          limit: 1
        )
      )

    with %AuditLog{
           actor_type: "app",
           actor_id: ^app_id,
           app_id: ^app_id,
           agent_id: agent_id,
           access_granted: true,
           correlation_id: ^request_id
         } <- original_audit,
         {:ok, normalized_agent_id} <- Ecto.UUID.cast(agent_id),
         true <-
           original_audit.event_data ==
             %{
               "app_certificate_issuance" => %{
                 "agent_id" => normalized_agent_id,
                 "app_id" => app_id,
                 "certificate_id" => certificate_id,
                 "request_id" => request_id,
                 "result_code" => "issued"
               }
             } do
      {:ok, normalized_agent_id}
    else
      _other -> {:error, :issuance_failed}
    end
  end

  defp consume_token_last(token, request_id, certificate_id, now) do
    token
    |> AppBootstrapToken.changeset(%{
      used: true,
      used_at: now,
      issuance_request_id: request_id,
      issued_certificate_id: certificate_id
    })
    |> Repo.update()
  end

  defp record_error_audit(reason, request_id) do
    event_type =
      if reason in @denied_errors,
        do: "auth.app_certificate_issuance_denied",
        else: "auth.app_certificate_issuance_failed"

    record_post_rollback_audit(%{
      event_type: event_type,
      actor_type: "app_bootstrap",
      access_granted: false,
      denial_reason: Atom.to_string(reason),
      correlation_id: request_id,
      event_data: %{
        "app_certificate_issuance" => %{
          "request_id" => request_id,
          "result_code" => Atom.to_string(reason)
        }
      }
    })
  end

  defp record_invalid_request_id_audit do
    record_post_rollback_audit(%{
      event_type: "auth.app_certificate_issuance_denied",
      actor_type: "app_bootstrap",
      access_granted: false,
      denial_reason: "invalid_request_id",
      event_data: %{
        "app_certificate_issuance" => %{
          "result_code" => "invalid_request_id"
        }
      }
    })
  end

  defp record_post_rollback_audit(attrs) do
    maybe_inject_post_rollback_audit_fault()

    case Audit.log_event(attrs) do
      {:ok, _audit_log} -> :ok
      {:error, _reason} -> log_post_rollback_audit_failure()
    end
  rescue
    _error -> log_post_rollback_audit_failure()
  catch
    :exit, _reason -> log_post_rollback_audit_failure()
  end

  defp log_post_rollback_audit_failure do
    Logger.error("Application certificate post-rollback audit could not be recorded")
    :ok
  rescue
    _error -> :ok
  catch
    _kind, _reason -> :ok
  end

  defp normalize_error(reason) when reason in @stable_errors, do: reason
  defp normalize_error(_reason), do: :issuance_failed

  if Application.compile_env(:secrethub_core, :env) == :test do
    defp maybe_inject_fault(point) do
      if Process.get(:secrethub_app_certificate_issuance_fault) == point,
        do: {:error, :issuance_failed},
        else: :ok
    end

    defp maybe_inject_post_rollback_audit_fault do
      case Process.get(:secrethub_app_certificate_issuance_audit_fault) do
        :raise -> raise "injected post-rollback audit failure"
        :exit -> exit(:injected_post_rollback_audit_failure)
        _other -> :ok
      end
    end

    defp maybe_inject_renewal_post_rollback_audit_fault do
      case Process.get(:secrethub_app_certificate_renewal_audit_fault) do
        :raise -> raise "injected renewal post-rollback audit failure"
        :exit -> exit(:injected_renewal_post_rollback_audit_failure)
        _other -> :ok
      end
    end

    defp maybe_inject_renewal_fault(point) do
      if Process.get(:secrethub_app_certificate_renewal_fault) == point,
        do: {:error, :renewal_failed},
        else: :ok
    end

    defp maybe_inject_revocation_fault(point) do
      if Process.get(:secrethub_app_certificate_revocation_fault) == point,
        do: {:error, :revocation_failed},
        else: :ok
    end
  else
    defp maybe_inject_fault(_point), do: :ok
    defp maybe_inject_post_rollback_audit_fault, do: :ok
    defp maybe_inject_renewal_post_rollback_audit_fault, do: :ok
    defp maybe_inject_renewal_fault(_point), do: :ok
    defp maybe_inject_revocation_fault(_point), do: :ok
  end
end
