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
    AuditLog,
    Certificate
  }

  alias SecretHub.Shared.Schemas.Application, as: App

  @runtime_agent_statuses [:active, :trusted_connected]
  @supported_ec_curves [
    {1, 2, 840, 10_045, 3, 1, 7},
    {1, 3, 132, 0, 34}
  ]
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
  else
    defp maybe_inject_fault(_point), do: :ok
    defp maybe_inject_post_rollback_audit_fault, do: :ok
  end
end
