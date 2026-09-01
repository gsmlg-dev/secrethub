defmodule SecretHub.Core.PKI.ClientAuth.CRLManager do
  @moduledoc """
  Manages complete signed Certificate Revocation Lists (CRLs) for Client Auth PKI.

  Every revocation or scheduled refresh transactionally generates a new signed CRL,
  increments the CRL number and generation, and publishes the new trust bundle.
  """

  require Logger
  import Ecto.Query

  alias SecretHub.Core.{Audit, Repo}
  alias SecretHub.Core.PKI.ClientAuth.{CAValidator, Notifier}
  alias SecretHub.Core.Vault.SealState
  alias SecretHub.Shared.Crypto.Encryption
  alias SecretHub.Shared.Schemas.{Certificate, ClientAuthAuthority, ClientAuthCrl}
  alias X509.CRL.Extension, as: CRLExtension

  @valid_reasons ~w(key_compromise keyCompromise superseded cessation_of_operation cessationOfOperation privilege_withdrawn privilegeWithdrawn operator_revoked identity_disabled)
  @crl_validity_hours 48
  @crl_refresh_ahead_hours 12
  @clock_skew_seconds 300

  @doc """
  Generates a new signed full CRL for the locked authority.
  Must be called within a database transaction where the authority row is locked.
  """
  @spec generate_crl_locked(ClientAuthAuthority.t(), term(), Certificate.t(), keyword()) ::
          {:ok, ClientAuthCrl.t(), ClientAuthAuthority.t()}
          | {:error, term()}
  def generate_crl_locked(
        %ClientAuthAuthority{} = authority,
        ca_key,
        %Certificate{} = ca_cert,
        opts \\ []
      ) do
    now = Keyword.get(opts, :now, DateTime.utc_now() |> DateTime.truncate(:second))

    this_update =
      Keyword.get(opts, :this_update, DateTime.add(now, -@clock_skew_seconds, :second))

    next_update =
      Keyword.get(
        opts,
        :next_update,
        DateTime.add(now, @crl_validity_hours * 3600, :second)
      )

    with :ok <- validate_ca(authority, ca_cert, ca_key, now),
         {:ok, parsed_ca} <- X509.Certificate.from_pem(ca_cert.certificate_pem) do
      # Query all active revoked certificates for this authority that have not yet naturally expired
      revoked_certs =
        Repo.all(
          from(c in Certificate,
            where: c.client_auth_authority_id == ^authority.id,
            where: c.cert_type == :client_auth_client,
            where: c.revoked == true,
            where: c.valid_until > ^now,
            order_by: [asc: c.revoked_at, asc: c.id]
          )
        )

      new_crl_number = authority.current_crl_number + 1
      new_generation = authority.current_generation + 1

      entries = Enum.map(revoked_certs, &build_crl_entry(&1, now))

      crl_extensions = [
        crl_number: CRLExtension.crl_number(new_crl_number)
      ]

      crl =
        X509.CRL.new(
          entries,
          parsed_ca,
          ca_key,
          hash: ca_signature_hash(authority, ca_cert),
          this_update: this_update,
          next_update: next_update,
          extensions: crl_extensions
        )

      # Validate CRL signature and issuer against CA
      if !X509.CRL.valid?(crl, parsed_ca) do
        {:error, :crl_generation_failed}
      else
        crl_der = X509.CRL.to_der(crl)
        crl_pem = X509.CRL.to_pem(crl)
        crl_der_sha256 = :crypto.hash(:sha256, crl_der) |> Base.encode16(case: :lower)

        crl_attrs = %{
          authority_id: authority.id,
          issuer_certificate_id: ca_cert.id,
          crl_number: new_crl_number,
          generation: new_generation,
          crl_pem: crl_pem,
          crl_der_sha256: crl_der_sha256,
          this_update: this_update,
          next_update: next_update,
          revoked_count: length(revoked_certs)
        }

        with {:ok, crl_record} <-
               %ClientAuthCrl{}
               |> ClientAuthCrl.changeset(crl_attrs)
               |> Repo.insert(),
             {:ok, updated_authority} <-
               authority
               |> ClientAuthAuthority.changeset(%{
                 current_crl_id: crl_record.id,
                 current_crl_number: new_crl_number,
                 current_generation: new_generation
               })
               |> Repo.update(),
             :ok <- record_crl_audit(updated_authority, crl_record) do
          {:ok, crl_record, updated_authority}
        else
          {:error, {:audit_failed, reason}} ->
            Repo.rollback({:audit_failed, reason})

          {:error, reason} ->
            {:error, reason}
        end
      end
    end
  rescue
    e ->
      Logger.error("Failed to generate CRL: #{Exception.message(e)}")
      {:error, :crl_generation_failed}
  end

  @doc """
  Revokes a client certificate and publishes a new signed CRL in a single transaction.
  """
  @spec revoke_certificate(term(), String.t(), keyword()) ::
          {:ok,
           %{
             certificate: Certificate.t(),
             crl: ClientAuthCrl.t(),
             generation: pos_integer(),
             crl_number: pos_integer()
           }}
          | {:error,
             :vault_sealed
             | :vault_unavailable
             | :certificate_not_found
             | :certificate_already_revoked
             | :invalid_reason
             | term()}
  def revoke_certificate(certificate_id, reason, opts \\ []) do
    with {:ok, normalized_cert_id} <- cast_uuid(certificate_id, :certificate_not_found),
         :ok <- validate_reason(reason),
         :ok <- check_unsealed() do
      transact_revocation(normalized_cert_id, reason, opts)
    end
  end

  @doc """
  Refreshes the current CRL if it is nearing nextUpdate or if forced.
  """
  @spec refresh_if_needed(keyword()) ::
          {:ok,
           :not_modified
           | %{crl: ClientAuthCrl.t(), generation: pos_integer(), crl_number: pos_integer()}}
          | {:error, term()}
  def refresh_if_needed(opts \\ []) do
    force = Keyword.get(opts, :force, false)
    now = Keyword.get(opts, :now, DateTime.utc_now() |> DateTime.truncate(:second))

    with :ok <- check_unsealed() do
      Repo.transaction(fn ->
        case lock_authority() do
          nil ->
            Repo.rollback(:authority_not_initialized)

          %ClientAuthAuthority{current_crl: nil} ->
            Repo.rollback(:authority_unavailable)

          %ClientAuthAuthority{current_crl: %ClientAuthCrl{} = current_crl} = authority ->
            hours_until_expiry = DateTime.diff(current_crl.next_update, now, :second) / 3600.0

            if force or hours_until_expiry <= @crl_refresh_ahead_hours do
              case do_refresh_crl_locked(authority, now) do
                {:ok, res} -> res
                {:error, reason} -> Repo.rollback(reason)
              end
            else
              :not_modified
            end
        end
      end)
      |> case do
        {:ok, :not_modified} ->
          {:ok, :not_modified}

        {:ok, result} ->
          Notifier.notify_bundle_updated(
            result.generation,
            result.crl_number,
            "crl_refreshed"
          )

          {:ok, result}

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  @doc """
  Forces an immediate CRL refresh and generation bump.
  """
  @spec refresh_crl(keyword()) ::
          {:ok, %{crl: ClientAuthCrl.t(), generation: pos_integer(), crl_number: pos_integer()}}
          | {:error, term()}
  def refresh_crl(opts \\ []) do
    refresh_if_needed(Keyword.put(opts, :force, true))
    |> case do
      {:ok, :not_modified} -> {:error, :crl_generation_failed}
      other -> other
    end
  end

  # Helper functions

  defp transact_revocation(cert_id, reason, opts) do
    now = Keyword.get(opts, :now, DateTime.utc_now() |> DateTime.truncate(:second))

    Repo.transaction(fn ->
      with %ClientAuthAuthority{} = authority <- lock_authority(),
           %Certificate{} = cert <- lock_certificate(cert_id),
           :ok <- validate_revocable_cert(cert, authority),
           {:ok, ca_key} <- decrypt_ca_key(authority.ca_certificate) do
        if cert.revoked do
          %{
            certificate: cert,
            crl: authority.current_crl,
            generation: authority.current_generation,
            crl_number: authority.current_crl_number,
            already_revoked: true
          }
        else
          {:ok, revoked_cert} =
            cert
            |> Certificate.changeset(%{
              revoked: true,
              revoked_at: now,
              revocation_reason: reason
            })
            |> Repo.update()

          actor = Keyword.get(opts, :actor, %{})

          {:ok, new_crl, updated_authority} =
            generate_crl_locked(authority, ca_key, authority.ca_certificate,
              now: now,
              actor: actor
            )

          :ok = record_revocation_audit(revoked_cert, reason, actor)

          %{
            certificate: revoked_cert,
            crl: new_crl,
            generation: updated_authority.current_generation,
            crl_number: updated_authority.current_crl_number,
            already_revoked: false
          }
        end
      else
        nil -> Repo.rollback(:authority_not_initialized)
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
    |> case do
      {:ok, %{already_revoked: true} = result} ->
        {:ok, Map.delete(result, :already_revoked)}

      {:ok, result} ->
        Notifier.notify_bundle_updated(
          result.generation,
          result.crl_number,
          "certificate_revoked"
        )

        {:ok, Map.delete(result, :already_revoked)}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp do_refresh_crl_locked(authority, now) do
    with {:ok, ca_key} <- decrypt_ca_key(authority.ca_certificate),
         {:ok, new_crl, updated_authority} <-
           generate_crl_locked(authority, ca_key, authority.ca_certificate, now: now) do
      {:ok,
       %{
         crl: new_crl,
         generation: updated_authority.current_generation,
         crl_number: updated_authority.current_crl_number
       }}
    end
  end

  defp build_crl_entry(%Certificate{} = cert, now) do
    serial_int = parse_serial_to_integer(cert.serial_number)
    revocation_date = cert.revoked_at || now
    reason_extension = reason_to_extension(cert.revocation_reason)
    extensions = if reason_extension, do: [reason_extension], else: []

    X509.CRL.Entry.new(serial_int, revocation_date, extensions)
  end

  defp parse_serial_to_integer(serial_str) when is_binary(serial_str) do
    clean_hex = String.replace(serial_str, ":", "")
    String.to_integer(clean_hex, 16)
  rescue
    _ -> String.to_integer(serial_str)
  end

  defp reason_to_extension("key_compromise"), do: CRLExtension.reason_code(:keyCompromise)
  defp reason_to_extension("keyCompromise"), do: CRLExtension.reason_code(:keyCompromise)
  defp reason_to_extension("superseded"), do: CRLExtension.reason_code(:superseded)

  defp reason_to_extension("cessation_of_operation"),
    do: CRLExtension.reason_code(:cessationOfOperation)

  defp reason_to_extension("cessationOfOperation"),
    do: CRLExtension.reason_code(:cessationOfOperation)

  defp reason_to_extension("privilege_withdrawn"),
    do: CRLExtension.reason_code(:privilegeWithdrawn)

  defp reason_to_extension("privilegeWithdrawn"),
    do: CRLExtension.reason_code(:privilegeWithdrawn)

  defp reason_to_extension("operator_revoked"), do: CRLExtension.reason_code(:privilegeWithdrawn)
  defp reason_to_extension("identity_disabled"), do: CRLExtension.reason_code(:privilegeWithdrawn)
  defp reason_to_extension(_), do: nil

  defp lock_authority do
    Repo.one(
      from(a in ClientAuthAuthority,
        where: a.slug == "client-auth" and a.status == "active",
        preload: [:ca_certificate, :current_crl],
        lock: "FOR UPDATE"
      )
    )
  end

  defp lock_certificate(cert_id) do
    case Repo.one(
           from(c in Certificate,
             where: c.id == ^cert_id,
             lock: "FOR UPDATE"
           )
         ) do
      nil -> {:error, :certificate_not_found}
      cert -> cert
    end
  end

  defp validate_revocable_cert(
         %Certificate{cert_type: :client_auth_client, client_auth_authority_id: auth_id},
         %ClientAuthAuthority{id: auth_id}
       ),
       do: :ok

  defp validate_revocable_cert(%Certificate{cert_type: :client_auth_client}, _authority),
    do: {:error, :certificate_not_found}

  defp validate_revocable_cert(_cert, _authority),
    do: {:error, :certificate_not_found}

  defp decrypt_ca_key(%Certificate{private_key_encrypted: encrypted_key})
       when is_binary(encrypted_key) do
    with {:ok, master_key} <- get_pki_master_key() do
      case Encryption.decrypt_from_blob(encrypted_key, master_key) do
        {:ok, key_pem} ->
          {:ok, X509.PrivateKey.from_pem!(key_pem)}

        {:error, reason} ->
          Logger.error("Failed to decrypt CA private key: #{inspect(reason)}")
          {:error, :vault_unavailable}
      end
    end
  rescue
    e ->
      Logger.error("Error decrypting CA key: #{inspect(e)}")
      {:error, :vault_unavailable}
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

  defp validate_reason(reason) when reason in @valid_reasons, do: :ok
  defp validate_reason(_), do: {:error, :invalid_reason}

  defp validate_ca(authority, ca_cert, ca_key, now) do
    case CAValidator.validate(authority, ca_cert, ca_key,
           now: now,
           requested_ttl: @crl_validity_hours * 3600
         ) do
      :ok -> :ok
      {:error, code, _detail} -> {:error, code}
    end
  end

  defp cast_uuid(val, err) do
    case Ecto.UUID.cast(val) do
      {:ok, uuid} -> {:ok, uuid}
      :error -> {:error, err}
    end
  end

  defp ca_signature_hash(%ClientAuthAuthority{key_algorithm: "ecdsa_p384"}, _), do: :sha384
  defp ca_signature_hash(%ClientAuthAuthority{key_algorithm: "rsa_4096"}, _), do: :sha384
  defp ca_signature_hash(%ClientAuthAuthority{key_algorithm: "ecdsa_p256"}, _), do: :sha256
  defp ca_signature_hash(%ClientAuthAuthority{key_algorithm: "rsa_2048"}, _), do: :sha256

  defp ca_signature_hash(_, %Certificate{certificate_pem: pem}) do
    case X509.Certificate.from_pem(pem) do
      {:ok, cert} ->
        case X509.Certificate.public_key(cert) do
          {:ECPoint, _} -> :sha384
          _ -> :sha256
        end

      _ ->
        :sha256
    end
  end

  defp ca_signature_hash(_, _), do: :sha256

  defp record_crl_audit(authority, crl) do
    attrs = %{
      event_type: "pki.client_auth.crl_published",
      actor_type: "system",
      actor_id: "client_auth_crl_manager",
      access_granted: true,
      correlation_id: crl.id,
      event_data: %{
        "authority" => authority.slug,
        "generation" => authority.current_generation,
        "crl_number" => crl.crl_number,
        "crl_der_sha256" => crl.crl_der_sha256,
        "revoked_count" => crl.revoked_count,
        "next_update" => DateTime.to_iso8601(crl.next_update)
      }
    }

    case Audit.log_event(attrs) do
      {:ok, _} -> :ok
      {:error, reason} -> {:error, {:audit_failed, reason}}
    end
  end

  defp record_revocation_audit(cert, reason, actor) do
    actor_type = Map.get(actor, :actor_type) || Map.get(actor, "actor_type") || "admin"
    actor_id = Map.get(actor, :actor_id) || Map.get(actor, "actor_id") || "admin"

    source_ip =
      Map.get(actor, :source_ip) || Map.get(actor, "source_ip") || Map.get(actor, :client_ip)

    attrs = %{
      event_type: "pki.client_auth.certificate_revoked",
      actor_type: actor_type,
      actor_id: actor_id,
      source_ip: source_ip,
      access_granted: true,
      correlation_id: cert.id,
      event_data: %{
        "certificate_id" => cert.id,
        "serial_number" => cert.serial_number,
        "canonical_fingerprint" => cert.canonical_fingerprint,
        "client_auth_identity_id" => cert.client_auth_identity_id,
        "reason" => reason,
        "revoked_at" => DateTime.to_iso8601(cert.revoked_at)
      }
    }

    case Audit.log_event(attrs) do
      {:ok, _} -> :ok
      {:error, reason} -> Repo.rollback({:audit_failed, reason})
    end
  end
end
