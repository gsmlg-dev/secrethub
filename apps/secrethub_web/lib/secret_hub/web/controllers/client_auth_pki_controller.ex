defmodule SecretHub.Web.ClientAuthPKIController do
  @moduledoc """
  REST API Controller for Client Auth PKI operations.
  """

  use SecretHub.Web, :controller
  require Logger

  alias SecretHub.Core.PKI.ClientAuth

  @doc """
  POST /v1/pki/client-auth/authority/init
  Initializes the Client Auth PKI Root CA authority.
  """
  def init_authority(conn, params) do
    actor = get_actor(conn)

    case ClientAuth.init_authority(params, actor: actor) do
      {:ok, %{authority: authority}} ->
        conn
        |> put_status(:created)
        |> json(%{data: render_authority(authority)})

      {:error, reason} when reason in [:already_initialized, :authority_already_initialized] ->
        conn
        |> put_status(:conflict)
        |> json(%{error: "Client Auth Authority is already initialized"})

      {:error, %Ecto.Changeset{} = changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Validation failed", details: format_changeset_errors(changeset)})

      {:error, {code, detail}} when is_atom(code) and is_binary(detail) ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: to_string(code), detail: detail})

      {:error, reason} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: format_error_message(reason)})
    end
  end

  @doc """
  GET /v1/pki/client-auth/authority/status
  Public/operator status of the Client Auth Authority.
  """
  def authority_status(conn, params) do
    slug = Map.get(params, "slug", "client-auth")

    case ClientAuth.authority_status(slug) do
      {:ok, status} ->
        json(conn, %{data: status})

      {:error, reason} when reason in [:not_found, :authority_not_initialized] ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Authority not found"})

      {:error, reason} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: format_error_message(reason)})
    end
  end

  @doc """
  GET /v1/pki/client-auth/bundle
  Returns the deterministic public trust bundle (CA PEM + signed CRL PEM + metadata).
  """
  def get_bundle(conn, params) do
    slug = Map.get(params, "slug", "client-auth")

    case ClientAuth.current_bundle(slug) do
      {:ok, bundle} ->
        json(conn, %{data: bundle})

      {:error, reason} when reason in [:not_initialized, :authority_not_initialized] ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{error: "Authority not initialized"})

      {:error, reason} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: format_error_message(reason)})
    end
  end

  @doc """
  POST /v1/pki/client-auth/identities
  Creates a new client identity.
  """
  def create_identity(conn, params) do
    actor = get_actor(conn)

    case ClientAuth.create_identity(params, actor: actor) do
      {:ok, identity} ->
        conn
        |> put_status(:created)
        |> json(%{data: render_identity(identity)})

      {:error, %Ecto.Changeset{} = changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Validation failed", details: format_changeset_errors(changeset)})

      {:error, reason} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: format_error_message(reason)})
    end
  end

  @doc """
  GET /v1/pki/client-auth/identities
  Lists client identities.
  """
  def list_identities(conn, params) do
    identities = ClientAuth.list_identities(params)
    json(conn, %{data: Enum.map(identities, &render_identity/1)})
  end

  @doc """
  GET /v1/pki/client-auth/identities/:id
  Gets a client identity by ID.
  """
  def get_identity(conn, %{"id" => id}) do
    case ClientAuth.get_identity(id) do
      {:ok, identity} ->
        json(conn, %{data: render_identity(identity)})

      {:error, _reason} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Identity not found"})
    end
  end

  @doc """
  POST /v1/pki/client-auth/identities/:id/disable
  Disables an identity and revokes all its active certificates.
  """
  def disable_identity(conn, %{"id" => id} = params) do
    actor = get_actor(conn)

    case ClientAuth.disable_identity(id, params, actor: actor) do
      {:ok, identity} ->
        json(conn, %{data: render_identity(identity)})

      {:error, reason} when reason in [:not_found, :identity_not_found] ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Identity not found"})

      {:error, reason} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: format_error_message(reason)})
    end
  end

  @doc """
  POST /v1/pki/client-auth/issue
  Issues a canonical client certificate from a CSR. Requires UUID request_id.
  """
  def issue_certificate(conn, params) do
    request_id = Map.get(params, "request_id") || Map.get(params, :request_id)

    case Ecto.UUID.cast(request_id || "") do
      {:ok, valid_request_id} ->
        actor = get_actor(conn)
        params_with_id = Map.put(params, "request_id", valid_request_id)

        case ClientAuth.issue_certificate(params_with_id, actor: actor) do
          {:ok, %{cert_record: cert_record} = result} ->
            data = %{
              cert_id: cert_record.id,
              certificate_pem: result.certificate,
              ca_bundle_pem: result.ca_bundle_pem,
              serial_number: cert_record.serial_number,
              fingerprint: cert_record.fingerprint,
              replayed: Map.get(result, :replayed, false),
              expires_at: cert_record.valid_until
            }

            conn
            |> put_status(:created)
            |> json(%{data: data})

          {:error, :idempotency_conflict} ->
            conn
            |> put_status(:conflict)
            |> json(%{
              error:
                "Idempotency conflict: request_id was previously used with different parameters"
            })

          {:error, %Ecto.Changeset{} = changeset} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: "Validation failed", details: format_changeset_errors(changeset)})

          {:error, reason} ->
            conn
            |> put_status(:bad_request)
            |> json(%{error: format_error_message(reason)})
        end

      :error ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Missing or invalid request_id (must be a valid UUID)"})
    end
  end

  @doc """
  GET /v1/pki/client-auth/certificates
  Lists issued client certificates.
  """
  def list_certificates(conn, params) do
    certs = ClientAuth.list_certificates(params)
    json(conn, %{data: Enum.map(certs, &render_certificate/1)})
  end

  @doc """
  GET /v1/pki/client-auth/certificates/:id
  Gets certificate by ID.
  """
  def get_certificate(conn, %{"id" => id}) do
    case ClientAuth.get_certificate(id) do
      {:ok, cert} ->
        json(conn, %{data: render_certificate(cert)})

      {:error, reason} when reason in [:not_found, :certificate_not_found] ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Certificate not found"})
    end
  end

  @doc """
  POST /v1/pki/client-auth/certificates/:id/revoke
  Revokes a client certificate and publishes a new CRL.
  """
  def revoke_certificate(conn, %{"id" => id} = params) do
    actor = get_actor(conn)

    case ClientAuth.revoke_certificate(id, params, actor: actor) do
      {:ok, %{certificate: cert}} ->
        json(conn, %{data: render_certificate(cert)})

      {:error, reason} when reason in [:not_found, :certificate_not_found] ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Certificate not found"})

      {:error, reason} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: format_error_message(reason)})
    end
  end

  @doc """
  POST /v1/pki/client-auth/crl/refresh
  Forces an immediate CRL refresh.
  """
  def refresh_crl(conn, params) do
    slug = Map.get(params, "slug", "client-auth")
    actor = get_actor(conn)

    case ClientAuth.force_refresh_crl(slug, actor: actor) do
      {:ok, %{crl: crl, generation: gen, crl_number: crl_num}} ->
        json(conn, %{
          data: %{
            generation: gen,
            crl_number: crl_num,
            this_update: crl.this_update,
            next_update: crl.next_update,
            crl_der_sha256: crl.crl_der_sha256
          }
        })

      {:error, reason} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: format_error_message(reason)})
    end
  end

  @doc """
  GET /v1/pki/client-auth/bundle/receipts
  Lists bundle receipts for authority.
  """
  def list_receipts(conn, params) do
    slug = Map.get(params, "slug", "client-auth")
    receipts = ClientAuth.list_bundle_receipts(slug)
    json(conn, %{data: Enum.map(receipts, &render_receipt/1)})
  end

  defp get_actor(conn) do
    admin_id = get_session(conn, :admin_id) || conn.assigns[:current_admin_id] || "admin"

    source_ip = :inet.ntoa(conn.remote_ip) |> to_string()

    %{
      actor_type: "admin",
      actor_id: to_string(admin_id),
      source_ip: source_ip
    }
  end

  # Rendering Helpers

  defp render_authority(auth) do
    %{
      id: auth.id,
      slug: auth.slug,
      name: auth.name,
      status: auth.status,
      current_generation: auth.current_generation,
      current_crl_number: auth.current_crl_number,
      key_algorithm: auth.key_algorithm,
      default_ttl_seconds: auth.default_ttl_seconds,
      max_ttl_seconds: auth.max_ttl_seconds,
      inserted_at: auth.inserted_at,
      updated_at: auth.updated_at
    }
  end

  defp render_identity(id) do
    %{
      id: id.id,
      name: id.name,
      status: id.status,
      metadata: id.metadata,
      inserted_at: id.inserted_at,
      updated_at: id.updated_at
    }
  end

  defp render_certificate(cert) do
    %{
      id: cert.id,
      serial_number: cert.serial_number,
      fingerprint: cert.fingerprint,
      canonical_fingerprint: cert.canonical_fingerprint,
      cert_type: cert.cert_type,
      subject: cert.subject,
      common_name: cert.common_name,
      valid_from: cert.valid_from,
      valid_until: cert.valid_until,
      revoked: cert.revoked,
      revoked_at: cert.revoked_at,
      revocation_reason: cert.revocation_reason,
      client_auth_identity_id: cert.client_auth_identity_id,
      metadata: cert.metadata,
      inserted_at: cert.inserted_at
    }
  end

  defp render_receipt(r) do
    %{
      id: r.id,
      agent_id: r.agent_id,
      generation: r.generation,
      crl_number: r.crl_number,
      bundle_sha256: r.bundle_sha256,
      status: r.status,
      last_error_code: r.last_error_code,
      last_error_detail: r.last_error_detail,
      applied_at: r.applied_at,
      inserted_at: r.inserted_at,
      updated_at: r.updated_at
    }
  end

  defp format_changeset_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end

  defp format_error_message({code, detail}) when is_atom(code) and is_binary(detail) do
    "#{code}: #{detail}"
  end

  defp format_error_message(reason) when is_atom(reason), do: to_string(reason)
  defp format_error_message(reason) when is_binary(reason), do: reason
  defp format_error_message(reason), do: inspect(reason)
end
