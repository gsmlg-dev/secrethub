defmodule SecretHub.Web.PKIController do
  @moduledoc """
  API Controller for PKI (Public Key Infrastructure) operations.

  Handles:
  - Root CA generation
  - Intermediate CA generation
  - Certificate signing requests (CSR)
  - Certificate revocation
  - Certificate listing and retrieval

  All PKI operations require an unsealed vault.
  """

  use SecretHub.Web, :controller
  require Logger

  alias SecretHub.Core.{Apps, PKI.AppCertificates, PKI.CA, Repo}
  alias SecretHub.Shared.Schemas.Certificate

  @app_certificate_revocation_reasons ~w(superseded compromised operator_revoked app_suspended)

  @doc """
  POST /v1/pki/ca/root/generate

  Generates a new Root CA certificate.

  Request body:
  ```json
  {
    "common_name": "SecretHub Root CA",
    "organization": "SecretHub Inc",
    "key_type": "rsa",
    "key_size": 4096,
    "validity_days": 3650,
    "country": "US",
    "state": "California",
    "locality": "San Francisco"
  }
  ```

  Response:
  ```json
  {
    "certificate": "-----BEGIN CERTIFICATE-----...",
    "private_key": "-----BEGIN RSA PRIVATE KEY-----...",
    "serial_number": "1A2B3C...",
    "fingerprint": "sha256:ab:cd:ef...",
    "cert_id": "uuid"
  }
  ```
  """
  def generate_root_ca(conn, params) do
    common_name = Map.get(params, "common_name")
    organization = Map.get(params, "organization")

    cond do
      is_nil(common_name) or common_name == "" ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "common_name is required"})

      is_nil(organization) or organization == "" ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "organization is required"})

      true ->
        opts = build_ca_opts(params)

        case CA.generate_root_ca(common_name, organization, opts) do
          {:ok, %{certificate: cert_pem, private_key: key_pem, cert_record: cert_record}} ->
            Logger.info("Root CA generated: #{common_name}")

            conn
            |> put_status(:created)
            |> json(%{
              certificate: cert_pem,
              private_key: key_pem,
              serial_number: cert_record.serial_number,
              fingerprint: cert_record.fingerprint,
              cert_id: cert_record.id,
              valid_from: DateTime.to_iso8601(cert_record.valid_from),
              valid_until: DateTime.to_iso8601(cert_record.valid_until)
            })

          {:error, reason} ->
            Logger.error("Root CA generation failed: #{inspect(reason)}")

            conn
            |> put_status(:internal_server_error)
            |> json(%{error: "Failed to generate Root CA: #{inspect(reason)}"})
        end
    end
  end

  @doc """
  POST /v1/pki/ca/intermediate/generate

  Generates an Intermediate CA certificate signed by a Root CA.

  Request body:
  ```json
  {
    "common_name": "SecretHub Intermediate CA",
    "organization": "SecretHub Inc",
    "root_ca_id": "uuid-of-root-ca",
    "key_type": "rsa",
    "key_size": 4096,
    "validity_days": 1825
  }
  ```

  Response: Same as generate_root_ca
  """
  def generate_intermediate_ca(conn, params) do
    with {:ok, common_name} <- validate_required_param(params, "common_name"),
         {:ok, organization} <- validate_required_param(params, "organization"),
         {:ok, root_ca_id} <- validate_required_param(params, "root_ca_id") do
      do_generate_intermediate_ca(conn, common_name, organization, root_ca_id, params)
    else
      {:error, error_msg} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: error_msg})
    end
  end

  defp validate_required_param(params, key) do
    case Map.get(params, key) do
      nil -> {:error, "#{key} is required"}
      "" -> {:error, "#{key} is required"}
      value -> {:ok, value}
    end
  end

  defp do_generate_intermediate_ca(conn, common_name, organization, root_ca_id, params) do
    opts = build_ca_opts(params)

    case CA.generate_intermediate_ca(common_name, organization, root_ca_id, opts) do
      {:ok, %{certificate: cert_pem, private_key: key_pem, cert_record: cert_record}} ->
        Logger.info("Intermediate CA generated: #{common_name}")

        conn
        |> put_status(:created)
        |> json(%{
          certificate: cert_pem,
          private_key: key_pem,
          serial_number: cert_record.serial_number,
          fingerprint: cert_record.fingerprint,
          cert_id: cert_record.id,
          valid_from: DateTime.to_iso8601(cert_record.valid_from),
          valid_until: DateTime.to_iso8601(cert_record.valid_until)
        })

      {:error, reason} ->
        Logger.error("Intermediate CA generation failed: #{inspect(reason)}")

        conn
        |> put_status(:internal_server_error)
        |> json(%{error: "Failed to generate Intermediate CA: #{inspect(reason)}"})
    end
  end

  @doc """
  POST /v1/pki/sign-request

  Signs a Certificate Signing Request (CSR).

  Request body:
  ```json
  {
    "csr": "-----BEGIN CERTIFICATE REQUEST-----...",
    "ca_id": "uuid-of-signing-ca",
    "cert_type": "agent_client",
    "validity_days": 365
  }
  ```

  Response:
  ```json
  {
    "certificate": "-----BEGIN CERTIFICATE-----...",
    "serial_number": "1A2B3C...",
    "fingerprint": "sha256:ab:cd:ef...",
    "cert_id": "uuid"
  }
  ```
  """
  def sign_csr(conn, params) do
    csr_pem = Map.get(params, "csr")
    ca_id = Map.get(params, "ca_id")
    cert_type = Map.get(params, "cert_type", "agent_client")

    cond do
      is_nil(csr_pem) or csr_pem == "" ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "csr is required"})

      is_nil(ca_id) or ca_id == "" ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "ca_id is required"})

      not valid_cert_type?(cert_type) ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "cert_type must be one of: agent_client, app_client, admin_client"})

      true ->
        cert_type_atom = String.to_existing_atom(cert_type)
        validity_days = Map.get(params, "validity_days", 365)

        case CA.sign_csr(csr_pem, ca_id, cert_type_atom, validity_days: validity_days) do
          {:ok, %{certificate: cert_pem, cert_record: cert_record}} ->
            Logger.info("CSR signed successfully for cert_type: #{cert_type}")

            conn
            |> put_status(:created)
            |> json(%{
              certificate: cert_pem,
              serial_number: cert_record.serial_number,
              fingerprint: cert_record.fingerprint,
              cert_id: cert_record.id,
              valid_from: DateTime.to_iso8601(cert_record.valid_from),
              valid_until: DateTime.to_iso8601(cert_record.valid_until)
            })

          {:error, reason} ->
            Logger.error("CSR signing failed: #{inspect(reason)}")

            conn
            |> put_status(:internal_server_error)
            |> json(%{error: "Failed to sign CSR: #{inspect(reason)}"})
        end
    end
  end

  @doc """
  GET /v1/pki/certificates

  Lists all certificates with optional filtering.

  Query parameters:
  - cert_type: Filter by certificate type
  - revoked: Filter by revocation status (true/false)

  Response:
  ```json
  {
    "certificates": [
      {
        "id": "uuid",
        "common_name": "SecretHub Root CA",
        "cert_type": "root_ca",
        "serial_number": "1A2B3C...",
        "valid_from": "2024-01-01T00:00:00Z",
        "valid_until": "2034-01-01T00:00:00Z",
        "revoked": false
      }
    ]
  }
  ```
  """
  def list_certificates(conn, params) do
    import Ecto.Query

    query = from(c in Certificate, order_by: [desc: c.inserted_at])

    # Apply filters
    query =
      if cert_type = params["cert_type"] do
        from(c in query, where: c.cert_type == ^cert_type)
      else
        query
      end

    query =
      if revoked = params["revoked"] do
        revoked_bool = revoked == "true"
        from(c in query, where: c.revoked == ^revoked_bool)
      else
        query
      end

    certificates = Repo.all(query)

    certs_json =
      Enum.map(certificates, fn cert ->
        %{
          id: cert.id,
          common_name: cert.common_name,
          cert_type: cert.cert_type,
          serial_number: cert.serial_number,
          fingerprint: cert.fingerprint,
          valid_from: DateTime.to_iso8601(cert.valid_from),
          valid_until: DateTime.to_iso8601(cert.valid_until),
          revoked: cert.revoked,
          organization: cert.organization
        }
      end)

    conn
    |> json(%{certificates: certs_json})
  end

  @doc """
  GET /v1/pki/certificates/:id

  Retrieves a specific certificate by ID.

  Response:
  ```json
  {
    "id": "uuid",
    "common_name": "SecretHub Root CA",
    "cert_type": "root_ca",
    "serial_number": "1A2B3C...",
    "fingerprint": "sha256:ab:cd:ef...",
    "certificate": "-----BEGIN CERTIFICATE-----...",
    "valid_from": "2024-01-01T00:00:00Z",
    "valid_until": "2034-01-01T00:00:00Z",
    "revoked": false
  }
  ```
  """
  def get_certificate(conn, %{"id" => id}) do
    case Repo.get(Certificate, id) do
      nil ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Certificate not found"})

      cert ->
        conn
        |> json(%{
          id: cert.id,
          common_name: cert.common_name,
          cert_type: cert.cert_type,
          serial_number: cert.serial_number,
          fingerprint: cert.fingerprint,
          certificate: cert.certificate_pem,
          subject: cert.subject,
          issuer: cert.issuer,
          organization: cert.organization,
          valid_from: DateTime.to_iso8601(cert.valid_from),
          valid_until: DateTime.to_iso8601(cert.valid_until),
          revoked: cert.revoked,
          revoked_at: cert.revoked_at && DateTime.to_iso8601(cert.revoked_at),
          revocation_reason: cert.revocation_reason
        })
    end
  end

  @doc """
  POST /v1/pki/certificates/:id/revoke

  Revokes a certificate.

  Request body:
  ```json
  {
    "reason": "key_compromise"
  }
  ```

  Response:
  ```json
  {
    "revoked": true,
    "revoked_at": "2024-01-01T12:00:00Z"
  }
  ```
  """
  def revoke_certificate(conn, %{"id" => id} = params) do
    reason = Map.get(params, "reason", "unspecified")

    with {:ok, cert} <- fetch_certificate(id),
         :ok <- check_not_revoked(cert),
         {:ok, updated_cert} <- do_revoke_certificate(cert, reason) do
      Logger.info("Certificate revoked: #{cert.common_name}")

      conn
      |> json(%{
        revoked: true,
        revoked_at: DateTime.to_iso8601(updated_cert.revoked_at),
        reason: reason
      })
    else
      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Certificate not found"})

      {:error, :already_revoked} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Certificate is already revoked"})

      {:error, %Ecto.Changeset{} = changeset} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{
          error: "Failed to revoke certificate",
          details: inspect(changeset.errors)
        })

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{
          error: "Failed to revoke certificate",
          details: inspect(reason)
        })
    end
  end

  defp fetch_certificate(id) do
    case Ecto.UUID.cast(id) do
      {:ok, uuid} ->
        case Repo.get(Certificate, uuid) do
          nil -> {:error, :not_found}
          cert -> {:ok, cert}
        end

      :error ->
        {:error, :not_found}
    end
  end

  defp check_not_revoked(%{revoked: true}), do: {:error, :already_revoked}
  defp check_not_revoked(_cert), do: :ok

  defp do_revoke_certificate(cert, reason), do: CA.revoke_certificate(cert.id, reason)

  # Private helper functions

  defp build_ca_opts(params) do
    opts = []

    opts =
      if key_type = params["key_type"] do
        Keyword.put(opts, :key_type, String.to_existing_atom(key_type))
      else
        opts
      end

    opts =
      if key_size = params["key_size"] do
        Keyword.put(opts, :key_size, key_size)
      else
        opts
      end

    opts =
      if validity_days = params["validity_days"] do
        Keyword.put(opts, :validity_days, validity_days)
      else
        opts
      end

    opts =
      if country = params["country"] do
        Keyword.put(opts, :country, country)
      else
        opts
      end

    opts =
      if state = params["state"] do
        Keyword.put(opts, :state, state)
      else
        opts
      end

    opts =
      if locality = params["locality"] do
        Keyword.put(opts, :locality, locality)
      else
        opts
      end

    opts
  end

  defp valid_cert_type?(cert_type) do
    cert_type in ["agent_client", "app_client", "admin_client"]
  end

  @doc """
  POST /v1/pki/app/issue

  Issue a certificate for an application using a bootstrap token.

  Request body:
  ```json
  {
    "token": "hvs.CAESIJ...",
    "csr": "-----BEGIN CERTIFICATE REQUEST-----...",
    "request_id": "uuid"
  }
  ```

  Response:
  ```json
  {
    "certificate": "-----BEGIN CERTIFICATE-----...",
    "ca_chain": ["-----BEGIN CERTIFICATE-----..."],
    "serial_number": "1A:2B:3C:4D",
    "expires_at": "2025-11-27T10:00:00Z",
    "issued_at": "2025-10-27T10:00:00Z",
    "replayed": false
  }
  ```
  """
  def issue_app_certificate(
        conn,
        %{"token" => token, "csr" => csr, "request_id" => request_id} = params
      )
      when map_size(params) == 3 and is_binary(token) and byte_size(token) > 0 and
             is_binary(csr) and byte_size(csr) > 0 and is_binary(request_id) and
             byte_size(request_id) > 0 do
    result = AppCertificates.issue_from_bootstrap(token, csr, request_id)
    respond_to_app_certificate_issuance(conn, result)
  end

  def issue_app_certificate(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "INVALID_REQUEST"})
  end

  @doc """
  POST /v1/pki/app/renew

  Renew an application certificate using a current-key possession proof.

  Request body:
  ```json
  {
    "app_id": "uuid",
    "current_fingerprint": "lowercase DER SHA-256 hex",
    "csr": "base64 PEM bytes",
    "request_id": "uuid",
    "signature_algorithm": "rsa-pss-sha256",
    "proof": "base64 signature bytes"
  }
  ```
  """
  def renew_app_certificate(
        conn,
        %{
          "app_id" => app_id,
          "current_fingerprint" => current_fingerprint,
          "csr" => encoded_csr,
          "request_id" => request_id,
          "signature_algorithm" => signature_algorithm
        } = params
      )
      when map_size(params) == 5 and is_binary(app_id) and
             is_binary(current_fingerprint) and is_binary(encoded_csr) and
             is_binary(request_id) and is_binary(signature_algorithm) do
    app_certificate_renewal_error(conn, :unauthorized, "PROOF_REQUIRED")
  end

  def renew_app_certificate(
        conn,
        %{
          "app_id" => app_id,
          "current_fingerprint" => current_fingerprint,
          "csr" => encoded_csr,
          "request_id" => request_id,
          "signature_algorithm" => signature_algorithm,
          "proof" => proof
        } = params
      )
      when map_size(params) == 6 and is_binary(app_id) and
             is_binary(current_fingerprint) and is_binary(encoded_csr) and
             is_binary(request_id) and is_binary(signature_algorithm) and
             (not is_binary(proof) or byte_size(proof) == 0) do
    app_certificate_renewal_error(conn, :unauthorized, "PROOF_REQUIRED")
  end

  def renew_app_certificate(
        conn,
        %{
          "app_id" => app_id,
          "current_fingerprint" => current_fingerprint,
          "csr" => encoded_csr,
          "request_id" => request_id,
          "signature_algorithm" => signature_algorithm,
          "proof" => encoded_proof
        } = params
      )
      when map_size(params) == 6 and is_binary(app_id) and byte_size(app_id) > 0 and
             is_binary(current_fingerprint) and byte_size(current_fingerprint) > 0 and
             is_binary(encoded_csr) and byte_size(encoded_csr) > 0 and
             is_binary(request_id) and byte_size(request_id) > 0 and
             is_binary(signature_algorithm) and byte_size(signature_algorithm) > 0 and
             is_binary(encoded_proof) and byte_size(encoded_proof) > 0 do
    with {:ok, csr} <- decode_padded_base64(encoded_csr),
         {:ok, proof} <- decode_padded_base64(encoded_proof) do
      AppCertificates.renew(%{
        app_id: app_id,
        current_fingerprint: current_fingerprint,
        csr: csr,
        request_id: request_id,
        signature_algorithm: signature_algorithm,
        proof: proof
      })
      |> then(&respond_to_app_certificate_renewal(conn, &1))
    else
      :error -> app_certificate_renewal_error(conn, :bad_request, "INVALID_REQUEST")
    end
  end

  def renew_app_certificate(conn, _params) do
    app_certificate_renewal_error(conn, :bad_request, "INVALID_REQUEST")
  end

  @doc """
  POST /v1/pki/app/revoke

  Revoke an application certificate.

  Request body:
  ```json
  {
    "app_id": "uuid",
    "reason": "operator_revoked"
  }
  ```
  """
  def revoke_app_certificate(conn, %{"app_id" => app_id} = params)
      when map_size(params) == 1 and is_binary(app_id) and byte_size(app_id) > 0 do
    perform_app_certificate_revocation(conn, app_id, "operator_revoked")
  end

  def revoke_app_certificate(
        conn,
        %{"app_id" => app_id, "reason" => reason} = params
      )
      when map_size(params) == 2 and is_binary(app_id) and byte_size(app_id) > 0 and
             reason in @app_certificate_revocation_reasons do
    perform_app_certificate_revocation(conn, app_id, reason)
  end

  def revoke_app_certificate(
        conn,
        %{"app_id" => app_id, "reason" => _reason} = params
      )
      when map_size(params) == 2 and is_binary(app_id) and byte_size(app_id) > 0 do
    app_certificate_revocation_error(conn, :bad_request, "INVALID_REVOCATION_REASON")
  end

  def revoke_app_certificate(conn, _params) do
    app_certificate_revocation_error(conn, :bad_request, "INVALID_REQUEST")
  end

  defp perform_app_certificate_revocation(conn, app_id, reason) do
    case Apps.revoke_all_app_certificates(app_id, reason) do
      {:ok, count} ->
        json(conn, %{
          message: "Application certificates revoked",
          revoked_count: count
        })

      {:error, :not_found} ->
        app_certificate_revocation_error(conn, :not_found, "APPLICATION_NOT_FOUND")

      {:error, :invalid_reason} ->
        app_certificate_revocation_error(conn, :bad_request, "INVALID_REVOCATION_REASON")

      {:error, _reason} ->
        app_certificate_revocation_error(conn, :internal_server_error, "REVOCATION_FAILED")
    end
  end

  defp app_certificate_revocation_error(conn, status, error) do
    conn
    |> put_status(status)
    |> json(%{error: error})
  end

  # Private helper functions for app certificate endpoints

  defp respond_to_app_certificate_issuance(
         conn,
         {:ok,
          %{
            certificate: certificate,
            ca_chain: ca_chain,
            cert_record: cert_record,
            replayed: replayed
          }}
       ) do
    json(conn, %{
      certificate: certificate,
      ca_chain: ca_chain,
      serial_number: cert_record.serial_number,
      expires_at: cert_record.valid_until,
      issued_at: cert_record.valid_from,
      replayed: replayed
    })
  end

  defp respond_to_app_certificate_issuance(conn, {:error, :invalid_request_id}) do
    app_certificate_issuance_error(conn, :bad_request, "INVALID_REQUEST_ID")
  end

  defp respond_to_app_certificate_issuance(conn, {:error, :invalid_token}) do
    app_certificate_issuance_error(conn, :unauthorized, "INVALID_TOKEN")
  end

  defp respond_to_app_certificate_issuance(conn, {:error, :idempotency_conflict}) do
    app_certificate_issuance_error(conn, :conflict, "IDEMPOTENCY_CONFLICT")
  end

  defp respond_to_app_certificate_issuance(conn, {:error, :invalid_csr}) do
    app_certificate_issuance_error(conn, :bad_request, "INVALID_CSR")
  end

  defp respond_to_app_certificate_issuance(conn, {:error, :unsupported_key}) do
    app_certificate_issuance_error(conn, :bad_request, "UNSUPPORTED_KEY")
  end

  defp respond_to_app_certificate_issuance(conn, {:error, :invalid_agent_assignment}) do
    app_certificate_issuance_error(conn, :forbidden, "INVALID_AGENT_ASSIGNMENT")
  end

  defp respond_to_app_certificate_issuance(conn, {:error, :ca_unavailable}) do
    app_certificate_issuance_error(conn, :service_unavailable, "ISSUANCE_FAILED")
  end

  defp respond_to_app_certificate_issuance(conn, {:error, _reason}) do
    app_certificate_issuance_error(conn, :internal_server_error, "ISSUANCE_FAILED")
  end

  defp app_certificate_issuance_error(conn, status, error) do
    conn
    |> put_status(status)
    |> json(%{error: error})
  end

  defp respond_to_app_certificate_renewal(
         conn,
         {:ok,
          %{
            certificate: certificate,
            ca_chain: ca_chain,
            cert_record: cert_record,
            replayed: replayed
          }}
       ) do
    json(conn, %{
      certificate: certificate,
      ca_chain: ca_chain,
      serial_number: cert_record.serial_number,
      expires_at: cert_record.valid_until,
      issued_at: cert_record.valid_from,
      replayed: replayed
    })
  end

  defp respond_to_app_certificate_renewal(conn, {:error, :invalid_request}) do
    app_certificate_renewal_error(conn, :bad_request, "INVALID_REQUEST")
  end

  defp respond_to_app_certificate_renewal(conn, {:error, :invalid_app_id}) do
    app_certificate_renewal_error(conn, :bad_request, "INVALID_REQUEST")
  end

  defp respond_to_app_certificate_renewal(conn, {:error, :invalid_fingerprint}) do
    app_certificate_renewal_error(conn, :unauthorized, "INVALID_CERTIFICATE")
  end

  defp respond_to_app_certificate_renewal(conn, {:error, :invalid_request_id}) do
    app_certificate_renewal_error(conn, :bad_request, "INVALID_REQUEST_ID")
  end

  defp respond_to_app_certificate_renewal(conn, {:error, :unsupported_algorithm}) do
    app_certificate_renewal_error(conn, :unauthorized, "PROOF_FAILED")
  end

  defp respond_to_app_certificate_renewal(conn, {:error, :invalid_csr}) do
    app_certificate_renewal_error(conn, :bad_request, "INVALID_CSR")
  end

  defp respond_to_app_certificate_renewal(conn, {:error, :unsupported_key}) do
    app_certificate_renewal_error(conn, :bad_request, "UNSUPPORTED_KEY")
  end

  defp respond_to_app_certificate_renewal(conn, {:error, :invalid_proof}) do
    app_certificate_renewal_error(conn, :unauthorized, "PROOF_FAILED")
  end

  defp respond_to_app_certificate_renewal(conn, {:error, :invalid_current_certificate}) do
    app_certificate_renewal_error(conn, :unauthorized, "INVALID_CERTIFICATE")
  end

  defp respond_to_app_certificate_renewal(conn, {:error, :invalid_agent_assignment}) do
    app_certificate_renewal_error(conn, :forbidden, "FORBIDDEN")
  end

  defp respond_to_app_certificate_renewal(conn, {:error, :idempotency_conflict}) do
    app_certificate_renewal_error(conn, :conflict, "IDEMPOTENCY_CONFLICT")
  end

  defp respond_to_app_certificate_renewal(conn, {:error, :ca_unavailable}) do
    app_certificate_renewal_error(conn, :service_unavailable, "UNAVAILABLE")
  end

  defp respond_to_app_certificate_renewal(conn, {:error, _reason}) do
    app_certificate_renewal_error(conn, :internal_server_error, "UNAVAILABLE")
  end

  defp app_certificate_renewal_error(conn, status, error) do
    conn
    |> put_status(status)
    |> json(%{error: error})
  end

  defp decode_padded_base64(value) when is_binary(value) do
    case Base.decode64(value) do
      {:ok, decoded} when byte_size(decoded) > 0 ->
        if Base.encode64(decoded) == value, do: {:ok, decoded}, else: :error

      _other ->
        :error
    end
  end
end
