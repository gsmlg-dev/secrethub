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

  alias SecretHub.Core.{Apps, PKI.CA, Repo}
  alias SecretHub.Shared.Schemas.Certificate

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

      {:error, changeset} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{
          error: "Failed to revoke certificate",
          details: inspect(changeset.errors)
        })
    end
  end

  defp fetch_certificate(id) do
    case Repo.get(Certificate, id) do
      nil -> {:error, :not_found}
      cert -> {:ok, cert}
    end
  end

  defp check_not_revoked(%{revoked: true}), do: {:error, :already_revoked}
  defp check_not_revoked(_cert), do: :ok

  defp do_revoke_certificate(cert, reason) do
    changeset =
      Certificate.changeset(cert, %{
        revoked: true,
        revoked_at: DateTime.utc_now() |> DateTime.truncate(:second),
        revocation_reason: reason
      })

    case Repo.update(changeset) do
      {:ok, updated_cert} -> {:ok, updated_cert}
      {:error, _} = error -> error
    end
  end

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
    "app_id": "uuid",
    "app_token": "hvs.CAESIJ...",
    "csr": "-----BEGIN CERTIFICATE REQUEST-----...",
    "ttl": 2592000,
    "metadata": {
      "hostname": "prod-payment-01",
      "environment": "production",
      "version": "v1.2.3"
    }
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
    "ttl": 2592000
  }
  ```
  """
  def issue_app_certificate(
        conn,
        %{
          "app_id" => app_id,
          "app_token" => app_token,
          "csr" => csr_pem
        } = params
      ) do
    Logger.info("App certificate issuance requested", app_id: app_id)

    with {:ok, validated_app_id} <- Apps.validate_bootstrap_token(app_token),
         :ok <- verify_app_id_match(app_id, validated_app_id),
         {:ok, app} <- Apps.get_app(app_id),
         {:ok, intermediate_ca} <- get_intermediate_ca(),
         ttl <- Map.get(params, "ttl", 2_592_000),
         validity_days <- div(ttl, 86400),
         {:ok, %{certificate: cert_pem, cert_record: cert_record}} <-
           CA.sign_csr(csr_pem, intermediate_ca.id, :app_client, validity_days: validity_days),
         {:ok, _app_cert} <-
           Apps.associate_certificate(app.id, cert_record.id, cert_record.valid_until),
         {:ok, ca_chain} <- CA.get_ca_chain() do
      Logger.info("App certificate issued successfully",
        app_id: app.id,
        certificate_id: cert_record.id
      )

      conn
      |> put_status(:ok)
      |> json(%{
        certificate: cert_pem,
        ca_chain: String.split(ca_chain, "\n\n", trim: true),
        serial_number: cert_record.serial_number,
        expires_at: cert_record.valid_until,
        issued_at: cert_record.valid_from,
        ttl: ttl
      })
    else
      {:error, :invalid_token} ->
        conn
        |> put_status(:unauthorized)
        |> json(%{error: "Invalid or expired bootstrap token"})

      {:error, :app_id_mismatch} ->
        conn
        |> put_status(:forbidden)
        |> json(%{error: "App ID does not match token"})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Application not found"})

      {:error, reason} ->
        Logger.error("Failed to issue app certificate", reason: inspect(reason))

        conn
        |> put_status(:internal_server_error)
        |> json(%{error: "Certificate issuance failed"})
    end
  end

  @doc """
  POST /v1/pki/app/renew

  Renew an application certificate.

  Request body:
  ```json
  {
    "app_id": "uuid",
    "current_cert": "-----BEGIN CERTIFICATE-----...",
    "csr": "-----BEGIN CERTIFICATE REQUEST-----...",
    "ttl": 2592000
  }
  ```
  """
  def renew_app_certificate(
        conn,
        %{
          "app_id" => app_id,
          "current_cert" => current_cert_pem,
          "csr" => csr_pem
        } = params
      ) do
    Logger.info("App certificate renewal requested", app_id: app_id)

    with {:ok, app} <- Apps.get_app(app_id),
         :ok <- verify_current_certificate(current_cert_pem, app_id),
         {:ok, intermediate_ca} <- get_intermediate_ca(),
         ttl <- Map.get(params, "ttl", 2_592_000),
         validity_days <- div(ttl, 86400),
         {:ok, %{certificate: cert_pem, cert_record: cert_record}} <-
           CA.sign_csr(csr_pem, intermediate_ca.id, :app_client, validity_days: validity_days),
         {:ok, _app_cert} <-
           Apps.associate_certificate(app.id, cert_record.id, cert_record.valid_until),
         {:ok, ca_chain} <- CA.get_ca_chain() do
      Logger.info("App certificate renewed successfully",
        app_id: app.id,
        certificate_id: cert_record.id
      )

      conn
      |> put_status(:ok)
      |> json(%{
        certificate: cert_pem,
        ca_chain: String.split(ca_chain, "\n\n", trim: true),
        serial_number: cert_record.serial_number,
        expires_at: cert_record.valid_until,
        issued_at: cert_record.valid_from,
        ttl: ttl
      })
    else
      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Application not found"})

      {:error, :invalid_certificate} ->
        conn
        |> put_status(:unauthorized)
        |> json(%{error: "Invalid current certificate"})

      {:error, reason} ->
        Logger.error("Failed to renew app certificate", reason: inspect(reason))

        conn
        |> put_status(:internal_server_error)
        |> json(%{error: "Certificate renewal failed"})
    end
  end

  @doc """
  POST /v1/pki/app/revoke

  Revoke an application certificate.

  Request body:
  ```json
  {
    "app_id": "uuid",
    "reason": "key_compromise"
  }
  ```
  """
  def revoke_app_certificate(conn, %{"app_id" => app_id} = params) do
    reason = Map.get(params, "reason", "unspecified")

    Logger.info("App certificate revocation requested", app_id: app_id, reason: reason)

    with {:ok, _app} <- Apps.get_app(app_id),
         {:ok, count} <- Apps.revoke_all_app_certificates(app_id, reason) do
      Logger.info("App certificates revoked", app_id: app_id, count: count)

      conn
      |> put_status(:ok)
      |> json(%{
        message: "Application certificates revoked",
        revoked_count: count
      })
    else
      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Application not found"})

      {:error, reason} ->
        Logger.error("Failed to revoke app certificate", reason: inspect(reason))

        conn
        |> put_status(:internal_server_error)
        |> json(%{error: "Certificate revocation failed"})
    end
  end

  # Private helper functions for app certificate endpoints

  defp verify_app_id_match(provided_app_id, validated_app_id) do
    if provided_app_id == validated_app_id do
      :ok
    else
      {:error, :app_id_mismatch}
    end
  end

  defp verify_current_certificate(_current_cert_pem, _app_id) do
    # TODO: Implement certificate verification
    # 1. Parse certificate
    # 2. Verify it's not revoked
    # 3. Verify it's issued to this app_id
    # 4. Verify it's still valid
    :ok
  end

  defp get_intermediate_ca do
    # Get the intermediate CA for signing client certificates
    import Ecto.Query

    query =
      from(c in Certificate,
        where: c.cert_type == "intermediate_ca" and c.revoked == false,
        order_by: [desc: c.inserted_at],
        limit: 1
      )

    case Repo.one(query) do
      nil -> {:error, :no_intermediate_ca}
      cert -> {:ok, cert}
    end
  end
end
