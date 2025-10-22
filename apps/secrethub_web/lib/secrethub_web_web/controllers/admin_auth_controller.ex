defmodule SecretHub.WebWeb.AdminAuthController do
  @moduledoc """
  Handles admin authentication for SecretHub.

  This controller implements certificate-based authentication
  for accessing the admin interface. It validates client certificates
  against known administrators and manages sessions.
  """

  use SecretHub.WebWeb, :controller
  require Logger

  @doc """
  Plug to require admin authentication.
  """
  def require_admin_auth(conn, _opts) do
    case get_client_certificate(conn) do
      nil ->
        conn
        |> put_status(:unauthorized)
        |> put_resp_header("www-authenticate", "Certificate required")
        |> text("Certificate required for admin access")

      cert ->
        case verify_admin_certificate(cert) do
          {:ok, admin_id} ->
            conn
            |> put_session(:admin_id, admin_id)
            |> configure_session_timeout()

          {:error, reason} ->
            Logger.warning("Admin auth failed: #{reason}")
            conn
            |> put_status(:forbidden)
            |> text("Access denied: #{reason}")
        end
    end
  end

  @doc """
  Show the admin login page.
  """
  def login_form(conn, _params) do
    conn
    |> put_layout(false)
    |> render(:login)
  end

  @doc """
  Handle admin login with certificate validation.
  """
  def login(conn, _params) do
    case get_client_certificate(conn) do
      nil ->
        conn
        |> put_flash(:error, "No client certificate provided")
        |> put_layout(false)
        |> render(:login)

      cert ->
        case verify_admin_certificate(cert) do
          {:ok, admin_id} ->
            conn
            |> put_session(:admin_id, admin_id)
            |> configure_session_timeout()
            |> put_flash(:info, "Successfully logged in")
            |> redirect(to: "/admin")

          {:error, reason} ->
            conn
            |> put_flash(:error, "Authentication failed: #{reason}")
            |> put_layout(false)
            |> render(:login)
        end
    end
  end

  @doc """
  Handle admin logout.
  """
  def logout(conn, _params) do
    Logger.info("Admin logout")

    conn
    |> clear_session()
    |> configure_session_timeout()
    |> put_flash(:info, "Successfully logged out")
    |> redirect(to: "/admin/auth/login")
  end

  @doc """
  Health check endpoint for admin authentication.
  """
  def health_check(conn, _params) do
    conn
    |> put_resp_content_type("application/json")
    |> json(%{status: "ok", timestamp: DateTime.utc_now()})
  end

  # Private functions

  defp get_client_certificate(conn) do
    case get_req_header(conn, "x-ssl-client-cert") do
      [pem] ->
        Certificate.from_pem(pem)

      nil ->
        case get_req_header(conn, "x-ssl-client-cert-chain") do
          nil ->
            # For development/testing with curl
            case get_req_header(conn, "authorization") do
              ["Bearer " <> _dev_token] ->
                Logger.info("Using dev token for admin authentication")
                dev_admin_id()

              _ ->
                nil
            end

          [chain] ->
            # Try to extract certificate from chain header
            case String.split(chain, "\n") do
              [first_line | _] ->
                first_line
                |> String.trim_leading("-----BEGIN CERTIFICATE-----")
                |> String.trim_trailing("-----END CERTIFICATE-----")
                |> String.replace("\r\n", "\n")
                |> Certificate.from_pem()

              _ ->
                nil
            end

          _ ->
            nil
        end

      _ ->
        nil
    end
  end

  defp verify_admin_certificate(cert) do
    # In development, accept any certificate with "admin" CN
    if Application.compile_env(:secrethub_web) == :dev do
      subject = cert.subject
      if String.contains?(subject, "admin") do
        {:ok, String.split(subject, "@") |> List.first()}
      else
        {:error, "Invalid certificate for development"}
      end
    else
      # In production, verify against known admin fingerprints
      # This would integrate with your Certificate schema
      # For now, implement a basic check
      expected_fingerprints = Application.get_env(:secrethub_web, :ADMIN_CERT_FINGERPRINTS, "")

      case expected_fingerprints do
        nil ->
          {:error, "No admin certificates configured"}

        fingerprints when is_list(fingerprints) ->
          cert_fingerprint = cert_fingerprint(cert)
          if cert_fingerprint in fingerprints do
            {:ok, String.split(cert.subject, "@") |> List.first()}
          else
            {:error, "Certificate not authorized"}
          end

        _ ->
          {:error, "Invalid certificate configuration"}
      end
    end
  end

  defp cert_fingerprint(cert) do
    # Generate SHA-256 fingerprint of certificate
    :crypto.hash(:sha256, Certificate.public_key(cert).der)
    |> Base.encode16(case: :lower)
  end

  defp configure_session_timeout(conn) do
    # Set session timeout to 1 hour
    conn
    |> put_session(:max_age, 3600)
  end

  defp dev_admin_id do
    # Mock admin ID for development
    "dev-admin-001"
  end
end