defmodule SecretHub.Web.AdminAuthController do
  @moduledoc """
  Handles admin authentication for SecretHub.

  This controller implements certificate-based authentication
  for accessing the admin interface. It validates client certificates
  against known administrators and manages sessions.
  """

  use SecretHub.Web, :controller
  require Logger

  @doc """
  Plug to require admin authentication.
  """
  def require_admin_auth(conn, _opts) do
    # First check if already authenticated via session
    case get_session(conn, :admin_id) do
      nil ->
        # No session, try certificate authentication
        authenticate_with_certificate(conn)

      _admin_id ->
        # Already authenticated via session
        conn
    end
  end

  defp authenticate_with_certificate(conn) do
    case get_client_certificate(conn) do
      nil ->
        # No certificate - redirect to login page for browser requests
        conn
        |> put_flash(:error, "Please log in to access the admin area")
        |> redirect(to: "/admin/auth/login")
        |> halt()

      cert ->
        case verify_admin_certificate(cert) do
          {:ok, admin_id} ->
            conn
            |> put_session(:admin_id, admin_id)
            |> configure_session_timeout()

          {:error, reason} ->
            Logger.warning("Admin auth failed: #{reason}")

            conn
            |> put_flash(:error, "Authentication failed: #{reason}")
            |> redirect(to: "/admin/auth/login")
            |> halt()
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
  Handle admin login with certificate validation or dev password.
  """
  def login(conn, params) do
    cond do
      # Development mode: allow password-based login
      Mix.env() == :dev and params["dev_password"] == dev_password() ->
        conn
        |> put_session(:admin_id, "dev-admin")
        |> configure_session_timeout()
        |> put_flash(:info, "Development login successful")
        |> redirect(to: "/admin/dashboard")

      # Development mode: wrong password
      Mix.env() == :dev and params["dev_password"] != nil ->
        conn
        |> put_flash(:error, "Invalid development password")
        |> redirect(to: "/admin/auth/login")

      # Production/certificate mode
      true ->
        case get_client_certificate(conn) do
          nil ->
            conn
            |> put_flash(:error, "No client certificate provided")
            |> redirect(to: "/admin/auth/login")

          cert ->
            case verify_admin_certificate(cert) do
              {:ok, admin_id} ->
                conn
                |> put_session(:admin_id, admin_id)
                |> configure_session_timeout()
                |> put_flash(:info, "Successfully logged in")
                |> redirect(to: "/admin/dashboard")

              {:error, reason} ->
                conn
                |> put_flash(:error, "Authentication failed: #{reason}")
                |> redirect(to: "/admin/auth/login")
            end
        end
    end
  end

  defp dev_password do
    # Simple dev password - NOT for production use
    Application.get_env(:secrethub_web, :dev_admin_password, "secrethub_dev")
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
    with nil <- get_cert_from_header(conn),
         nil <- get_cert_from_chain(conn) do
      get_cert_from_auth_token(conn)
    end
  end

  defp get_cert_from_header(conn) do
    case get_req_header(conn, "x-ssl-client-cert") do
      [pem] -> SecretHub.Shared.Schemas.Certificate.from_pem(pem)
      _ -> nil
    end
  end

  defp get_cert_from_chain(conn) do
    case get_req_header(conn, "x-ssl-client-cert-chain") do
      [chain] -> extract_cert_from_chain(chain)
      _ -> nil
    end
  end

  defp get_cert_from_auth_token(conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> _dev_token] ->
        Logger.info("Using dev token for admin authentication")
        dev_admin_id()

      _ ->
        nil
    end
  end

  defp extract_cert_from_chain(chain) do
    case String.split(chain, "\n") do
      [first_line | _] ->
        first_line
        |> String.trim_leading("-----BEGIN CERTIFICATE-----")
        |> String.trim_trailing("-----END CERTIFICATE-----")
        |> String.replace("\r\n", "\n")
        |> then(&SecretHub.Shared.Schemas.Certificate.from_pem/1)

      _ ->
        nil
    end
  end

  defp verify_admin_certificate(cert) do
    if Mix.env() == :dev do
      verify_dev_certificate(cert)
    else
      verify_prod_certificate(cert)
    end
  end

  defp verify_dev_certificate(cert) do
    subject = cert.subject

    if String.contains?(subject, "admin") do
      {:ok, String.split(subject, "@") |> List.first()}
    else
      {:error, "Invalid certificate for development"}
    end
  end

  defp verify_prod_certificate(cert) do
    expected_fingerprints = Application.get_env(:secrethub_web, :ADMIN_CERT_FINGERPRINTS, "")

    case expected_fingerprints do
      nil ->
        {:error, "No admin certificates configured"}

      fingerprints when is_list(fingerprints) ->
        check_fingerprint_match(cert, fingerprints)

      _ ->
        {:error, "Invalid certificate configuration"}
    end
  end

  defp check_fingerprint_match(cert, fingerprints) do
    cert_fingerprint = cert_fingerprint(cert)

    if cert_fingerprint in fingerprints do
      {:ok, String.split(cert.subject, "@") |> List.first()}
    else
      {:error, "Certificate not authorized"}
    end
  end

  defp cert_fingerprint(cert) do
    # Return fingerprint from certificate struct
    # Note: Certificate.from_pem/1 is not yet implemented, so this is placeholder code
    cert.fingerprint || ""
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
