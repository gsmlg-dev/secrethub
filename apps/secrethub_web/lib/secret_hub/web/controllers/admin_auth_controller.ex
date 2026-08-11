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
    require_admin(conn, :redirect)
  end

  @doc """
  Plug to require admin authentication for JSON APIs.
  """
  def require_admin_api_auth(conn, _opts) do
    require_admin(conn, :json)
  end

  defp require_admin(conn, failure_mode) do
    # First check if already authenticated via session
    case get_session(conn, :admin_id) do
      nil ->
        # No session, try certificate authentication
        authenticate_with_certificate(conn, failure_mode)

      _admin_id ->
        # Already authenticated via session
        conn
    end
  end

  defp authenticate_with_certificate(conn, failure_mode) do
    case get_client_certificate(conn) do
      nil ->
        reject_admin_auth(conn, failure_mode, "Please log in to access the admin area")

      cert ->
        case verify_admin_certificate(cert) do
          {:ok, admin_id} ->
            conn
            |> put_session(:admin_id, admin_id)
            |> configure_session_timeout()

          {:error, reason} ->
            Logger.warning("Admin auth failed: #{reason}")

            reject_admin_auth(conn, failure_mode, "Authentication failed: #{reason}")
        end
    end
  end

  defp reject_admin_auth(conn, :json, _message) do
    conn
    |> put_status(:unauthorized)
    |> json(%{error: "Admin authentication required"})
    |> halt()
  end

  defp reject_admin_auth(conn, :redirect, message) do
    conn
    |> put_flash(:error, message)
    |> redirect(to: "/admin/auth/login")
    |> halt()
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
    if dev_mode?() do
      handle_dev_login(conn, params)
    else
      handle_cert_login(conn)
    end
  end

  defp handle_dev_login(conn, %{"dev_password" => password}) do
    if password == dev_password() do
      conn
      |> put_session(:admin_id, "dev-admin")
      |> configure_session_timeout()
      |> put_flash(:info, "Development login successful")
      |> redirect(to: "/admin/dashboard")
    else
      conn
      |> put_flash(:error, "Invalid development password")
      |> redirect(to: "/admin/auth/login")
    end
  end

  defp handle_dev_login(conn, _params), do: handle_cert_login(conn)

  defp handle_cert_login(conn) do
    case get_client_certificate(conn) do
      nil ->
        conn
        |> put_flash(:error, "No client certificate provided")
        |> redirect(to: "/admin/auth/login")

      cert ->
        authenticate_cert_and_redirect(conn, cert)
    end
  end

  defp authenticate_cert_and_redirect(conn, cert) do
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
    |> put_flash(:info, "Successfully logged out")
    |> redirect(to: "/admin/auth/login")
  end

  @doc """
  Health check endpoint for admin authentication.
  """
  def health_check(conn, _params) do
    conn
    |> put_resp_content_type("application/json")
    |> json(%{status: "ok", timestamp: DateTime.utc_now() |> DateTime.truncate(:second)})
  end

  # Private functions

  defp get_client_certificate(%{
         assigns: %{mtls_authenticated: true, client_certificate: certificate}
       })
       when is_map(certificate),
       do: certificate

  defp get_client_certificate(_conn), do: nil

  defp verify_admin_certificate(cert) do
    if dev_mode?() do
      verify_dev_certificate(cert)
    else
      verify_prod_certificate(cert)
    end
  end

  defp verify_dev_certificate(%{subject: subject}) when is_binary(subject) do
    if String.contains?(subject, "admin") do
      {:ok, String.split(subject, "@") |> List.first()}
    else
      {:error, "Invalid certificate for development"}
    end
  end

  defp verify_dev_certificate(_cert), do: {:error, "Invalid client certificate"}

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

  defp check_fingerprint_match(%{subject: subject} = cert, fingerprints)
       when is_binary(subject) do
    cert_fingerprint = cert_fingerprint(cert)

    if cert_fingerprint in fingerprints do
      {:ok, String.split(subject, "@") |> List.first()}
    else
      {:error, "Certificate not authorized"}
    end
  end

  defp check_fingerprint_match(_cert, _fingerprints), do: {:error, "Invalid client certificate"}

  defp cert_fingerprint(%{fingerprint: fingerprint}) when is_binary(fingerprint), do: fingerprint
  defp cert_fingerprint(_cert), do: ""

  defp configure_session_timeout(conn) do
    # Set session timeout to 1 hour
    conn
    |> put_session(:admin_authenticated, true)
    |> put_session(
      :admin_login_at,
      DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_iso8601()
    )
    |> put_session(:max_age, 3600)
  end

  defp dev_mode? do
    Application.get_env(:secrethub_web, :dev_mode, false)
  end
end
