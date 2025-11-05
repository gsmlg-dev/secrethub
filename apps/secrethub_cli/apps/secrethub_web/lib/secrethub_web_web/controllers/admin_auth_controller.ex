defmodule SecretHub.WebWeb.AdminAuthController do
  use SecretHub.WebWeb, :controller

  @moduledoc """
  Admin authentication controller for SecretHub web interface.

  Provides session-based authentication for admin users with:
  - Password-based login
  - Session management with timeout  
  - CSRF protection
  - Secure session cookies
  """

  require Logger

  @session_timeout_minutes 30

  @doc """
  Health check endpoint (public, no auth required).
  """
  def health_check(conn, _params) do
    json(conn, %{status: "healthy", timestamp: DateTime.utc_now()})
  end

  @doc """
  Plug function to require admin authentication.

  Checks:
  1. Session is authenticated
  2. Session is not expired

  If any check fails, returns 401 Unauthorized.
  """
  def require_admin_auth(conn, _opts) do
    authenticated = get_session(conn, :admin_authenticated)
    login_at_str = get_session(conn, :admin_login_at)
    username = get_session(conn, :admin_username)

    cond do
      # Not authenticated
      not authenticated ->
        conn
        |> put_status(:unauthorized)
        |> json(%{error: "Authentication required"})
        |> halt()

      # Session expired
      session_expired?(login_at_str) ->
        Logger.warning("Admin session expired", username: username)

        conn
        |> configure_session(drop: true)
        |> put_status(:unauthorized)
        |> json(%{error: "Session expired"})
        |> halt()

      # All checks passed
      true ->
        # Update last activity time
        conn
        |> put_session(:admin_last_activity, DateTime.utc_now() |> DateTime.to_iso8601())
        |> assign(:current_admin_user, username)
    end
  end

  ## Private Functions

  defp session_expired?(nil), do: true

  defp session_expired?(login_at_str) when is_binary(login_at_str) do
    case DateTime.from_iso8601(login_at_str) do
      {:ok, login_at, _offset} ->
        now = DateTime.utc_now()
        timeout_seconds = @session_timeout_minutes * 60
        DateTime.diff(now, login_at, :second) > timeout_seconds

      _ ->
        true
    end
  end

  defp session_expired?(_), do: true
end
