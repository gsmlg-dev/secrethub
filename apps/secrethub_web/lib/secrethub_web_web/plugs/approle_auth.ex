defmodule SecretHub.WebWeb.Plugs.AppRoleAuth do
  @moduledoc """
  Authentication plug for AppRole management endpoints.

  Requires either:
  1. Valid admin session (for web UI)
  2. Valid AppRole token with admin privileges (for API)

  This prevents unauthorized creation/deletion of AppRole roles.
  """

  import Plug.Conn
  require Logger

  def init(opts), do: opts

  def call(conn, _opts) do
    cond do
      # Check for admin session (web UI)
      has_admin_session?(conn) ->
        conn

      # Check for AppRole token with admin privileges (API)
      has_admin_token?(conn) ->
        conn

      # No valid authentication
      true ->
        Logger.warning("Unauthorized AppRole management attempt",
          path: conn.request_path,
          method: conn.method,
          ip: get_client_ip(conn)
        )

        # Log unauthorized attempt
        SecretHub.Core.Audit.log_event(%{
          event_type: "approle.unauthorized_access",
          actor_type: "unknown",
          actor_id: "unknown",
          access_granted: false,
          denial_reason: "Missing authentication",
          source_ip: get_client_ip(conn),
          event_data: %{
            path: conn.request_path,
            method: conn.method
          }
        })

        conn
        |> put_status(:unauthorized)
        |> Phoenix.Controller.json(%{error: "Authentication required for AppRole management"})
        |> halt()
    end
  end

  defp has_admin_session?(conn) do
    admin_authenticated = Plug.Conn.get_session(conn, :admin_authenticated)
    login_at = Plug.Conn.get_session(conn, :admin_login_at)

    admin_authenticated && !session_expired?(login_at)
  end

  defp has_admin_token?(conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> token] ->
        verify_admin_token(token)

      _ ->
        false
    end
  end

  defp verify_admin_token(token) do
    # Verify the token is valid and has admin privileges
    # This would check against the AppRole tokens table
    case SecretHub.Core.Auth.AppRole.verify_token(token) do
      {:ok, role} ->
        # Check if the role has admin privileges
        role.role_name == "admin" || has_admin_policy?(role)

      {:error, _} ->
        false
    end
  rescue
    _ -> false
  end

  defp has_admin_policy?(_role) do
    # TODO: Implement policy-based admin check
    # For now, only allow "admin" role name
    false
  end

  defp session_expired?(nil), do: true

  defp session_expired?(login_at_str) when is_binary(login_at_str) do
    case DateTime.from_iso8601(login_at_str) do
      {:ok, login_at, _offset} ->
        now = DateTime.utc_now()
        timeout_seconds = 30 * 60  # 30 minutes

        DateTime.diff(now, login_at, :second) > timeout_seconds

      _ ->
        true
    end
  end

  defp session_expired?(_), do: true

  defp get_client_ip(conn) do
    case get_req_header(conn, "x-forwarded-for") do
      [ip | _] ->
        ip |> String.split(",") |> List.first() |> String.trim()

      _ ->
        case conn.remote_ip do
          {a, b, c, d} -> "#{a}.#{b}.#{c}.#{d}"
          {a, b, c, d, e, f, g, h} -> Enum.join([a, b, c, d, e, f, g, h], ":")
          _ -> "unknown"
        end
    end
  end
end
