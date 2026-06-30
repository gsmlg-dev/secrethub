defmodule SecretHub.Web.CliAccessController do
  @moduledoc """
  API endpoints for browser-approved CLI login.
  """

  use SecretHub.Web, :controller

  alias SecretHub.Core.Auth.CliAccess

  def create(conn, params) do
    case CliAccess.create_request(params, get_client_ip(conn)) do
      {:ok, request} ->
        conn
        |> put_status(:created)
        |> json(%{
          request_id: request.request_id,
          user_code: request.user_code,
          status: "pending",
          interval: CliAccess.poll_interval_seconds(),
          expires_at: DateTime.to_iso8601(request.expires_at)
        })

      {:error, reason} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: inspect(reason)})
    end
  end

  def poll(conn, %{"request_id" => request_id}) do
    case CliAccess.poll_request(request_id) do
      {:pending, request} ->
        conn
        |> put_status(:accepted)
        |> json(%{
          status: "pending",
          user_code: request.user_code,
          interval: CliAccess.poll_interval_seconds(),
          expires_at: DateTime.to_iso8601(request.expires_at)
        })

      {:approved, %{token: token, policies: policies, role_name: role_name, ttl: ttl}} ->
        render_approle_token(conn, token, role_name, policies, ttl)

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "CLI access request not found"})

      {:error, :expired} ->
        conn
        |> put_status(:gone)
        |> json(%{error: "CLI access request expired"})

      {:error, :rejected} ->
        conn
        |> put_status(:forbidden)
        |> json(%{error: "CLI access request rejected"})

      {:error, :already_consumed} ->
        conn
        |> put_status(:gone)
        |> json(%{error: "CLI access token already delivered"})

      {:error, reason} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: inspect(reason)})
    end
  end

  defp render_approle_token(conn, token, role_name, policies, ttl) do
    conn
    |> put_status(:ok)
    |> json(%{
      token: token,
      token_type: "approle",
      role_name: role_name,
      policies: policies,
      ttl: ttl,
      auth: %{
        client_token: token,
        lease_duration: ttl,
        token_type: "bearer",
        policies: policies,
        metadata: %{role_name: role_name}
      }
    })
  end

  defp get_client_ip(conn) do
    case get_req_header(conn, "x-forwarded-for") do
      [ip | _] ->
        ip |> String.split(",") |> List.first() |> String.trim()

      _ ->
        conn.remote_ip
        |> :inet.ntoa()
        |> to_string()
    end
  rescue
    _ -> "unknown"
  end
end
