defmodule SecretHub.CLI.Auth do
  @moduledoc """
  Authentication handling for the SecretHub CLI.

  Manages AppRole authentication and token storage.
  """

  alias SecretHub.CLI.{Config, Output}

  @doc """
  Authenticates with the SecretHub server using AppRole credentials.

  ## Parameters

  - `role_id` - The AppRole RoleID
  - `secret_id` - The AppRole SecretID
  - `server_url` - Optional server URL (uses config if not provided)

  ## Returns

  - `{:ok, token}` - Authentication successful
  - `{:error, reason}` - Authentication failed
  """
  def login(role_id, secret_id, server_url \\ nil) do
    server = server_url || Config.get_server_url()

    with {:ok, response} <- request_token(server, role_id, secret_id),
         :ok <- save_token(response) do
      Output.success("Successfully authenticated with SecretHub")
      {:ok, "Authentication successful"}
    else
      {:error, reason} ->
        Output.error("Authentication failed: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc """
  Logs out by clearing stored credentials.
  """
  def logout do
    case Config.clear_auth() do
      :ok ->
        Output.success("Successfully logged out")
        {:ok, "Logged out"}

      {:error, reason} ->
        Output.error("Failed to logout: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc """
  Checks if the user is currently authenticated.
  """
  def authenticated? do
    case Config.get_auth_token() do
      {:ok, _token} -> true
      _ -> false
    end
  end

  @doc """
  Gets the current authentication token.

  Returns {:ok, token} or {:error, reason}.
  """
  def get_token do
    Config.get_auth_token()
  end

  @doc """
  Ensures the user is authenticated, prompting if necessary.
  """
  def ensure_authenticated do
    case get_token() do
      {:ok, token} ->
        {:ok, token}

      {:error, :expired} ->
        Output.error("Authentication token has expired. Please login again.")
        {:error, :not_authenticated}

      {:error, :not_found} ->
        Output.error("Not authenticated. Please run 'secrethub login' first.")
        {:error, :not_authenticated}
    end
  end

  @doc """
  Returns authentication headers for API requests.
  """
  def auth_headers do
    case get_token() do
      {:ok, token} ->
        [{"authorization", "Bearer #{token}"}]

      {:error, _} ->
        []
    end
  end

  ## Private Functions

  defp request_token(server_url, role_id, secret_id) do
    url = "#{server_url}/v1/auth/approle/login"

    body =
      Jason.encode!(%{
        role_id: role_id,
        secret_id: secret_id
      })

    headers = [{"content-type", "application/json"}]

    case Req.post(url, body: body, headers: headers) do
      {:ok, %{status: 200, body: body}} ->
        parse_token_response(body)

      {:ok, %{status: status, body: body}} ->
        {:error, "Authentication failed with status #{status}: #{inspect(body)}"}

      {:error, reason} ->
        {:error, "HTTP request failed: #{inspect(reason)}"}
    end
  end

  defp parse_token_response(body) when is_map(body) do
    case Map.get(body, "auth") || Map.get(body, "data") do
      %{"client_token" => token, "lease_duration" => ttl} ->
        expires_at = DateTime.add(DateTime.utc_now(), ttl, :second)
        {:ok, %{token: token, expires_at: expires_at}}

      %{"token" => token, "ttl" => ttl} ->
        expires_at = DateTime.add(DateTime.utc_now(), ttl, :second)
        {:ok, %{token: token, expires_at: expires_at}}

      %{"token" => token} ->
        # Default to 24 hour expiration if not specified
        expires_at = DateTime.add(DateTime.utc_now(), 86_400, :second)
        {:ok, %{token: token, expires_at: expires_at}}

      _ ->
        {:error, "Invalid token response format"}
    end
  end

  defp parse_token_response(_), do: {:error, "Invalid response body"}

  defp save_token(%{token: token, expires_at: expires_at}) do
    Config.save_auth(token, expires_at)
  end
end
