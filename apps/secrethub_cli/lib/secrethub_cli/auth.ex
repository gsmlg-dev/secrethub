defmodule SecretHub.CLI.Auth do
  @moduledoc """
  Authentication handling for the SecretHub CLI.

  Manages AppRole authentication and token storage.
  """

  alias SecretHub.CLI.{Config, Output}

  @default_cli_access_poll_interval_ms 2_000
  @default_cli_access_max_attempts 300

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
  Authenticates by creating a CLI access request and waiting for admin approval.
  """
  def login_with_cli_access(server_url \\ nil, opts \\ []) do
    server = server_url || Config.get_server_url()

    with {:ok, request} <- cli_access_requester().(server, cli_access_metadata()) do
      Output.info("CLI Access Code: #{request.user_code}")
      Output.info("Approve this login in Admin > Access Control > CLI Access.")
      Output.info("Waiting for approval...")

      poll_interval_ms =
        Keyword.get(opts, :poll_interval_ms, request_interval_ms(request))

      max_attempts = Keyword.get(opts, :max_attempts, @default_cli_access_max_attempts)

      case poll_cli_access(server, request.request_id, poll_interval_ms, max_attempts) do
        {:ok, response} ->
          :ok = save_token(response)
          Output.success("Successfully authenticated with SecretHub")
          {:ok, "Authentication successful"}

        {:error, reason} ->
          Output.error("CLI access login failed: #{inspect(reason)}")
          {:error, reason}
      end
    else
      {:error, reason} ->
        Output.error("CLI access request failed: #{inspect(reason)}")
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
        case renew_current_token() do
          {:ok, token} ->
            {:ok, token}

          {:error, _reason} ->
            Output.error("Authentication token has expired. Please login again.")
            {:error, :not_authenticated}
        end

      {:error, :not_found} ->
        Output.error("Not authenticated. Please run 'secrethub login' first.")
        {:error, :not_authenticated}
    end
  end

  @doc """
  Renews the current authentication token.
  """
  def renew do
    case renew_current_token() do
      {:ok, _token} ->
        Output.success("Authentication token renewed")
        {:ok, "Authentication token renewed"}

      {:error, :not_found} ->
        Output.error("Not authenticated. Please run 'secrethub login' first.")
        {:error, :not_authenticated}

      {:error, reason} ->
        Output.error("Failed to renew authentication token: #{inspect(reason)}")
        {:error, reason}
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

  @doc """
  Returns Vault-compatible authentication headers for secret API requests.
  """
  def vault_headers do
    case get_token() do
      {:ok, token} ->
        [{"x-vault-token", token}]

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

  defp request_token_renewal(server_url, token) do
    url = "#{server_url}/v1/auth/approle/renew"
    headers = [{"x-vault-token", token}, {"content-type", "application/json"}]

    case Req.post(url, body: Jason.encode!(%{}), headers: headers) do
      {:ok, %{status: 200, body: body}} ->
        parse_token_response(body)

      {:ok, %{status: status, body: body}} ->
        {:error, "Token renewal failed with status #{status}: #{inspect(body)}"}

      {:error, reason} ->
        {:error, "HTTP request failed: #{inspect(reason)}"}
    end
  rescue
    error ->
      {:error, "HTTP request failed: #{Exception.message(error)}"}
  end

  defp request_cli_access(server_url, metadata) do
    url = "#{server_url}/v1/auth/cli-access"
    headers = [{"content-type", "application/json"}]

    case Req.post(url, body: Jason.encode!(metadata), headers: headers) do
      {:ok, %{status: 201, body: body}} ->
        parse_cli_access_request(body)

      {:ok, %{status: status, body: body}} ->
        {:error, "CLI access request failed with status #{status}: #{inspect(body)}"}

      {:error, reason} ->
        {:error, "HTTP request failed: #{inspect(reason)}"}
    end
  rescue
    error ->
      {:error, "HTTP request failed: #{Exception.message(error)}"}
  end

  defp poll_cli_access_request(server_url, request_id) do
    url = "#{server_url}/v1/auth/cli-access/#{request_id}"

    case Req.get(url) do
      {:ok, %{status: 200, body: body}} ->
        with {:ok, response} <- parse_token_response(body) do
          {:approved, response}
        end

      {:ok, %{status: 202, body: body}} ->
        {:pending, Map.get(body, "interval") || Map.get(body, :interval)}

      {:ok, %{status: status, body: body}} ->
        {:error, "CLI access poll failed with status #{status}: #{inspect(body)}"}

      {:error, reason} ->
        {:error, "HTTP request failed: #{inspect(reason)}"}
    end
  rescue
    error ->
      {:error, "HTTP request failed: #{Exception.message(error)}"}
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

  defp renew_current_token do
    with {:ok, token} <- Config.get_stored_auth_token(),
         {:ok, response} <- token_renewer().(Config.get_server_url(), token),
         :ok <- save_token(response) do
      {:ok, response.token}
    end
  end

  defp token_renewer do
    Application.get_env(:secrethub_cli, :token_renewer, &request_token_renewal/2)
  end

  defp cli_access_requester do
    Application.get_env(:secrethub_cli, :cli_access_requester, &request_cli_access/2)
  end

  defp cli_access_poller do
    Application.get_env(:secrethub_cli, :cli_access_poller, &poll_cli_access_request/2)
  end

  defp poll_cli_access(_server, _request_id, _poll_interval_ms, 0), do: {:error, :timeout}

  defp poll_cli_access(server, request_id, poll_interval_ms, attempts_left) do
    case cli_access_poller().(server, request_id) do
      {:approved, response} ->
        {:ok, response}

      {:pending, next_interval_seconds} ->
        sleep_ms = next_poll_interval_ms(next_interval_seconds, poll_interval_ms)
        if sleep_ms > 0, do: Process.sleep(sleep_ms)
        poll_cli_access(server, request_id, poll_interval_ms, attempts_left - 1)

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp parse_cli_access_request(body) when is_map(body) do
    with {:ok, request_id} <- fetch_response_value(body, :request_id),
         {:ok, user_code} <- fetch_response_value(body, :user_code) do
      {:ok,
       %{
         request_id: request_id,
         user_code: user_code,
         expires_at: response_value(body, :expires_at),
         interval: response_value(body, :interval)
       }}
    end
  end

  defp parse_cli_access_request(_body), do: {:error, "Invalid CLI access response format"}

  defp fetch_response_value(body, key) do
    case response_value(body, key) do
      value when is_binary(value) and value != "" -> {:ok, value}
      _ -> {:error, "Invalid CLI access response format"}
    end
  end

  defp response_value(body, key) do
    Map.get(body, Atom.to_string(key)) || Map.get(body, key)
  end

  defp request_interval_ms(%{interval: interval}) when is_integer(interval) and interval > 0 do
    interval * 1_000
  end

  defp request_interval_ms(_request), do: @default_cli_access_poll_interval_ms

  defp next_poll_interval_ms(interval_seconds, _default_ms)
       when is_integer(interval_seconds) and interval_seconds > 0 do
    interval_seconds * 1_000
  end

  defp next_poll_interval_ms(_interval_seconds, default_ms), do: default_ms

  defp cli_access_metadata do
    %{
      "client_name" => client_name(),
      "cli_version" => cli_version(),
      "os" => :os.type() |> Tuple.to_list() |> Enum.join("-")
    }
  end

  defp client_name do
    case :inet.gethostname() do
      {:ok, hostname} -> List.to_string(hostname)
      {:error, _reason} -> "unknown"
    end
  end

  defp cli_version do
    Application.spec(:secrethub_cli, :vsn)
    |> case do
      nil -> "unknown"
      version -> to_string(version)
    end
  end
end
