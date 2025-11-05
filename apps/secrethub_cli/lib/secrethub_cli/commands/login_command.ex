defmodule SecretHub.CLI.Commands.LoginCommand do
  @moduledoc """
  Login command implementation.
  """

  alias SecretHub.CLI.{Auth, Config, Output}

  @doc """
  Executes the login command.
  """
  def execute(opts) do
    role_id = Keyword.get(opts, :role_id)
    secret_id = Keyword.get(opts, :secret_id)
    server = Keyword.get(opts, :server)

    cond do
      is_nil(role_id) ->
        {:error, "Missing required option: --role-id"}

      is_nil(secret_id) ->
        {:error, "Missing required option: --secret-id"}

      true ->
        Auth.login(role_id, secret_id, server)
    end
  end

  @doc """
  Shows current authentication status.
  """
  def whoami(_opts) do
    case Auth.get_token() do
      {:ok, _token} ->
        with {:ok, config} <- Config.load(),
             auth_config = Map.get(config, "auth", %{}) do
          info = %{
            "authenticated" => true,
            "server" => Config.get_server_url(),
            "authenticated_at" => Map.get(auth_config, "authenticated_at"),
            "expires_at" => Map.get(auth_config, "expires_at")
          }

          Output.format(info, format: "table")
        end

      {:error, :expired} ->
        Output.error("Authentication token has expired")
        {:error, "Token expired"}

      {:error, :not_found} ->
        Output.info("Not authenticated")
        {:ok, "Not authenticated"}
    end
  end
end
