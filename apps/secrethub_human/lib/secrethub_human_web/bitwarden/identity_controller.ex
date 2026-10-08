defmodule SecretHub.HumanWeb.Bitwarden.IdentityController do
  alias SecretHub.HumanWeb.Bitwarden.DTO
  use SecretHub.HumanWeb, :controller
  alias SecretHub.Human.Accounts
  alias SecretHub.HumanWeb.Bitwarden.Token

  def prelogin(conn, %{"email" => email}) do
    case Accounts.prelogin(email) do
      {:ok, config} -> json(conn, %{kdf: config.kdf, kdfIterations: config.kdf_iterations})
      {:error, _} -> error(conn, 400, "invalid_request")
    end
  end

  def prelogin(conn, _), do: error(conn, 400, "invalid_request")

  def password_prelogin(conn, %{"email" => email}) do
    case Accounts.prelogin(email) do
      {:ok, config} ->
        json(conn, %{
          kdfSettings: %{kdfType: config.kdf, iterations: config.kdf_iterations},
          salt: String.downcase(String.trim(email))
        })

      {:error, _} ->
        error(conn, 400, "invalid_request")
    end
  end

  def password_prelogin(conn, _), do: error(conn, 400, "invalid_request")

  def token(conn, %{"grant_type" => "password"} = params) do
    device = %{
      identifier: params["deviceIdentifier"],
      name: params["deviceName"],
      type: device_type(params["deviceType"]),
      two_factor_token: params["twoFactorToken"],
      two_factor_provider: params["twoFactorProvider"]
    }

    Accounts.authenticate(params["username"], params["password"], device) |> respond_token(conn)
  end

  def token(conn, %{"grant_type" => "refresh_token", "refresh_token" => refresh}) do
    Accounts.refresh_session(refresh) |> respond_token(conn)
  end

  def token(conn, _), do: error(conn, 400, "unsupported_grant_type")

  def key_id(conn, params) do
    case Accounts.record_user_key_id(conn.assigns.human_actor, params["userKeyId"]) do
      :ok -> json(conn, %{})
      {:error, _} -> error(conn, 400, "invalid_request")
    end
  end

  def register(conn, params) do
    attrs = %{
      email: params["email"],
      name: params["name"],
      password_hash: params["masterPasswordHash"],
      encrypted_key: params["key"],
      public_key: get_in(params, ["keys", "publicKey"]),
      encrypted_private_key: get_in(params, ["keys", "encryptedPrivateKey"]),
      kdf: Map.get(params, "kdf", 0),
      kdf_iterations: Map.get(params, "kdfIterations", 600_000)
    }

    case Accounts.register(attrs) do
      {:ok, _} -> json(conn, %{})
      {:error, :signup_disabled} -> error(conn, 403, "signup_disabled")
      {:error, _} -> error(conn, 400, "invalid_request")
    end
  end

  defp respond_token({:ok, session}, conn) do
    user = session.user

    json(conn, %{
      "access_token" => Token.issue(session),
      "refresh_token" => session.refresh_token,
      "expires_in" => session.expires_in,
      "token_type" => "Bearer",
      "Key" => user.encrypted_key,
      "PrivateKey" => user.encrypted_private_key,
      "AccountKeys" => DTO.account_keys(user),
      "Kdf" => user.kdf,
      "KdfIterations" => user.kdf_iterations,
      "ForcePasswordReset" => false,
      "ApiUseKeyConnector" => false,
      "MasterPasswordPolicy" => nil,
      "UserDecryptionOptions" => DTO.user_decryption(user)
    })
  end

  defp respond_token({:error, :rate_limited}, conn), do: error(conn, 429, "invalid_grant")
  defp respond_token({:error, _}, conn), do: error(conn, 400, "invalid_grant")
  defp device_type(type) when is_integer(type), do: type

  defp device_type(type) when is_binary(type) do
    case Integer.parse(type) do
      {number, ""} -> number
      _ -> -1
    end
  end

  defp device_type(nil), do: 9
  defp device_type(_), do: -1
  defp error(conn, status, message), do: conn |> put_status(status) |> json(%{error: message})
end
