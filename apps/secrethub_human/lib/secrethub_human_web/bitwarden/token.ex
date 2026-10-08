defmodule SecretHub.HumanWeb.Bitwarden.Token do
  alias SecretHub.HumanWeb.Endpoint
  @moduledoc "Signed Bitwarden access-token envelope around a revocable Human session."
  alias SecretHub.Human.Accounts

  def issue(session) do
    actor = session.actor

    payload = %{
      "sub" => actor.user_id,
      "aud" => "api",
      "iss" => origin(),
      "exp" => DateTime.to_unix(session.expires_at),
      "nbf" => System.system_time(:second),
      "jti" => session.access_token,
      "sid" => actor.session_id,
      "device" => actor.device_id,
      "email" => session.user.email,
      "email_verified" => true,
      "name" => session.user.name,
      "amr" => ["Application"],
      "scope" => ["api", "offline_access"],
      "premium" => false
    }

    message = encode(%{"alg" => "HS256", "typ" => "JWT"}) <> "." <> encode(payload)
    message <> "." <> sign(message)
  end

  def authenticate(token) when is_binary(token) and byte_size(token) <= 4096 do
    with [header, payload, signature] <- String.split(token, "."),
         true <- Plug.Crypto.secure_compare(sign(header <> "." <> payload), signature),
         {:ok, header} <- decode(header),
         true <- header == %{"alg" => "HS256", "typ" => "JWT"},
         {:ok, claims} <- decode(payload),
         %{"aud" => "api", "exp" => exp, "nbf" => nbf, "iss" => issuer, "jti" => session} <-
           claims,
         true <-
           is_integer(exp) and is_integer(nbf) and exp > System.system_time(:second) and
             nbf <= System.system_time(:second) and issuer == origin(),
         {:ok, actor} <- Accounts.authenticate_session(session),
         true <-
           claims["sub"] == actor.user_id and claims["sid"] == actor.session_id and
             claims["device"] == actor.device_id do
      {:ok, actor}
    else
      _ -> {:error, :unauthenticated}
    end
  end

  def authenticate(_), do: {:error, :unauthenticated}

  defp origin do
    Endpoint.url()
  end

  defp encode(data), do: data |> Jason.encode!() |> Base.url_encode64(padding: false)

  defp decode(part) do
    with {:ok, json} <- Base.url_decode64(part, padding: false),
         {:ok, data} <- Jason.decode(json),
         true <- is_map(data),
         do: {:ok, data}
  end

  defp sign(message),
    do:
      :crypto.mac(:hmac, :sha256, Endpoint.config(:secret_key_base), message)
      |> Base.url_encode64(padding: false)
end
