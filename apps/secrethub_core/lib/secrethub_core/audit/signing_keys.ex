defmodule SecretHub.Core.Audit.SigningKeys do
  @moduledoc """
  Runtime signing material. Key IDs and signature versions are independent of
  the audit entry's hash version. Historical keys are verification-only.
  """

  @development_secret "dev-audit-secret"
  @key_id ~r/\A[a-zA-Z0-9_.-]{1,64}\z/

  def active(config) do
    development = Keyword.get(config, :env) in [:dev, :test]
    default = if development, do: @development_secret
    secret = Keyword.get(config, :audit_hmac_secret, default)
    id = Keyword.get(config, :audit_hmac_key_id)

    cond do
      development and is_nil(id) and is_binary(secret) and byte_size(secret) > 0 ->
        {:ok, %{id: nil, secret: secret, version: 1}}

      not valid_id?(id) ->
        {:error, :invalid_audit_key_id}

      not valid_signing_secret?(secret) ->
        {:error, :invalid_audit_signing_key}

      true ->
        {:ok, %{id: id, secret: secret, version: 2}}
    end
  end

  def verification_key(config, nil, 1) do
    case historical_key(config, "legacy") do
      {:ok, _} = found -> found
      {:error, _} -> legacy_development_key(config)
    end
  end

  def verification_key(config, id, 2) when is_binary(id) do
    with true <- valid_id?(id), {:ok, active} <- active(config) do
      if active.id == id, do: {:ok, active.secret}, else: historical_key(config, id)
    else
      _ -> {:error, :unknown_audit_key}
    end
  end

  def verification_key(_config, _id, _version), do: {:error, :unknown_audit_key}

  defp legacy_development_key(config) do
    case active(config) do
      {:ok, %{id: nil, secret: secret}} -> {:ok, secret}
      _ -> {:error, :unknown_audit_key}
    end
  end

  defp historical_key(config, id) do
    case Keyword.get(config, :audit_hmac_verification_keys, %{}) do
      %{^id => key} when is_binary(key) and byte_size(key) in 1..4096 -> {:ok, key}
      _ -> {:error, :unknown_audit_key}
    end
  end

  defp valid_id?(id) when is_binary(id), do: Regex.match?(@key_id, id)
  defp valid_id?(_), do: false

  defp valid_signing_secret?(secret) when is_binary(secret) and byte_size(secret) in 32..64,
    do: secret not in [@development_secret, "change-me-in-production"]

  defp valid_signing_secret?(_), do: false
end
