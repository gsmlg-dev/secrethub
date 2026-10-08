defmodule SecretHub.Shared.RuntimeConfig do
  @moduledoc "Strict parsers for the supported single-operator release configuration."

  def database_url!(value) do
    try do
      config = Ecto.Repo.Supervisor.parse_url(value)
      if config[:scheme] not in ["postgresql", "postgres"], do: raise(ArgumentError)
      value
    rescue
      _ -> raise ArgumentError, "DATABASE_URL: invalid_database_url"
    end
  end

  def port!(name, default) do
    case Integer.parse(System.get_env(name) || to_string(default)) do
      {port, ""} when port in 1..65_535 -> port
      _ -> raise ArgumentError, "#{name}: invalid_port"
    end
  end

  def private_ip!(name, default) do
    value = System.get_env(name) || default

    case :inet.parse_address(String.to_charlist(value)) do
      {:ok, {127, _, _, _} = ip} -> ip
      {:ok, {10, _, _, _} = ip} -> ip
      {:ok, {172, second, _, _} = ip} when second in 16..31 -> ip
      {:ok, {192, 168, _, _} = ip} -> ip
      {:ok, {0, 0, 0, 0, 0, 0, 0, 1} = ip} -> ip
      _ -> raise ArgumentError, "#{name}: private_address_required"
    end
  end

  def https_url!(name, value) do
    case URI.parse(value) do
      %URI{scheme: "https", host: host, userinfo: nil, query: nil, fragment: nil} = uri
      when is_binary(host) and host != "" ->
        uri

      _ ->
        raise ArgumentError, "#{name}: invalid_https_url"
    end
  end

  def decode_key!(name, value) do
    case Base.decode64(value) do
      {:ok, key} when byte_size(key) in 32..64 -> key
      _ -> raise ArgumentError, "#{name}: invalid_base64_key"
    end
  end

  def https_origin!(name, value) do
    uri = https_url!(name, value)

    if uri.path in [nil, "", "/"] and uri.port in 1..65_535 and
         not Regex.match?(~r/[\s*\\]/, uri.host) do
      %{uri | path: nil}
    else
      raise ArgumentError
    end
  rescue
    _ -> raise ArgumentError, "#{name}: invalid_origin"
  end

  def verification_keys!(nil), do: %{}

  def verification_keys!(encoded) do
    with {:ok, keys} when is_map(keys) <- Jason.decode(encoded),
         true <-
           Enum.all?(keys, fn {id, key} ->
             is_binary(id) and Regex.match?(~r/\A[a-zA-Z0-9_.-]{1,64}\z/, id) and
               is_binary(key)
           end) do
      Map.new(keys, fn {id, value} ->
        case Base.decode64(value) do
          {:ok, key} when byte_size(key) in 1..4096 -> {id, key}
          _ -> raise ArgumentError, "AUDIT_HMAC_VERIFICATION_KEYS: invalid_key"
        end
      end)
    else
      _ -> raise ArgumentError, "AUDIT_HMAC_VERIFICATION_KEYS: invalid_keyring"
    end
  end

  def distribution! do
    if System.get_env("RELEASE_DISTRIBUTION") != "none" do
      raise ArgumentError, "RELEASE_DISTRIBUTION: single_operator_requires_none"
    end

    :ok
  end
end
