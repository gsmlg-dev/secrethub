defmodule SecretHub.Human.Vault.Envelope do
  @moduledoc "Validates client-owned AES-CBC/HMAC envelopes without decrypting or accessing a Core key."
  @encrypted_keys ~w(name notes username password totp uri uriChecksum value number brand code expMonth expYear
    cardholderName title firstName middleName lastName address1 address2 address3 city state postalCode
    country company email phone ssn passportNumber licenseNumber privateKey publicKey keyFingerprint)
  @objects ~w(login secureNote card identity sshKey)
  @arrays ~w(fields uris passwordHistory)
  @numeric_keys ~w(type match linkedId)

  def valid?(envelope), do: valid_blob?(envelope, 1_000_000)

  def valid_blob?("2." <> parts = envelope, max_bytes) when byte_size(envelope) <= max_bytes do
    with [iv, cipher, mac] <- String.split(parts, "|"),
         {:ok, iv} <- Base.decode64(iv),
         {:ok, cipher} <- Base.decode64(cipher),
         {:ok, mac} <- Base.decode64(mac) do
      byte_size(iv) == 16 and byte_size(mac) == 32 and byte_size(cipher) > 0 and
        rem(byte_size(cipher), 16) == 0
    else
      _ -> false
    end
  end

  def valid_blob?(_, _), do: false

  def valid_payload?(payload) when is_map(payload) do
    map_size(payload) > 0 and map_size(payload) <= 20 and valid?(Map.get(payload, "name")) and
      valid_map?(payload, 0) and byte_size(Jason.encode!(payload)) <= 1_000_000
  end

  def valid_payload?(_), do: false

  defp valid_map?(map, depth) when depth <= 4 and map_size(map) <= 40 do
    Enum.all?(map, &valid_field?(&1, depth))
  end

  defp valid_map?(_, _), do: false

  defp valid_field?({key, value}, _depth) when key in @encrypted_keys,
    do: is_nil(value) or valid?(value)

  defp valid_field?({key, value}, depth) when key in @objects,
    do: is_nil(value) or (is_map(value) and valid_map?(value, depth + 1))

  defp valid_field?({key, value}, depth) when key in @arrays,
    do:
      is_nil(value) or
        (is_list(value) and length(value) <= 100 and
           Enum.all?(value, &(is_map(&1) and valid_map?(&1, depth + 1))))

  defp valid_field?({key, value}, _depth) when key in @numeric_keys,
    do: is_nil(value) or (is_integer(value) and value in 0..100)

  defp valid_field?({"lastUsedDate", value}, _depth),
    do: is_binary(value) and match?({:ok, _, _}, DateTime.from_iso8601(value))

  defp valid_field?({"passwordRevisionDate", value}, _depth),
    do: is_nil(value) or (is_binary(value) and match?({:ok, _, _}, DateTime.from_iso8601(value)))

  defp valid_field?(_, _), do: false
end
