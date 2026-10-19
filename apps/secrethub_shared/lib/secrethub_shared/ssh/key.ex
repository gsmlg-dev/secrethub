defmodule SecretHub.Shared.SSH.Key do
  @moduledoc """
  Bounded SSH key import and signing. Private keys are never logged or written.

  OTP's experimental OpenSSH private decoder is isolated here. Its result is
  checked and normalized to a single unencrypted PEM key before storage.
  """

  @ed25519 {1, 3, 101, 112}
  @public_types [
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521"
  ]

  def decode_public(input) when is_binary(input) and byte_size(input) <= 16_384 do
    with [encoded_type, encoded] <- public_fields(String.trim(input)),
         {:ok, blob} <- Base.decode64(encoded, padding: false),
         <<len::32, type::binary-size(len), _::binary>> <- blob,
         true <- type in @public_types and encoded_type in [nil, type],
         key <- :ssh_file.decode(blob, :ssh2_pubkey),
         true <- valid_public?(key),
         ^blob <- :ssh_file.encode(key, :ssh2_pubkey) do
      encoded = Base.encode64(blob)

      {:ok,
       %{
         type: type,
         blob: blob,
         encoded: encoded,
         key: key,
         public_line: type <> " " <> encoded,
         fingerprint: "SHA256:" <> Base.encode64(:crypto.hash(:sha256, blob), padding: false)
       }}
    else
      _ -> {:error, :invalid_public_key}
    end
  rescue
    _ -> {:error, :invalid_public_key}
  catch
    _, _ -> {:error, :invalid_public_key}
  end

  def decode_public(_), do: {:error, :invalid_public_key}

  def import_private(pem) when is_binary(pem) and byte_size(pem) <= 65_536 do
    with {:ok, declared_public} <- single_container(pem),
         {:ok, decoded} <- :ssh_file.decode_ssh_file(:private, :any, pem, :ignore),
         [key] <- Enum.flat_map(decoded, &private_entry/1),
         {:ok, normalized} <- normalize_private(key),
         {:ok, result} <- private_result(normalized),
         true <- is_nil(declared_public) or result.public.blob == declared_public do
      {:ok, result}
    else
      _ -> {:error, :invalid_private_key}
    end
  rescue
    _ -> {:error, :invalid_private_key}
  catch
    _, _ -> {:error, :invalid_private_key}
  end

  def import_private(_), do: {:error, :invalid_private_key}

  def generate("ed25519") do
    {pub, seed} = :crypto.generate_key(:eddsa, :ed25519)
    private_result({:ECPrivateKey, 1, seed, {:namedCurve, @ed25519}, pub, :asn1_NOVALUE})
  end

  def generate("rsa"), do: private_result(:public_key.generate_key({:rsa, 3072, 65_537}))
  def generate(_), do: {:error, :unsupported_algorithm}

  def sign(pem, data, flags) when is_binary(data) and byte_size(data) <= 262_144 do
    with {:ok, imported} <- import_private(pem),
         [entry] <- :public_key.pem_decode(imported.private_pem) do
      entry |> :public_key.pem_entry_decode() |> signature(data, flags)
    end
  rescue
    _ -> {:error, :signing_failed}
  catch
    _, _ -> {:error, :signing_failed}
  end

  def sign(_, _, _), do: {:error, :signing_failed}

  defp public_fields(text) do
    if String.contains?(text, ["\n", "\r", "\0"]) do
      []
    else
      case String.split(text, ~r/[\t ]+/, parts: 3) do
        [encoded] -> [nil, encoded]
        [type, encoded | _] -> [type, encoded]
      end
    end
  end

  defp valid_public?({:RSAPublicKey, n, e}), do: rsa_public?(n, e)
  defp valid_public?({{:ECPoint, pub}, {:namedCurve, @ed25519}}), do: byte_size(pub) == 32

  defp valid_public?({{:ECPoint, <<4, _::binary>> = pub}, {:namedCurve, oid}}) do
    case oid do
      {1, 2, 840, 10_045, 3, 1, 7} -> valid_point?(pub, :secp256r1, 65)
      {1, 3, 132, 0, 34} -> valid_point?(pub, :secp384r1, 97)
      {1, 3, 132, 0, 35} -> valid_point?(pub, :secp521r1, 133)
      _ -> false
    end
  end

  defp valid_public?(_), do: false

  defp valid_point?(pub, curve, length) do
    byte_size(pub) == length and is_binary(:crypto.compute_key(:ecdh, pub, <<1>>, curve))
  end

  defp rsa_public?(n, e) when is_integer(n) and is_integer(e) do
    n >= Bitwise.bsl(1, 2047) and n < Bitwise.bsl(1, 16_384) and e >= 3 and rem(e, 2) == 1
  end

  defp rsa_public?(_, _), do: false

  defp single_container(pem) do
    case Regex.run(
           ~r/\A\s*-----BEGIN ([A-Z0-9 ]+)-----\r?\n([A-Za-z0-9+\/=\r\n]+)-----END \1-----\s*\z/,
           pem
         ) do
      [_, "OPENSSH PRIVATE KEY", encoded] ->
        with {:ok, blob} <- Base.decode64(String.replace(encoded, ~r/\s/, "")),
             <<"openssh-key-v1\0", rest::binary>> <- blob,
             {:ok, "none", rest} <- ssh_string(rest),
             {:ok, "none", rest} <- ssh_string(rest),
             {:ok, "", <<1::32, rest::binary>>} <- ssh_string(rest),
             {:ok, public, rest} <- ssh_string(rest),
             {:ok, _private, ""} <- ssh_string(rest) do
          {:ok, public}
        else
          _ -> {:error, :invalid_container}
        end

      [_, type, _] when type in ["RSA PRIVATE KEY", "EC PRIVATE KEY", "PRIVATE KEY"] ->
        case :public_key.pem_decode(pem) do
          [{_, _, :not_encrypted}] -> {:ok, nil}
          _ -> {:error, :invalid_container}
        end

      _ ->
        {:error, :invalid_container}
    end
  end

  defp ssh_string(<<len::32, value::binary-size(len), rest::binary>>), do: {:ok, value, rest}
  defp ssh_string(_), do: {:error, :invalid_string}

  defp private_entry({key, _}) when elem(key, 0) in [:RSAPrivateKey, :ECPrivateKey], do: [key]
  defp private_entry(_), do: []

  defp normalize_private({:RSAPrivateKey, ver, n, e, d, p, q, _, _, _, extras})
       when is_integer(d) and is_integer(p) and p > 1 and is_integer(q) and q > 1 do
    if rsa_public?(n, e) and p * q == n and
         rem(d * e, div((p - 1) * (q - 1), Integer.gcd(p - 1, q - 1))) == 1 do
      coefficient = :crypto.mod_pow(q, p - 2, p) |> :binary.decode_unsigned()

      {:ok,
       {:RSAPrivateKey, ver, n, e, d, p, q, rem(d, p - 1), rem(d, q - 1), coefficient, extras}}
    else
      {:error, :invalid_rsa_key}
    end
  end

  defp normalize_private({:ECPrivateKey, ver, seed, {:namedCurve, @ed25519}, existing, _})
       when byte_size(seed) == 32 do
    {pub, ^seed} = :crypto.generate_key(:eddsa, :ed25519, seed)

    if existing in [:asn1_NOVALUE, :undefined, pub] do
      {:ok, {:ECPrivateKey, ver, seed, {:namedCurve, @ed25519}, pub, :asn1_NOVALUE}}
    else
      {:error, :invalid_ed25519_key}
    end
  end

  defp normalize_private(_), do: {:error, :unsupported_private_key}

  defp private_result(key) do
    public =
      key |> :ssh_file.extract_public_key() |> :ssh_file.encode(:ssh2_pubkey) |> Base.encode64()

    {:ok, public} = decode_public(public)
    entry = :public_key.pem_entry_encode(elem(key, 0), key)
    {:ok, %{public: public, private_pem: :public_key.pem_encode([entry])}}
  end

  defp signature({:ECPrivateKey, _, seed, {:namedCurve, @ed25519}, _, _}, data, 0) do
    {:ok,
     wire_string("ssh-ed25519") <>
       wire_string(:crypto.sign(:eddsa, :none, data, [seed, :ed25519]))}
  end

  defp signature({:RSAPrivateKey, _, _, _, _, _, _, _, _, _, _} = key, data, flag)
       when flag in [2, 4] do
    {algorithm, digest} =
      if flag == 2, do: {"rsa-sha2-256", :sha256}, else: {"rsa-sha2-512", :sha512}

    {:ok, wire_string(algorithm) <> wire_string(:public_key.sign(data, digest, key))}
  end

  defp signature(_, _, _), do: {:error, :unsupported_signature}
  defp wire_string(bin), do: <<byte_size(bin)::32, bin::binary>>
end
