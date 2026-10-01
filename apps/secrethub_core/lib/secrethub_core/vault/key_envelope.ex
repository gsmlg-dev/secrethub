defmodule SecretHub.Core.Vault.KeyEnvelope do
  @moduledoc "Authenticated wrapping of a Vault data key, bound to its durable identity."
  @version 1

  def wrap(<<_::256>> = data_key, <<_::256>> = wrapping_key, config) do
    nonce = :crypto.strong_rand_bytes(12)

    {ciphertext, tag} =
      :crypto.crypto_one_time_aead(:aes_256_gcm, wrapping_key, nonce, data_key, aad(config), true)

    <<@version, nonce::binary, tag::binary, ciphertext::binary>>
  end

  def unwrap(
        <<@version, nonce::binary-size(12), tag::binary-size(16), ciphertext::binary-size(32)>>,
        <<_::256>> = key,
        config
      ) do
    case :crypto.crypto_one_time_aead(
           :aes_256_gcm,
           key,
           nonce,
           ciphertext,
           aad(config),
           tag,
           false
         ) do
      <<_::256>> = data_key -> {:ok, data_key}
      _ -> {:error, :invalid_key_envelope}
    end
  rescue
    _ -> {:error, :invalid_key_envelope}
  end

  def unwrap(_, _, _), do: {:error, :invalid_key_envelope}

  defp aad(%{
         id: id,
         share_set_id: <<_::128>> = generation,
         threshold: threshold,
         total_shares: total
       }) do
    # UUID text has a fixed canonical representation; a length prefix avoids ambiguous concatenation.
    <<"SecretHub-Vault", @version, 4, byte_size(id)::16, id::binary, generation::binary,
      threshold::8, total::8>>
  end
end
