defmodule SecretHub.Core.Vault.LegacyRecovery do
  @moduledoc """
  Quarantined decoder for historical modulo-251 shares. Reconstruction is never
  sufficient proof: persistence verifies the key against trusted database
  ciphertext while locking the legacy Vault row in the same transaction.
  """
  import Ecto.Query
  alias SecretHub.Shared.Crypto.Encryption
  alias SecretHub.Shared.Schemas.{Secret, SecretVersion, VaultConfig}

  def reconstruct(encoded, config) when is_list(encoded) and length(encoded) in 1..250 do
    with {:ok, shares} <- decode_all(encoded),
         [first | _] <- shares,
         true <- length(shares) >= config.threshold,
         true <-
           Enum.all?(shares, fn share ->
             share.threshold == config.threshold and share.total == config.total_shares and
               {share.version, share.mask} == {first.version, first.mask}
           end),
         true <- length(Enum.uniq_by(shares, & &1.id)) == length(shares) do
      key =
        for position <- 0..31 do
          normalized =
            Enum.reduce(shares, 0, fn share, sum ->
              weight =
                Enum.reduce(shares, 1, fn
                  %{id: id}, acc when id == share.id ->
                    acc

                  other, acc ->
                    modulo(acc * modulo(-other.id) * inverse(modulo(share.id - other.id)))
                end)

              modulo(sum + :binary.at(share.value, position) * weight)
            end)

          normalized + 251 * :binary.at(first.mask, position)
        end

      if Enum.all?(key, &(&1 <= 255)),
        do: {:ok, :binary.list_to_bin(key)},
        else: {:error, :invalid_legacy_shares}
    else
      _ -> {:error, :invalid_legacy_shares}
    end
  rescue
    _ -> {:error, :invalid_legacy_shares}
  end

  def reconstruct(_, _), do: {:error, :invalid_legacy_shares}

  def persist(repo, original, candidate, old_key, append_audit) do
    repo.transaction(fn ->
      current = repo.one(from(v in VaultConfig, where: v.id == ^original.id, lock: "FOR UPDATE"))
      if current != original, do: repo.rollback(:legacy_state_changed)
      if not verified?(repo, old_key), do: repo.rollback(:no_trusted_ciphertext)

      attrs =
        Map.take(Map.from_struct(candidate), [
          :encrypted_master_key,
          :envelope_version,
          :share_version,
          :share_set_id,
          :threshold,
          :total_shares
        ])

      case repo.update(VaultConfig.changeset(current, attrs)) do
        {:ok, committed} ->
          case append_audit.() do
            {:ok, _} -> committed
            _ -> repo.rollback(:durable_failure)
          end

        {:error, _} ->
          repo.rollback(:durable_failure)
      end
    end)
  rescue
    _ -> {:error, :durable_failure}
  catch
    :exit, _ -> {:error, :durable_failure}
  end

  defp verified?(repo, key) do
    # Certificate ciphertext lacks trustworthy Vault-key provenance: historical
    # PKI code also used a known development wrapping key. Even a matching
    # certificate/private key pair cannot prove which encryption key was used.
    queries = [
      from(s in Secret, where: not is_nil(s.encrypted_data), select: s.encrypted_data),
      from(s in SecretVersion, where: not is_nil(s.encrypted_data), select: s.encrypted_data)
    ]

    Enum.any?(queries, fn query ->
      Enum.any?(repo.all(query), fn
        <<1, _nonce::binary-size(12), _tag::binary-size(16), ciphertext::binary>> = blob
        when byte_size(ciphertext) > 0 ->
          match?({:ok, _}, Encryption.decrypt_from_blob(blob, key))

        _ ->
          false
      end)
    end)
  end

  defp decode_all(encoded) do
    Enum.reduce_while(encoded, {:ok, []}, fn input, {:ok, acc} ->
      case decode(input) do
        {:ok, share} -> {:cont, {:ok, [share | acc]}}
        error -> {:halt, error}
      end
    end)
  end

  # Fixed 32-byte Vault keys; canonical encoding, exact framing, and nonzero field coordinates.
  defp decode("secrethub-share-" <> encoded) when byte_size(encoded) <= 94 do
    with {:ok, blob} <- Base.url_decode64(encoded, padding: false),
         true <- Base.url_encode64(blob, padding: false) == encoded,
         {:ok, share} <- decode_blob(blob),
         true <-
           share.id in 1..250 and share.id <= share.total and
             share.threshold in 1..share.total//1 and share.total <= 251 and
             Enum.all?(:binary.bin_to_list(share.value), &(&1 < 251)) and
             Enum.all?(:binary.bin_to_list(share.mask), &(&1 in [0, 1])) do
      {:ok, share}
    else
      _ -> {:error, :invalid_legacy_shares}
    end
  end

  defp decode(_), do: {:error, :invalid_legacy_shares}

  defp decode_blob(<<1, id, threshold, total, value::binary-size(32)>>),
    do:
      {:ok,
       %{version: 1, id: id, threshold: threshold, total: total, mask: <<0::256>>, value: value}}

  defp decode_blob(<<2, id, threshold, total, 32, value::binary-size(32)>>),
    do:
      {:ok,
       %{version: 2, id: id, threshold: threshold, total: total, mask: <<0::256>>, value: value}}

  defp decode_blob(
         <<3, id, threshold, total, 32, 32, mask::binary-size(32), value::binary-size(32)>>
       ),
       do:
         {:ok,
          %{version: 3, id: id, threshold: threshold, total: total, mask: mask, value: value}}

  defp decode_blob(_), do: {:error, :invalid_legacy_shares}

  defp modulo(value), do: Integer.mod(value, 251)
  defp inverse(value), do: power(value, 249)
  defp power(_, 0), do: 1

  defp power(value, exponent) do
    half = power(value, div(exponent, 2))
    square = modulo(half * half)
    if rem(exponent, 2) == 0, do: square, else: modulo(square * value)
  end
end
