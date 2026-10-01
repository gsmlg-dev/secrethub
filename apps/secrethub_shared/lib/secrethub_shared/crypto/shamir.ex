defmodule SecretHub.Shared.Crypto.Shamir do
  @moduledoc """
  Byte-wise Shamir sharing over GF(256), with the AES polynomial `0x11b`.

  Every secret byte is the constant coefficient of an independent polynomial.
  All remaining coefficients are independent uniform random bytes, including
  zero. Shares use distinct nonzero coordinates 1 through 251. Any threshold
  shares recover the secret; fewer reveal no information about its bytes.

  Version 4 envelopes bind the parameters to a 16-byte share-set generation.
  This metadata is not authentication: callers must compare the generation to
  durable Vault state and authenticate the reconstructed key before unsealing.
  Versions 1–3 are deliberately unsupported and require verified recovery.
  See `docs/security/shamir-v4.md` for the wire specification and vectors.
  """

  import Bitwise

  @version 4
  @max_shares 251
  @max_secret_length 4096
  @header_length 22
  @max_encoded_length div((@header_length + @max_secret_length) * 4 + 2, 3)

  @type share :: %{
          version: 4,
          share_set_id: binary(),
          id: pos_integer(),
          value: binary(),
          threshold: pos_integer(),
          total_shares: pos_integer(),
          secret_length: pos_integer()
        }

  @doc "Splits a nonempty secret of at most 4096 bytes into a fresh share set."
  @spec split(binary(), pos_integer(), pos_integer()) :: {:ok, [share()]} | {:error, String.t()}
  def split(secret, total_shares, threshold) do
    split(secret, total_shares, threshold, :crypto.strong_rand_bytes(16))
  end

  @doc "Splits a secret with a caller-supplied raw 16-byte Vault generation."
  @spec split(binary(), pos_integer(), pos_integer(), binary()) ::
          {:ok, [share()]} | {:error, String.t()}
  def split(secret, total, threshold, share_set_id)
      when is_binary(secret) and byte_size(secret) in 1..@max_secret_length and
             is_integer(total) and total in 1..@max_shares and
             is_integer(threshold) and threshold in 1..total//1 and
             is_binary(share_set_id) and byte_size(share_set_id) == 16 do
    polynomials =
      for <<byte <- secret>> do
        # No reduction, rejection, or forced nonzero leading coefficient:
        # all 256 coefficients are equally likely, including zero.
        [byte | :binary.bin_to_list(:crypto.strong_rand_bytes(threshold - 1))]
      end

    shares =
      for id <- 1..total do
        value = for coefficients <- polynomials, into: <<>>, do: <<evaluate(coefficients, id)>>

        %{
          version: @version,
          share_set_id: share_set_id,
          id: id,
          value: value,
          threshold: threshold,
          total_shares: total,
          secret_length: byte_size(secret)
        }
      end

    {:ok, shares}
  end

  def split(_secret, total, _threshold, _share_set_id)
      when is_integer(total) and total > @max_shares,
      do: {:error, "Maximum #{@max_shares} shares allowed"}

  def split(_secret, total, threshold, _share_set_id)
      when is_integer(total) and is_integer(threshold) and threshold > total,
      do: {:error, "Threshold cannot exceed total shares"}

  def split(_secret, _total, _threshold, _share_set_id), do: {:error, "Invalid parameters"}

  @doc "Validates complete v4 envelopes, then interpolates at coordinate zero."
  @spec combine([share()]) :: {:ok, binary()} | {:error, String.t()}
  def combine([]), do: {:error, "No shares provided"}

  def combine([first | _] = shares) when length(shares) <= @max_shares do
    cond do
      not Enum.all?(shares, &valid_share?/1) ->
        {:error, "Invalid share"}

      not Enum.all?(shares, &(&1.threshold == first.threshold)) ->
        {:error, "All shares must have the same threshold"}

      not Enum.all?(shares, &(parameters(&1) == parameters(first))) ->
        {:error, "Inconsistent share parameters or share-set generation"}

      length(Enum.uniq_by(shares, & &1.id)) != length(shares) ->
        {:error, "Duplicate share coordinates"}

      length(shares) < first.threshold ->
        {:error, "Not enough shares. Need #{first.threshold}, got #{length(shares)}"}

      true ->
        weighted = Enum.map(shares, &{&1.value, lagrange_weight(&1.id, shares)})

        secret =
          for position <- 0..(first.secret_length - 1), into: <<>> do
            byte =
              Enum.reduce(weighted, 0, fn {value, weight}, acc ->
                bxor(acc, multiply(:binary.at(value, position), weight))
              end)

            <<byte>>
          end

        {:ok, secret}
    end
  end

  def combine(_invalid), do: {:error, "Invalid shares"}

  @doc "Checks every required v4 field and its bounds without raising."
  @spec valid_share?(any()) :: boolean()
  def valid_share?(%{
        version: @version,
        share_set_id: generation,
        id: id,
        value: value,
        threshold: threshold,
        total_shares: total,
        secret_length: length
      })
      when is_binary(generation) and byte_size(generation) == 16 and
             is_integer(total) and total in 1..@max_shares and
             is_integer(id) and id in 1..total//1 and
             is_integer(threshold) and threshold in 1..total//1 and
             is_integer(length) and length in 1..@max_secret_length and
             is_binary(value) and byte_size(value) == length,
      do: true

  def valid_share?(_invalid), do: false

  @doc "Encodes a valid v4 share as unpadded URL-safe base64; rejects invalid maps."
  @spec encode_share(share()) :: String.t() | {:error, String.t()}
  def encode_share(share) do
    if valid_share?(share) do
      blob =
        <<@version, share.id, share.threshold, share.total_shares,
          share.secret_length::unsigned-big-16, share.share_set_id::binary-size(16),
          share.value::binary>>

      "secrethub-share-" <> Base.url_encode64(blob, padding: false)
    else
      {:error, "Invalid share"}
    end
  end

  @doc "Decodes bounded v4 input, rejecting malformed or legacy envelopes."
  @spec decode_share(any()) :: {:ok, share()} | {:error, String.t()}
  def decode_share("secrethub-share-" <> encoded)
      when byte_size(encoded) <= @max_encoded_length do
    with {:ok, blob} <- Base.url_decode64(encoded, padding: false),
         true <- Base.url_encode64(blob, padding: false) == encoded do
      decode_blob(blob)
    else
      _invalid -> {:error, "Invalid share format"}
    end
  end

  def decode_share("secrethub-share-" <> _oversized), do: {:error, "Share exceeds size limit"}

  def decode_share(_invalid),
    do: {:error, "Invalid share format - must start with 'secrethub-share-'"}

  defp decode_blob(
         <<@version, id, threshold, total, length::unsigned-big-16, generation::binary-size(16),
           value::binary>>
       ) do
    share = %{
      version: @version,
      share_set_id: generation,
      id: id,
      value: value,
      threshold: threshold,
      total_shares: total,
      secret_length: length
    }

    if valid_share?(share), do: {:ok, share}, else: {:error, "Invalid share envelope"}
  end

  defp decode_blob(<<version, _rest::binary>>) when version in 1..3,
    do: {:error, "Legacy share version unsupported; verified Vault recovery required"}

  defp decode_blob(_invalid), do: {:error, "Invalid or unsupported share format"}

  defp parameters(share),
    do: {share.version, share.share_set_id, share.total_shares, share.secret_length}

  defp evaluate(coefficients, x) do
    coefficients |> Enum.reverse() |> Enum.reduce(0, &bxor(&1, multiply(&2, x)))
  end

  defp lagrange_weight(id, shares) do
    Enum.reduce(shares, 1, fn
      %{id: ^id}, weight -> weight
      %{id: other}, weight -> multiply(weight, multiply(other, power(bxor(id, other), 254)))
    end)
  end

  # Carryless shift-and-add, reducing modulo x^8+x^4+x^3+x+1 (0x11b).
  defp multiply(a, b), do: multiply(a, b, 0, 8)
  defp multiply(_a, _b, product, 0), do: product

  defp multiply(a, b, product, remaining) do
    product = if band(b, 1) == 1, do: bxor(product, a), else: product
    shifted = bsl(a, 1)
    a = if band(a, 0x80) == 0, do: shifted, else: bxor(shifted, 0x11B)
    multiply(a, bsr(b, 1), product, remaining - 1)
  end

  # For a nonzero field element, a^254 is its multiplicative inverse.
  defp power(_base, 0), do: 1

  defp power(base, exponent) do
    half = power(base, div(exponent, 2))
    square = multiply(half, half)
    if rem(exponent, 2) == 0, do: square, else: multiply(square, base)
  end
end
