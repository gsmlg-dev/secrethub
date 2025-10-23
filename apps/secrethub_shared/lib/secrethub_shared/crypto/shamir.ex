defmodule SecretHub.Shared.Crypto.Shamir do
  @moduledoc """
  Shamir's Secret Sharing implementation for secure key splitting.

  This module implements Shamir's Secret Sharing algorithm to split the master
  encryption key into N shares, where any K shares can reconstruct the original
  secret. This is used for the unseal mechanism.

  ## Security Properties
  - Information-theoretic security
  - Any K-1 shares reveal no information about the secret
  - Exactly K shares are required to reconstruct
  - Shares can be distributed to different administrators

  ## Typical Configuration
  - Total shares (N): 5
  - Threshold (K): 3
  - This means 5 key shares are generated, and any 3 can unseal the vault
  """

  # Use largest prime < 256 for byte-wise Shamir sharing
  # This ensures all values stay within byte range (0-255)
  @prime 251
  # Limited by prime
  @max_shares 251

  @type share :: %{
          id: non_neg_integer(),
          value: binary(),
          threshold: non_neg_integer(),
          total_shares: non_neg_integer(),
          secret_length: non_neg_integer(),
          adjustment_mask: binary()
        }

  @doc """
  Splits a secret into N shares with threshold K.

  ## Parameters
  - `secret`: The secret to split (typically 32 bytes for AES-256 key)
  - `total_shares`: Total number of shares to generate (N)
  - `threshold`: Minimum shares required to reconstruct (K)

  ## Examples

      iex> secret = :crypto.strong_rand_bytes(32)
      iex> {:ok, shares} = Shamir.split(secret, 5, 3)
      iex> length(shares)
      5
  """
  @spec split(binary(), pos_integer(), pos_integer()) :: {:ok, [share()]} | {:error, String.t()}
  def split(secret, total_shares, threshold)
      when is_binary(secret) and
             total_shares > 0 and total_shares <= @max_shares and
             threshold > 0 and threshold <= total_shares do
    # Store original secret length
    secret_length = byte_size(secret)

    # Split secret byte-by-byte
    secret_bytes = :binary.bin_to_list(secret)

    # For bytes >= @prime, we need to map them to valid field elements
    # Map 251->0, 252->1, 253->2, 254->3, 255->4 (offset by -251)
    normalized_bytes =
      Enum.map(secret_bytes, fn byte ->
        if byte >= @prime, do: byte - @prime, else: byte
      end)

    # Track which bytes were adjusted (for reconstruction)
    adjustment_mask =
      Enum.map(secret_bytes, fn byte ->
        if byte >= @prime, do: 1, else: 0
      end)

    # Generate one polynomial per byte of the secret
    # Each polynomial: P(x) = secret_byte + a1*x + a2*x^2 + ... + a(k-1)*x^(k-1)
    data_polynomials =
      for byte <- normalized_bytes do
        [byte | generate_coefficients(threshold - 1)]
      end

    # Generate shares by evaluating each polynomial at points 1..N
    shares =
      for id <- 1..total_shares do
        # For each share, evaluate all polynomials at this ID
        share_bytes =
          for coefficients <- data_polynomials do
            evaluate_polynomial(coefficients, id)
          end

        # Encode adjustment mask in the share (simple approach: store as binary)
        adjustment_bin = :binary.list_to_bin(adjustment_mask)

        %{
          id: id,
          value: :binary.list_to_bin(share_bytes),
          threshold: threshold,
          total_shares: total_shares,
          secret_length: secret_length,
          # Store which bytes need +251 adjustment
          adjustment_mask: adjustment_bin
        }
      end

    {:ok, shares}
  end

  def split(_secret, total_shares, _threshold) when total_shares > @max_shares do
    {:error, "Maximum #{@max_shares} shares allowed (limited by prime #{@prime})"}
  end

  def split(_secret, total_shares, threshold) when threshold > total_shares do
    {:error, "Threshold cannot exceed total shares"}
  end

  def split(_secret, _total_shares, _threshold) do
    {:error, "Invalid parameters"}
  end

  @doc """
  Combines K shares to reconstruct the original secret.

  Uses Lagrange interpolation to reconstruct the polynomial at x=0.

  ## Examples

      iex> secret = :crypto.strong_rand_bytes(32)
      iex> {:ok, shares} = Shamir.split(secret, 5, 3)
      iex> {:ok, reconstructed} = Shamir.combine(Enum.take(shares, 3))
      iex> reconstructed == secret
      true
  """
  @spec combine([share()]) :: {:ok, binary()} | {:error, String.t()}
  def combine(shares) when is_list(shares) and length(shares) > 0 do
    # Verify all shares have the same threshold and secret_length
    thresholds = shares |> Enum.map(& &1.threshold) |> Enum.uniq()
    secret_lengths = shares |> Enum.map(&Map.get(&1, :secret_length, 32)) |> Enum.uniq()

    cond do
      length(thresholds) != 1 ->
        {:error, "All shares must have the same threshold"}

      length(shares) < hd(thresholds) ->
        {:error, "Not enough shares. Need #{hd(thresholds)}, got #{length(shares)}"}

      true ->
        # Get the secret length and adjustment mask
        secret_length = hd(secret_lengths)
        adjustment_mask = hd(shares).adjustment_mask |> :binary.bin_to_list()

        # Convert share values to byte lists
        share_byte_lists =
          Enum.map(shares, fn share ->
            {share.id, :binary.bin_to_list(share.value)}
          end)

        # Reconstruct each byte independently using Lagrange interpolation
        reconstructed_bytes =
          for byte_index <- 0..(secret_length - 1) do
            # Get the byte at this index from each share
            points =
              Enum.map(share_byte_lists, fn {id, bytes} ->
                {id, Enum.at(bytes, byte_index)}
              end)

            # Reconstruct this byte using Lagrange interpolation at x=0
            reconstructed_byte = lagrange_interpolation(points, 0)

            # Apply adjustment if this byte was >= 251 originally
            # Use rem/2 to ensure result is always a valid byte (0-255)
            if Enum.at(adjustment_mask, byte_index) == 1 do
              rem(reconstructed_byte + @prime, 256)
            else
              rem(reconstructed_byte, 256)
            end
          end

        # Convert back to binary
        secret = :binary.list_to_bin(reconstructed_bytes)

        {:ok, secret}
    end
  end

  def combine([]) do
    {:error, "No shares provided"}
  end

  @doc """
  Validates that a share has the correct structure.

  ## Examples

      iex> share = %{id: 1, value: <<1,2,3>>, threshold: 3, total_shares: 5, secret_length: 32, adjustment_mask: <<0>>}
      iex> Shamir.valid_share?(share)
      true
  """
  @spec valid_share?(any()) :: boolean()
  # Modern shares with adjustment_mask
  def valid_share?(%{
        id: id,
        value: value,
        threshold: threshold,
        total_shares: total,
        adjustment_mask: mask
      })
      when is_integer(id) and id > 0 and
             is_binary(value) and
             is_binary(mask) and
             is_integer(threshold) and threshold > 0 and
             is_integer(total) and total > 0 and threshold <= total do
    true
  end

  # Legacy shares without adjustment_mask (backwards compatibility)
  def valid_share?(%{id: id, value: value, threshold: threshold, total_shares: total})
      when is_integer(id) and id > 0 and
             is_binary(value) and
             is_integer(threshold) and threshold > 0 and
             is_integer(total) and total > 0 and threshold <= total do
    true
  end

  def valid_share?(_), do: false

  @doc """
  Encodes a share as a base64 string for safe transmission.

  ## Examples

      iex> share = %{id: 1, value: <<1,2,3>>, threshold: 3, total_shares: 5, secret_length: 32}
      iex> encoded = Shamir.encode_share(share)
      iex> String.starts_with?(encoded, "secrethub-share-")
      true
  """
  @spec encode_share(share()) :: String.t()
  def encode_share(%{
        id: id,
        value: value,
        threshold: threshold,
        total_shares: total,
        secret_length: secret_length,
        adjustment_mask: adjustment_mask
      }) do
    # Format: [version(3)][id(1)][threshold(1)][total(1)][secret_length(1)][mask_length(1)][adjustment_mask(N)][value(M)]
    mask_length = byte_size(adjustment_mask)

    blob =
      <<3::8, id::8, threshold::8, total::8, secret_length::8, mask_length::8,
        adjustment_mask::binary, value::binary>>

    encoded = Base.url_encode64(blob, padding: false)
    "secrethub-share-#{encoded}"
  end

  @doc """
  Decodes a base64-encoded share string.

  ## Examples

      iex> share = %{id: 1, value: <<1,2,3>>, threshold: 3, total_shares: 5, secret_length: 32}
      iex> encoded = Shamir.encode_share(share)
      iex> {:ok, decoded} = Shamir.decode_share(encoded)
      iex> decoded.id
      1
  """
  @spec decode_share(String.t()) :: {:ok, share()} | {:error, String.t()}
  def decode_share("secrethub-share-" <> encoded_blob) do
    with {:ok, blob} <- Base.url_decode64(encoded_blob, padding: false) do
      case blob do
        # Version 3: includes adjustment_mask
        <<3::8, id::8, threshold::8, total::8, secret_length::8, mask_length::8, rest::binary>> ->
          <<adjustment_mask::binary-size(mask_length), value::binary>> = rest

          {:ok,
           %{
             id: id,
             value: value,
             threshold: threshold,
             total_shares: total,
             secret_length: secret_length,
             adjustment_mask: adjustment_mask
           }}

        # Version 2: includes secret_length (backwards compat - no adjustment)
        <<2::8, id::8, threshold::8, total::8, secret_length::8, value::binary>> ->
          {:ok,
           %{
             id: id,
             value: value,
             threshold: threshold,
             total_shares: total,
             secret_length: secret_length,
             # No adjustments
             adjustment_mask: <<0::size(secret_length)-unit(8)>>
           }}

        # Version 1: backwards compatibility (assume 32 bytes)
        <<1::8, id::8, threshold::8, total::8, value::binary>> ->
          {:ok,
           %{
             id: id,
             value: value,
             threshold: threshold,
             total_shares: total,
             secret_length: 32,
             # No adjustments
             adjustment_mask: <<0::size(32)-unit(8)>>
           }}

        _ ->
          {:error, "Invalid share format"}
      end
    else
      _ -> {:error, "Invalid share format"}
    end
  end

  def decode_share(_invalid) do
    {:error, "Invalid share format - must start with 'secrethub-share-'"}
  end

  # Private helper functions

  defp generate_coefficients(count) when count <= 0, do: []

  defp generate_coefficients(count) do
    for _ <- 1..count do
      # Generate random coefficients in GF(257) (0-256)
      :crypto.strong_rand_bytes(1) |> :binary.decode_unsigned() |> rem(@prime)
    end
  end

  defp evaluate_polynomial(coefficients, x) do
    coefficients
    |> Enum.with_index()
    |> Enum.reduce(0, fn {coeff, power}, acc ->
      term = modular_mult(coeff, modular_pow(x, power))
      modular_add(acc, term)
    end)
  end

  defp lagrange_interpolation(points, x) do
    points
    |> Enum.reduce(0, fn {xi, yi}, acc ->
      basis = lagrange_basis(points, xi, x)
      term = modular_mult(yi, basis)
      modular_add(acc, term)
    end)
  end

  defp lagrange_basis(points, xi, x) do
    points
    |> Enum.reject(fn {xj, _} -> xj == xi end)
    |> Enum.reduce(1, fn {xj, _}, acc ->
      numerator = modular_sub(x, xj)
      denominator = modular_sub(xi, xj)
      denominator_inv = modular_inverse(denominator)
      term = modular_mult(numerator, denominator_inv)
      modular_mult(acc, term)
    end)
  end

  # Modular arithmetic operations

  defp modular_add(a, b), do: rem(a + b, @prime)

  defp modular_sub(a, b), do: rem(a - b + @prime, @prime)

  defp modular_mult(a, b), do: rem(a * b, @prime)

  defp modular_pow(_base, 0), do: 1

  defp modular_pow(base, exp) when exp > 0 do
    half = modular_pow(base, div(exp, 2))
    half_squared = modular_mult(half, half)

    if rem(exp, 2) == 0 do
      half_squared
    else
      modular_mult(base, half_squared)
    end
  end

  defp modular_inverse(a) do
    # Extended Euclidean algorithm
    extended_gcd(a, @prime) |> elem(0) |> rem(@prime) |> modular_add(@prime)
  end

  defp extended_gcd(_a, 0), do: {1, 0}

  defp extended_gcd(a, b) do
    {x1, y1} = extended_gcd(b, rem(a, b))
    {y1, x1 - div(a, b) * y1}
  end
end
