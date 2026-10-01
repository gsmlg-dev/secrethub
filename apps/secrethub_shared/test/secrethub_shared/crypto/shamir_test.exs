defmodule SecretHub.Shared.Crypto.ShamirTest do
  @moduledoc """
  Unit tests for Shamir Secret Sharing implementation.

  Tests cover:
  - Basic split and combine
  - Threshold requirements
  - Share validation
  - Encoding/decoding
  - Security properties
  - Edge cases
  """

  use ExUnit.Case, async: true

  alias SecretHub.Shared.Crypto.Shamir

  describe "split/3 and combine/1" do
    test "splits and combines secret correctly with minimum threshold" do
      secret = :crypto.strong_rand_bytes(32)
      total_shares = 3
      threshold = 2

      assert {:ok, shares} = Shamir.split(secret, total_shares, threshold)
      assert length(shares) == total_shares

      # Any 2 shares should reconstruct the secret
      assert {:ok, reconstructed} = Shamir.combine(Enum.take(shares, 2))
      assert reconstructed == secret
    end

    test "splits and combines with standard configuration (5,3)" do
      secret = :crypto.strong_rand_bytes(32)

      assert {:ok, shares} = Shamir.split(secret, 5, 3)
      assert length(shares) == 5

      # Any 3 shares should work
      assert {:ok, reconstructed} = Shamir.combine(Enum.take(shares, 3))
      assert reconstructed == secret
    end

    test "different combinations of threshold shares reconstruct same secret" do
      secret = :crypto.strong_rand_bytes(32)

      {:ok, shares} = Shamir.split(secret, 5, 3)

      # Try different combinations
      combo1 = [Enum.at(shares, 0), Enum.at(shares, 1), Enum.at(shares, 2)]
      combo2 = [Enum.at(shares, 1), Enum.at(shares, 3), Enum.at(shares, 4)]
      combo3 = [Enum.at(shares, 0), Enum.at(shares, 2), Enum.at(shares, 4)]

      assert {:ok, reconstructed1} = Shamir.combine(combo1)
      assert {:ok, reconstructed2} = Shamir.combine(combo2)
      assert {:ok, reconstructed3} = Shamir.combine(combo3)

      assert reconstructed1 == secret
      assert reconstructed2 == secret
      assert reconstructed3 == secret
    end

    test "fails to reconstruct with fewer than threshold shares" do
      secret = :crypto.strong_rand_bytes(32)

      {:ok, shares} = Shamir.split(secret, 5, 3)

      # Only 2 shares (less than threshold of 3)
      assert {:error, msg} = Shamir.combine(Enum.take(shares, 2))
      assert msg =~ "Not enough shares"
    end

    test "successfully reconstructs with more than threshold shares" do
      secret = :crypto.strong_rand_bytes(32)

      {:ok, shares} = Shamir.split(secret, 5, 3)

      # Use all 5 shares (more than threshold of 3)
      assert {:ok, reconstructed} = Shamir.combine(shares)
      assert reconstructed == secret
    end

    test "each share contains correct metadata" do
      secret = :crypto.strong_rand_bytes(32)
      total = 7
      threshold = 4

      {:ok, shares} = Shamir.split(secret, total, threshold)

      Enum.each(shares, fn share ->
        assert share.threshold == threshold
        assert share.total_shares == total
        assert share.id >= 1 and share.id <= total
        assert is_binary(share.value)
      end)
    end

    test "share IDs are sequential from 1 to N" do
      secret = :crypto.strong_rand_bytes(32)

      {:ok, shares} = Shamir.split(secret, 5, 3)

      ids = Enum.map(shares, & &1.id) |> Enum.sort()
      assert ids == [1, 2, 3, 4, 5]
    end

    test "works with threshold equal to total shares" do
      secret = :crypto.strong_rand_bytes(32)

      {:ok, shares} = Shamir.split(secret, 3, 3)

      # Need all shares
      assert {:ok, reconstructed} = Shamir.combine(shares)
      assert reconstructed == secret

      # Missing one share should fail
      assert {:error, _} = Shamir.combine(Enum.take(shares, 2))
    end

    test "works with threshold of 1 (no splitting really)" do
      secret = :crypto.strong_rand_bytes(32)

      {:ok, shares} = Shamir.split(secret, 5, 1)

      # Any single share should reconstruct
      assert {:ok, reconstructed} = Shamir.combine([Enum.at(shares, 0)])
      assert reconstructed == secret

      assert {:ok, reconstructed} = Shamir.combine([Enum.at(shares, 3)])
      assert reconstructed == secret
    end

    test "rejects invalid parameters - threshold > total" do
      secret = :crypto.strong_rand_bytes(32)

      assert {:error, msg} = Shamir.split(secret, 3, 5)
      assert msg =~ "Threshold cannot exceed total shares"
    end

    test "rejects invalid parameters - too many shares" do
      secret = :crypto.strong_rand_bytes(32)

      assert {:error, msg} = Shamir.split(secret, 252, 3)
      assert msg =~ "Maximum 251 shares"
    end

    test "fails combine with mismatched thresholds" do
      secret = :crypto.strong_rand_bytes(32)

      {:ok, shares1} = Shamir.split(secret, 5, 3)
      {:ok, shares2} = Shamir.split(:crypto.strong_rand_bytes(32), 5, 2)

      mixed = [Enum.at(shares1, 0), Enum.at(shares2, 1), Enum.at(shares1, 2)]

      assert {:error, msg} = Shamir.combine(mixed)
      assert msg =~ "same threshold"
    end

    test "handles empty share list" do
      assert {:error, msg} = Shamir.combine([])
      assert msg =~ "No shares provided"
    end
  end

  describe "valid_share?/1" do
    test "validates correct share structure" do
      share = %{
        version: 4,
        share_set_id: <<0::128>>,
        id: 1,
        value: <<1, 2, 3>>,
        threshold: 3,
        total_shares: 5,
        secret_length: 3
      }

      assert Shamir.valid_share?(share) == true
    end

    test "rejects share with missing fields" do
      invalid = %{id: 1, value: <<1, 2, 3>>}
      assert Shamir.valid_share?(invalid) == false
    end

    test "rejects share with invalid id" do
      invalid = %{id: 0, value: <<1, 2, 3>>, threshold: 3, total_shares: 5}
      assert Shamir.valid_share?(invalid) == false

      invalid = %{id: -1, value: <<1, 2, 3>>, threshold: 3, total_shares: 5}
      assert Shamir.valid_share?(invalid) == false
    end

    test "rejects share with non-binary value" do
      # Test with integer (not a binary)
      invalid = %{id: 1, value: 12_345, threshold: 3, total_shares: 5}
      assert Shamir.valid_share?(invalid) == false

      # Test with list (not a binary)
      invalid = %{id: 1, value: [1, 2, 3], threshold: 3, total_shares: 5}
      assert Shamir.valid_share?(invalid) == false
    end

    test "rejects share with threshold > total" do
      invalid = %{id: 1, value: <<1, 2, 3>>, threshold: 5, total_shares: 3}
      assert Shamir.valid_share?(invalid) == false
    end

    test "rejects non-map input" do
      assert Shamir.valid_share?("not a share") == false
      assert Shamir.valid_share?(nil) == false
      assert Shamir.valid_share?(123) == false
    end
  end

  describe "encode_share/1 and decode_share/1" do
    test "encodes and decodes share correctly" do
      secret = :crypto.strong_rand_bytes(32)
      {:ok, shares} = Shamir.split(secret, 5, 3)

      share = Enum.at(shares, 0)
      encoded = Shamir.encode_share(share)

      assert is_binary(encoded)
      assert String.starts_with?(encoded, "secrethub-share-")

      assert {:ok, decoded} = Shamir.decode_share(encoded)
      assert decoded.id == share.id
      assert decoded.value == share.value
      assert decoded.threshold == share.threshold
      assert decoded.total_shares == share.total_shares
    end

    test "encoded shares are URL-safe base64" do
      secret = :crypto.strong_rand_bytes(32)
      {:ok, shares} = Shamir.split(secret, 5, 3)

      encoded = Shamir.encode_share(Enum.at(shares, 0))

      # Should not contain padding
      refute String.contains?(encoded, "=")
      # Should be safe for URLs
      refute String.contains?(encoded, "+")
      refute String.contains?(encoded, "/")
    end

    test "can reconstruct secret from encoded shares" do
      secret = :crypto.strong_rand_bytes(32)
      {:ok, shares} = Shamir.split(secret, 5, 3)

      # Encode all shares
      encoded_shares = Enum.map(shares, &Shamir.encode_share/1)

      # Decode 3 shares
      decoded_shares =
        encoded_shares
        |> Enum.take(3)
        |> Enum.map(fn enc ->
          {:ok, share} = Shamir.decode_share(enc)
          share
        end)

      # Reconstruct
      assert {:ok, reconstructed} = Shamir.combine(decoded_shares)
      assert reconstructed == secret
    end

    test "rejects invalid encoded share format" do
      assert {:error, msg} = Shamir.decode_share("not-a-share")
      assert msg =~ "must start with 'secrethub-share-'"
    end

    test "rejects malformed base64" do
      assert {:error, _} = Shamir.decode_share("secrethub-share-!!!invalid!!!")
    end

    test "rejects share with invalid prefix" do
      assert {:error, _} = Shamir.decode_share("wrong-prefix-AAAA")
    end
  end

  describe "security properties" do
    test "k-1 shares reveal no information about secret" do
      secret = :crypto.strong_rand_bytes(32)
      {:ok, shares} = Shamir.split(secret, 5, 3)

      # With only 2 shares (threshold is 3), should not be able to reconstruct
      assert {:error, _} = Shamir.combine(Enum.take(shares, 2))
    end

    test "shares are unique" do
      secret = :crypto.strong_rand_bytes(32)
      {:ok, shares} = Shamir.split(secret, 5, 3)

      values = Enum.map(shares, & &1.value)
      assert length(Enum.uniq(values)) == 5
    end

    test "splitting same secret twice produces different shares" do
      secret = :crypto.strong_rand_bytes(32)

      {:ok, shares1} = Shamir.split(secret, 5, 3)
      {:ok, shares2} = Shamir.split(secret, 5, 3)

      # Shares should be different (due to random coefficients)
      assert Enum.at(shares1, 0).value != Enum.at(shares2, 0).value
      assert Enum.at(shares1, 1).value != Enum.at(shares2, 1).value

      # But both should reconstruct to same secret
      assert {:ok, ^secret} = Shamir.combine(Enum.take(shares1, 3))
      assert {:ok, ^secret} = Shamir.combine(Enum.take(shares2, 3))
    end

    test "cannot mix shares from different secrets" do
      secret1 = :crypto.strong_rand_bytes(32)
      secret2 = :crypto.strong_rand_bytes(32)

      {:ok, shares1} = Shamir.split(secret1, 5, 3)
      {:ok, shares2} = Shamir.split(secret2, 5, 3)

      # Mix shares from different secrets
      mixed = [Enum.at(shares1, 0), Enum.at(shares2, 1), Enum.at(shares1, 2)]

      assert {:error, _} = Shamir.combine(mixed)
    end
  end

  describe "edge cases" do
    test "handles maximum shares (251)" do
      secret = :crypto.strong_rand_bytes(32)

      assert {:ok, shares} = Shamir.split(secret, 251, 3)
      assert length(shares) == 251

      assert {:ok, reconstructed} = Shamir.combine(Enum.take(shares, 3))
      assert reconstructed == secret
    end

    test "handles small secrets (16 bytes)" do
      secret = :crypto.strong_rand_bytes(16)

      {:ok, shares} = Shamir.split(secret, 5, 3)
      {:ok, reconstructed} = Shamir.combine(Enum.take(shares, 3))

      assert reconstructed == secret
    end

    test "handles large secrets (1KB)" do
      secret = :crypto.strong_rand_bytes(1024)

      {:ok, shares} = Shamir.split(secret, 5, 3)
      {:ok, reconstructed} = Shamir.combine(Enum.take(shares, 3))

      assert reconstructed == secret
    end

    test "handles secret with all zero bytes" do
      secret = <<0::256>>

      {:ok, shares} = Shamir.split(secret, 5, 3)
      {:ok, reconstructed} = Shamir.combine(Enum.take(shares, 3))

      assert reconstructed == secret
    end

    test "handles secret with all one bytes" do
      secret =
        <<255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
          255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255>>

      {:ok, shares} = Shamir.split(secret, 5, 3)
      {:ok, reconstructed} = Shamir.combine(Enum.take(shares, 3))

      assert reconstructed == secret
    end

    test "duplicate shares are handled correctly" do
      secret = :crypto.strong_rand_bytes(32)
      {:ok, shares} = Shamir.split(secret, 5, 3)

      # Use same share twice plus one different share
      duplicated = [Enum.at(shares, 0), Enum.at(shares, 0), Enum.at(shares, 1)]

      assert {:error, _} = Shamir.combine(duplicated)
    end
  end

  describe "v4 finite-field and envelope regressions" do
    test "all byte values survive every three-of-five threshold subset" do
      secret = :binary.list_to_bin(Enum.to_list(0..255))
      assert {:ok, shares} = Shamir.split(secret, 5, 3)

      for [a, b, c] <- subsets(shares, 3) do
        assert {:ok, ^secret} = Shamir.combine([a, b, c])
      end
    end

    test "random 32-byte keys survive threshold subsets and encoded round trips" do
      for _ <- 1..25, threshold <- 1..5 do
        secret = :crypto.strong_rand_bytes(32)
        assert {:ok, shares} = Shamir.split(secret, 5, threshold)
        assert {:ok, ^secret} = Shamir.combine(Enum.take_random(shares, threshold))

        decoded =
          Enum.map(shares, fn share ->
            assert {:ok, ^share} = Shamir.decode_share(Shamir.encode_share(share))
            share
          end)

        assert {:ok, ^secret} = Shamir.combine(decoded)
      end
    end

    test "independent AES-field vectors include the old maximum coordinate 251" do
      secret = <<0, 1, 250, 251, 252, 253, 254, 255>>

      vectors = [
        {1, "9998050403020100"},
        {2, "a3d92b2c21261d1a"},
        {3, "3a40d4d3ded9e2e5"},
        {17, "8590cfc5dfd56369"},
        {250, "47ee1fe6f20b3bc2"},
        {251, "de77e0190df4c43d"}
      ]

      shares =
        Enum.map(vectors, fn {id, hex} ->
          vector_share(id, Base.decode16!(hex, case: :lower))
        end)

      for subset <- subsets(shares, 3) do
        assert {:ok, ^secret} = Shamir.combine(subset)
      end

      assert {:ok, ^secret} = Shamir.combine(shares)
      refute List.last(shares).value == secret
    end

    test "split evaluations agree with independent carryless polynomial reduction" do
      secret = :binary.list_to_bin(Enum.to_list(0..255))
      assert {:ok, [first | _] = shares} = Shamir.split(secret, 251, 2)
      coefficients = xor_bytes(secret, first.value)

      for share <- shares do
        expected =
          for {byte, coefficient} <- Enum.zip(:binary.bin_to_list(secret), coefficients),
              into: <<>>,
              do: <<Bitwise.bxor(byte, reference_multiply(coefficient, share.id))>>

        assert share.value == expected
      end

      assert {:ok, ^secret} = Shamir.combine(Enum.take(shares, -2))
    end

    test "linear coefficients use the full byte space including zero without modulo bias" do
      coefficients =
        for _ <- 1..8 do
          assert {:ok, [share]} = Shamir.split(<<0::4096-unit(8)>>, 1, 1)
          assert share.value == <<0::4096-unit(8)>>
          assert {:ok, [first, _]} = Shamir.split(<<0::4096-unit(8)>>, 2, 2)
          :binary.bin_to_list(first.value)
        end
        |> List.flatten()
        |> Enum.frequencies()

      assert map_size(coefficients) == 256
      # Expected count is 128. These broad bounds catch the old modulo-251
      # sampling while making a random false failure negligibly unlikely.
      assert Enum.all?(coefficients, fn {_byte, count} -> count in 48..224 end)
    end

    test "split binds each share to a fresh or caller supplied 16-byte generation" do
      generation = <<42::128>>
      assert {:ok, shares} = Shamir.split(<<251, 255>>, 3, 2, generation)
      assert Enum.all?(shares, &(&1.version == 4 and &1.share_set_id == generation))
      assert Enum.all?(shares, &(not Map.has_key?(&1, :adjustment_mask)))
      assert {:ok, [other | _]} = Shamir.split(<<251, 255>>, 3, 2)
      refute other.share_set_id == generation
      assert byte_size(other.share_set_id) == 16
      assert {:error, _} = Shamir.split(<<1>>, 3, 2, <<1>>)
    end

    test "v4 wire format has exact lengths and preserves the complete envelope" do
      share = vector_share(251, <<251, 255>>)
      blob = <<4, 251, 3, 251, 2::16, 42::128, 251, 255>>
      encoded = wire(blob)
      assert Shamir.encode_share(share) == encoded
      assert {:ok, ^share} = Shamir.decode_share(encoded)
    end

    test "rejects empty oversized and noninteger split parameters" do
      for args <- [
            {<<>>, 3, 2},
            {:binary.copy(<<1>>, 4097), 3, 2},
            {<<1>>, 3.0, 2},
            {<<1>>, 3, 2.0},
            {nil, 3, 2},
            {<<1>>, 0, 0},
            {<<1>>, 3, 0},
            {<<1>>, 3, -1}
          ] do
        assert {:error, _} = apply(Shamir, :split, Tuple.to_list(args))
      end
    end

    test "rejects every malformed envelope field before interpolation" do
      valid = vector_share(1, <<1, 2>>)

      changes = [
        version: 3,
        version: 5,
        share_set_id: <<1>>,
        id: 0,
        id: -1,
        id: 252,
        id: 255,
        id: 256,
        id: 1.0,
        total_shares: 252,
        total_shares: 0,
        threshold: 0,
        threshold: 252,
        secret_length: 0,
        secret_length: 4097,
        secret_length: 1,
        value: <<1>>,
        value: nil,
        value: :binary.copy(<<1>>, 4097)
      ]

      for {field, value} <- changes do
        invalid = Map.put(valid, field, value)
        refute Shamir.valid_share?(invalid)
        assert {:error, _} = Shamir.combine([invalid])
        assert {:error, _} = Shamir.encode_share(invalid)
      end

      for field <- Map.keys(valid) do
        invalid = Map.delete(valid, field)
        refute Shamir.valid_share?(invalid)
        assert {:error, _} = Shamir.combine([invalid])
      end

      for input <- [nil, 1, %{}, "bad", [nil], [valid, nil]] do
        assert {:error, _} = Shamir.combine(input)
      end
    end

    test "rejects conflicting metadata mixed generations and duplicate coordinates" do
      assert {:ok, [a, b, c | _]} = Shamir.split(<<1, 2>>, 5, 3)

      for changed <- [
            %{b | share_set_id: <<99::128>>},
            %{b | total_shares: 6},
            %{b | threshold: 2},
            %{b | secret_length: 1, value: <<1>>},
            %{b | id: a.id}
          ] do
        assert {:error, _} = Shamir.combine([a, changed, c])
      end
    end

    test "truncated oversized invalid and unsupported encoded input never raises" do
      blob = <<4, 1, 2, 3, 2::16, 42::128, 1, 2>>

      for length <- 0..(byte_size(blob) - 1) do
        assert {:error, _} = Shamir.decode_share(wire(binary_part(blob, 0, length)))
      end

      for bad <- [
            blob <> <<0>>,
            <<4, 1, 2, 3, 4097::16, 42::128>>,
            <<4, 0, 2, 3, 2::16, 42::128, 1, 2>>,
            <<4, 252, 2, 252, 2::16, 42::128, 1, 2>>,
            <<5, 0>>
          ] do
        assert {:error, _} = Shamir.decode_share(wire(bad))
      end

      for input <- [
            nil,
            42,
            "secrethub-share-%%%",
            "secrethub-share-_",
            "secrethub-share-" <> String.duplicate("A", 6000)
          ] do
        assert {:error, _} = Shamir.decode_share(input)
      end
    end

    test "rejects padding appended to otherwise valid unpadded base64" do
      share = vector_share(1, <<0>>)
      encoded = Shamir.encode_share(share)
      assert {:ok, ^share} = Shamir.decode_share(encoded)
      assert {:error, "Invalid share format"} = Shamir.decode_share(encoded <> "=")
    end

    test "rejects noncanonical discarded base64 pad bits" do
      share = vector_share(1, <<0>>)
      encoded = Shamir.encode_share(share)
      assert String.ends_with?(encoded, "A")
      noncanonical = binary_part(encoded, 0, byte_size(encoded) - 1) <> "B"
      assert {:ok, ^share} = Shamir.decode_share(encoded)
      assert {:error, "Invalid share format"} = Shamir.decode_share(noncanonical)
    end

    test "legacy versions fail closed with a recovery blocking explanation" do
      for version <- 1..3 do
        assert {:error, message} = Shamir.decode_share(wire(<<version, 1, 2, 3, 2, 255>>))
        assert message =~ "Legacy"
        assert message =~ "recovery"
      end
    end
  end

  defp vector_share(id, value) do
    %{
      version: 4,
      share_set_id: <<42::128>>,
      id: id,
      value: value,
      threshold: 3,
      total_shares: 251,
      secret_length: byte_size(value)
    }
  end

  defp wire(blob), do: "secrethub-share-" <> Base.url_encode64(blob, padding: false)

  defp subsets(_items, 0), do: [[]]
  defp subsets([], _count), do: []

  defp subsets([item | rest], count),
    do: Enum.map(subsets(rest, count - 1), &[item | &1]) ++ subsets(rest, count)

  defp xor_bytes(left, right),
    do: Enum.zip_with(:binary.bin_to_list(left), :binary.bin_to_list(right), &Bitwise.bxor/2)

  # Independent reference: carryless polynomial convolution followed by long
  # division, rather than the production shift-and-add multiplication.
  defp reference_multiply(a, b) do
    product =
      for i <- 0..7, j <- 0..7, reduce: 0 do
        acc ->
          if Bitwise.band(Bitwise.bsr(a, i), 1) == 1 and
               Bitwise.band(Bitwise.bsr(b, j), 1) == 1,
             do: Bitwise.bxor(acc, Bitwise.bsl(1, i + j)),
             else: acc
      end

    Enum.reduce(14..8//-1, product, fn bit, acc ->
      if Bitwise.band(Bitwise.bsr(acc, bit), 1) == 1,
        do: Bitwise.bxor(acc, Bitwise.bsl(0x11B, bit - 8)),
        else: acc
    end)
  end
end
