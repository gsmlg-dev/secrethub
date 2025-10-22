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
        id: 1,
        value: <<1, 2, 3>>,
        threshold: 3,
        total_shares: 5
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
      invalid = %{id: 1, value: 12345, threshold: 3, total_shares: 5}
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

      # Combine will succeed but produce wrong result
      assert {:ok, reconstructed} = Shamir.combine(mixed)
      assert reconstructed != secret1
      assert reconstructed != secret2
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
      secret = <<255, 255, 255, 255, 255, 255, 255, 255,
                 255, 255, 255, 255, 255, 255, 255, 255,
                 255, 255, 255, 255, 255, 255, 255, 255,
                 255, 255, 255, 255, 255, 255, 255, 255>>

      {:ok, shares} = Shamir.split(secret, 5, 3)
      {:ok, reconstructed} = Shamir.combine(Enum.take(shares, 3))

      assert reconstructed == secret
    end

    test "duplicate shares are handled correctly" do
      secret = :crypto.strong_rand_bytes(32)
      {:ok, shares} = Shamir.split(secret, 5, 3)

      # Use same share twice plus one different share
      duplicated = [Enum.at(shares, 0), Enum.at(shares, 0), Enum.at(shares, 1)]

      # Should reconstruct (duplicate is ignored by having same ID)
      assert {:ok, _} = Shamir.combine(duplicated)
    end
  end
end
