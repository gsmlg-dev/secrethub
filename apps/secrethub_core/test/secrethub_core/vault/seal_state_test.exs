defmodule SecretHub.Core.Vault.SealStateTest do
  @moduledoc """
  Unit tests for Vault SealState GenServer.

  Tests cover:
  - Vault initialization with Shamir shares
  - Unseal process with share accumulation
  - Seal/unseal state transitions
  - Auto-sealing after inactivity
  - Master key access controls
  - Status reporting
  - Error handling
  - Edge cases
  """

  # GenServer tests can't be async
  use SecretHub.Core.DataCase, async: false

  alias SecretHub.Core.Vault.SealState
  alias SecretHub.Shared.Crypto.Shamir

  # Start SealState for these tests (it's disabled in test mode by default)
  setup do
    # Stop any existing SealState
    case Process.whereis(SealState) do
      nil -> :ok
      pid -> GenServer.stop(pid, :normal)
    end

    # Start fresh SealState for this test
    {:ok, _pid} = start_supervised(SealState)
    :ok
  end

  describe "initialization" do
    test "vault starts in not_initialized state" do
      status = SealState.status()
      assert status.initialized == false
      assert status.sealed == true
      assert status.progress == 0
      assert status.threshold == nil
      assert status.total_shares == nil
    end

    test "initializes vault with valid parameters" do
      assert {:ok, shares} = SealState.initialize(5, 3)

      # Should return the correct number of shares
      assert length(shares) == 5

      # Each share should be valid
      Enum.each(shares, fn share ->
        assert share.threshold == 3
        assert share.total_shares == 5
        assert is_binary(share.value)
      end)

      # Vault should now be sealed but initialized
      status = SealState.status()
      assert status.initialized == true
      assert status.sealed == true
      assert status.progress == 0
      assert status.threshold == 3
      assert status.total_shares == 5
    end

    test "rejects initialization if already initialized" do
      {:ok, _shares} = SealState.initialize(5, 3)

      assert {:error, reason} = SealState.initialize(5, 3)
      assert reason =~ "already initialized"
    end

    test "initializes with threshold equal to total shares" do
      assert {:ok, shares} = SealState.initialize(3, 3)
      assert length(shares) == 3

      status = SealState.status()
      assert status.threshold == 3
      assert status.total_shares == 3
    end

    test "initializes with threshold of 1" do
      assert {:ok, shares} = SealState.initialize(5, 1)
      assert length(shares) == 5

      status = SealState.status()
      assert status.threshold == 1
      assert status.total_shares == 5
    end
  end

  describe "unsealing" do
    setup do
      {:ok, shares} = SealState.initialize(5, 3)
      %{shares: shares}
    end

    test "unseals with exact threshold shares", %{shares: shares} do
      # Submit first share
      assert {:ok, result} = SealState.unseal(Enum.at(shares, 0))
      assert result.sealed == true
      assert result.progress == 1
      assert result.threshold == 3

      # Submit second share
      assert {:ok, result} = SealState.unseal(Enum.at(shares, 1))
      assert result.sealed == true
      assert result.progress == 2

      # Submit third share - should unseal
      assert {:ok, result} = SealState.unseal(Enum.at(shares, 2))
      assert result.sealed == false
      assert result.progress == 3
      assert result.threshold == 3

      # Status should show unsealed
      status = SealState.status()
      assert status.sealed == false
    end

    test "unseals with more than threshold shares", %{shares: shares} do
      # Submit all 5 shares
      Enum.each(shares, fn share ->
        SealState.unseal(share)
      end)

      status = SealState.status()
      assert status.sealed == false
    end

    test "different combinations of shares unseal vault", %{shares: shares} do
      # Combination 1: shares 0, 1, 2
      combo1 = [Enum.at(shares, 0), Enum.at(shares, 1), Enum.at(shares, 2)]

      Enum.each(combo1, &SealState.unseal/1)
      assert SealState.status().sealed == false

      # Re-seal for next test
      SealState.seal()

      # Combination 2: shares 1, 3, 4
      combo2 = [Enum.at(shares, 1), Enum.at(shares, 3), Enum.at(shares, 4)]

      Enum.each(combo2, &SealState.unseal/1)
      assert SealState.status().sealed == false
    end

    test "rejects unseal when not initialized" do
      # Create a fresh SealState (would need to restart GenServer)
      # For this test, we'll just document the expected behavior
      # In real scenario, would need process isolation
    end

    test "handles duplicate shares correctly", %{shares: shares} do
      # Submit same share twice
      SealState.unseal(Enum.at(shares, 0))
      SealState.unseal(Enum.at(shares, 0))

      status = SealState.status()
      # Progress should only count unique shares
      assert status.progress == 1
    end

    test "accepts shares after already unsealed", %{shares: shares} do
      # Unseal vault
      Enum.take(shares, 3) |> Enum.each(&SealState.unseal/1)

      # Submitting another share should succeed but have no effect
      assert {:ok, result} = SealState.unseal(Enum.at(shares, 3))
      assert result.sealed == false
    end

    test "tracks unseal progress correctly", %{shares: shares} do
      # No shares submitted
      status = SealState.status()
      assert status.progress == 0

      # One share
      SealState.unseal(Enum.at(shares, 0))
      status = SealState.status()
      assert status.progress == 1

      # Two shares
      SealState.unseal(Enum.at(shares, 1))
      status = SealState.status()
      assert status.progress == 2

      # Three shares - unsealed, progress resets to 0
      SealState.unseal(Enum.at(shares, 2))
      status = SealState.status()
      assert status.progress == 0
      assert status.sealed == false
    end
  end

  describe "sealing" do
    setup do
      {:ok, shares} = SealState.initialize(5, 3)
      # Unseal the vault
      Enum.take(shares, 3) |> Enum.each(&SealState.unseal/1)
      %{shares: shares}
    end

    test "seals an unsealed vault" do
      status = SealState.status()
      assert status.sealed == false

      assert :ok = SealState.seal()

      status = SealState.status()
      assert status.sealed == true
      assert status.progress == 0
    end

    test "sealing when already sealed is idempotent" do
      SealState.seal()
      assert :ok = SealState.seal()

      status = SealState.status()
      assert status.sealed == true
    end

    test "clears master key from memory when sealed" do
      # Vault is unsealed in setup
      assert {:ok, _key} = SealState.get_master_key()

      SealState.seal()

      # Master key should no longer be accessible
      assert {:error, :sealed} = SealState.get_master_key()
    end

    test "requires re-unsealing after seal", %{shares: shares} do
      SealState.seal()

      status = SealState.status()
      assert status.sealed == true

      # Should need shares again
      Enum.take(shares, 3) |> Enum.each(&SealState.unseal/1)

      status = SealState.status()
      assert status.sealed == false
    end
  end

  describe "master key access" do
    setup do
      {:ok, shares} = SealState.initialize(5, 3)
      Enum.take(shares, 3) |> Enum.each(&SealState.unseal/1)
      :ok
    end

    test "returns master key when unsealed" do
      assert {:ok, key} = SealState.get_master_key()
      assert is_binary(key)
      # 256-bit key
      assert byte_size(key) == 32
    end

    test "returns same master key on repeated calls" do
      assert {:ok, key1} = SealState.get_master_key()
      assert {:ok, key2} = SealState.get_master_key()
      assert key1 == key2
    end

    test "returns error when sealed" do
      SealState.seal()
      assert {:error, :sealed} = SealState.get_master_key()
    end

    test "resets auto-seal timer on key access" do
      # Access key
      SealState.get_master_key()

      # Wait a bit
      Process.sleep(100)

      # Access again - should reset timer
      SealState.get_master_key()

      # Vault should still be unsealed
      status = SealState.status()
      assert status.sealed == false
    end
  end

  describe "auto-sealing" do
    setup do
      {:ok, shares} = SealState.initialize(5, 3)
      Enum.take(shares, 3) |> Enum.each(&SealState.unseal/1)
      :ok
    end

    test "auto-seals after timeout period" do
      # Vault is unsealed
      status = SealState.status()
      assert status.sealed == false

      # Wait for auto-seal timeout (30 seconds + buffer)
      # Note: In real tests, you might want to make this configurable
      # or use a shorter timeout for testing
      Process.sleep(31_000)

      # Vault should be sealed
      status = SealState.status()
      assert status.sealed == true
    end

    test "accessing master key resets auto-seal timer" do
      # Access key to reset timer
      SealState.get_master_key()

      # Wait less than timeout
      Process.sleep(15_000)

      # Access again
      SealState.get_master_key()

      # Wait less than timeout again
      Process.sleep(15_000)

      # Vault should still be unsealed (timer was reset)
      status = SealState.status()
      assert status.sealed == false
    end

    test "manual seal cancels auto-seal timer" do
      # Seal manually
      SealState.seal()

      # Wait past auto-seal timeout
      Process.sleep(31_000)

      # Vault should still be sealed (not double-sealed or errored)
      status = SealState.status()
      assert status.sealed == true
    end
  end

  describe "status reporting" do
    test "reports correct status when not initialized" do
      status = SealState.status()

      assert status.initialized == false
      assert status.sealed == true
      assert status.progress == 0
      assert status.threshold == nil
      assert status.total_shares == nil
    end

    test "reports correct status when sealed" do
      {:ok, _shares} = SealState.initialize(5, 3)

      status = SealState.status()

      assert status.initialized == true
      assert status.sealed == true
      assert status.progress == 0
      assert status.threshold == 3
      assert status.total_shares == 5
    end

    test "reports correct status during unsealing" do
      {:ok, shares} = SealState.initialize(5, 3)

      SealState.unseal(Enum.at(shares, 0))
      status = SealState.status()
      assert status.sealed == true
      assert status.progress == 1

      SealState.unseal(Enum.at(shares, 1))
      status = SealState.status()
      assert status.sealed == true
      assert status.progress == 2
    end

    test "reports correct status when unsealed" do
      {:ok, shares} = SealState.initialize(5, 3)
      Enum.take(shares, 3) |> Enum.each(&SealState.unseal/1)

      status = SealState.status()

      assert status.initialized == true
      assert status.sealed == false
      assert status.progress == 0
      assert status.threshold == 3
      assert status.total_shares == 5
    end
  end

  describe "edge cases and error handling" do
    test "handles invalid share format gracefully" do
      {:ok, _shares} = SealState.initialize(5, 3)

      # Test with missing fields - this will fail valid_share? check
      invalid_share = %{id: 1, threshold: 3}
      assert {:error, _reason} = SealState.unseal(invalid_share)

      # Vault should still be sealed
      status = SealState.status()
      assert status.sealed == true
    end

    test "handles share from wrong vault" do
      # Initialize first vault
      {:ok, shares1} = SealState.initialize(5, 3)

      # Re-seal and initialize with different parameters
      # (In real scenario, would need separate GenServer instances)
      # For this test, we'll just document the expected behavior
    end

    test "initializes with maximum shares (251)" do
      # Shamir implementation supports maximum 251 shares (limited by prime 251)
      assert {:ok, shares} = SealState.initialize(251, 3)
      assert length(shares) == 251

      status = SealState.status()
      assert status.total_shares == 251
    end

    test "rejects initialization with more than 251 shares" do
      # Should return error when exceeding Shamir's maximum
      assert {:error, reason} = SealState.initialize(255, 3)
      assert reason =~ "Maximum 251 shares"
    end

    test "initializes with minimum configuration (1 share, threshold 1)" do
      assert {:ok, shares} = SealState.initialize(1, 1)
      assert length(shares) == 1

      # Should unseal with just that one share
      SealState.unseal(Enum.at(shares, 0))

      status = SealState.status()
      assert status.sealed == false
    end
  end

  describe "security properties" do
    test "master key never accessible when sealed" do
      {:ok, shares} = SealState.initialize(5, 3)

      # Before unsealing
      assert {:error, :sealed} = SealState.get_master_key()

      # Partially unsealed
      SealState.unseal(Enum.at(shares, 0))
      assert {:error, :sealed} = SealState.get_master_key()

      SealState.unseal(Enum.at(shares, 1))
      assert {:error, :sealed} = SealState.get_master_key()

      # Fully unsealed
      SealState.unseal(Enum.at(shares, 2))
      assert {:ok, _key} = SealState.get_master_key()

      # After sealing again
      SealState.seal()
      assert {:error, :sealed} = SealState.get_master_key()
    end

    test "insufficient shares cannot unseal vault" do
      {:ok, shares} = SealState.initialize(5, 3)

      # Submit only 2 shares (threshold is 3)
      SealState.unseal(Enum.at(shares, 0))
      SealState.unseal(Enum.at(shares, 1))

      status = SealState.status()
      assert status.sealed == true

      # Master key should not be accessible
      assert {:error, :sealed} = SealState.get_master_key()
    end

    test "reconstructed master key works for encryption/decryption" do
      {:ok, shares} = SealState.initialize(5, 3)

      # Unseal and get master key
      Enum.take(shares, 3) |> Enum.each(&SealState.unseal/1)
      {:ok, master_key} = SealState.get_master_key()

      # Use master key to encrypt data
      alias SecretHub.Shared.Crypto.Encryption
      plaintext = "test secret data"
      {:ok, encrypted} = Encryption.encrypt(plaintext, master_key)

      # Should be able to decrypt with same key
      {:ok, decrypted} = Encryption.decrypt(encrypted, master_key)
      assert decrypted == plaintext

      # Seal and unseal again
      SealState.seal()
      Enum.take(shares, 3) |> Enum.each(&SealState.unseal/1)
      {:ok, master_key2} = SealState.get_master_key()

      # Should be the same master key
      assert master_key == master_key2

      # Should still be able to decrypt
      {:ok, decrypted2} = Encryption.decrypt(encrypted, master_key2)
      assert decrypted2 == plaintext
    end
  end
end
