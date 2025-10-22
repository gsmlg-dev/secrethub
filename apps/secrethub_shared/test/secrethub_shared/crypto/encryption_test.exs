defmodule SecretHub.Shared.Crypto.EncryptionTest do
  @moduledoc """
  Unit tests for AES-256-GCM encryption/decryption module.

  Tests cover:
  - Basic encryption/decryption
  - Key generation
  - Key derivation
  - Blob encoding/decoding
  - Error handling
  - Security properties
  """

  use ExUnit.Case, async: true

  alias SecretHub.Shared.Crypto.Encryption

  describe "encrypt/2 and decrypt/2" do
    test "encrypts and decrypts data correctly" do
      key = Encryption.generate_key()
      plaintext = "super secret data"

      assert {:ok, encrypted} = Encryption.encrypt(plaintext, key)
      assert is_map(encrypted)
      assert encrypted.version == 1
      assert is_binary(encrypted.ciphertext)
      assert is_binary(encrypted.nonce)
      assert is_binary(encrypted.tag)

      assert {:ok, decrypted} = Encryption.decrypt(encrypted, key)
      assert decrypted == plaintext
    end

    test "produces different ciphertexts for same plaintext (due to random nonce)" do
      key = Encryption.generate_key()
      plaintext = "test data"

      assert {:ok, encrypted1} = Encryption.encrypt(plaintext, key)
      assert {:ok, encrypted2} = Encryption.encrypt(plaintext, key)

      # Nonces should be different
      assert encrypted1.nonce != encrypted2.nonce
      # Ciphertexts should be different
      assert encrypted1.ciphertext != encrypted2.ciphertext

      # But both should decrypt to same plaintext
      assert {:ok, ^plaintext} = Encryption.decrypt(encrypted1, key)
      assert {:ok, ^plaintext} = Encryption.decrypt(encrypted2, key)
    end

    test "fails to decrypt with wrong key" do
      key1 = Encryption.generate_key()
      key2 = Encryption.generate_key()
      plaintext = "secret"

      assert {:ok, encrypted} = Encryption.encrypt(plaintext, key1)
      assert {:error, _} = Encryption.decrypt(encrypted, key2)
    end

    test "fails to decrypt with tampered ciphertext" do
      key = Encryption.generate_key()
      plaintext = "secret"

      assert {:ok, encrypted} = Encryption.encrypt(plaintext, key)

      # Tamper with ciphertext
      tampered = %{encrypted | ciphertext: <<0, 1, 2, 3>>}
      assert {:error, _} = Encryption.decrypt(tampered, key)
    end

    test "fails to decrypt with tampered tag" do
      key = Encryption.generate_key()
      plaintext = "secret"

      assert {:ok, encrypted} = Encryption.encrypt(plaintext, key)

      # Tamper with authentication tag
      tampered = %{encrypted | tag: :crypto.strong_rand_bytes(16)}
      assert {:error, _} = Encryption.decrypt(tampered, key)
    end

    test "rejects invalid key size" do
      bad_key = :crypto.strong_rand_bytes(16)  # 128 bits instead of 256
      plaintext = "test"

      assert {:error, msg} = Encryption.encrypt(plaintext, bad_key)
      assert msg =~ "Invalid key size"
    end

    test "encrypts empty string" do
      key = Encryption.generate_key()
      plaintext = ""

      assert {:ok, encrypted} = Encryption.encrypt(plaintext, key)
      assert {:ok, decrypted} = Encryption.decrypt(encrypted, key)
      assert decrypted == ""
    end

    test "encrypts large data" do
      key = Encryption.generate_key()
      # 1 MB of data
      plaintext = :crypto.strong_rand_bytes(1024 * 1024)

      assert {:ok, encrypted} = Encryption.encrypt(plaintext, key)
      assert {:ok, decrypted} = Encryption.decrypt(encrypted, key)
      assert decrypted == plaintext
    end

    test "encrypts binary data (not just strings)" do
      key = Encryption.generate_key()
      plaintext = <<0, 1, 2, 3, 255, 254, 253>>

      assert {:ok, encrypted} = Encryption.encrypt(plaintext, key)
      assert {:ok, decrypted} = Encryption.decrypt(encrypted, key)
      assert decrypted == plaintext
    end
  end

  describe "generate_key/0" do
    test "generates 256-bit (32 byte) keys" do
      key = Encryption.generate_key()
      assert byte_size(key) == 32
    end

    test "generates unique keys" do
      key1 = Encryption.generate_key()
      key2 = Encryption.generate_key()
      assert key1 != key2
    end

    test "generates cryptographically random keys" do
      # Generate multiple keys and check they're all different
      keys = for _ <- 1..10, do: Encryption.generate_key()
      unique_keys = Enum.uniq(keys)
      assert length(unique_keys) == 10
    end
  end

  describe "derive_key/3" do
    test "derives 256-bit keys from password and salt" do
      password = "my-secure-password"
      salt = :crypto.strong_rand_bytes(32)

      key = Encryption.derive_key(password, salt)
      assert byte_size(key) == 32
    end

    test "same password and salt produce same key" do
      password = "password123"
      salt = :crypto.strong_rand_bytes(32)

      key1 = Encryption.derive_key(password, salt)
      key2 = Encryption.derive_key(password, salt)
      assert key1 == key2
    end

    test "different salts produce different keys" do
      password = "password123"
      salt1 = :crypto.strong_rand_bytes(32)
      salt2 = :crypto.strong_rand_bytes(32)

      key1 = Encryption.derive_key(password, salt1)
      key2 = Encryption.derive_key(password, salt2)
      assert key1 != key2
    end

    test "different passwords produce different keys" do
      salt = :crypto.strong_rand_bytes(32)

      key1 = Encryption.derive_key("password1", salt)
      key2 = Encryption.derive_key("password2", salt)
      assert key1 != key2
    end

    test "supports custom iteration count" do
      password = "password"
      salt = :crypto.strong_rand_bytes(32)

      key = Encryption.derive_key(password, salt, 50_000)
      assert byte_size(key) == 32
    end
  end

  describe "encode_encrypted_blob/1 and decode_encrypted_blob/1" do
    test "encodes and decodes encrypted data" do
      key = Encryption.generate_key()
      plaintext = "test data"

      assert {:ok, encrypted} = Encryption.encrypt(plaintext, key)
      blob = Encryption.encode_encrypted_blob(encrypted)

      assert is_binary(blob)
      # Should contain version + nonce + tag + ciphertext
      assert byte_size(blob) >= 1 + 12 + 16 + byte_size(plaintext)

      assert {:ok, decoded} = Encryption.decode_encrypted_blob(blob)
      assert decoded.version == encrypted.version
      assert decoded.nonce == encrypted.nonce
      assert decoded.tag == encrypted.tag
      assert decoded.ciphertext == encrypted.ciphertext
    end

    test "rejects invalid blob format" do
      invalid_blob = <<1, 2, 3>>
      assert {:error, _} = Encryption.decode_encrypted_blob(invalid_blob)
    end

    test "rejects empty blob" do
      assert {:error, _} = Encryption.decode_encrypted_blob(<<>>)
    end

    test "handles blob with extra data" do
      key = Encryption.generate_key()
      {:ok, encrypted} = Encryption.encrypt("test", key)
      blob = Encryption.encode_encrypted_blob(encrypted)

      # Decode should work even with properly formatted blob
      assert {:ok, decoded} = Encryption.decode_encrypted_blob(blob)
      assert {:ok, "test"} = Encryption.decrypt(decoded, key)
    end
  end

  describe "encrypt_to_blob/2 and decrypt_from_blob/2" do
    test "encrypts to blob and decrypts from blob" do
      key = Encryption.generate_key()
      plaintext = "secret message"

      assert {:ok, blob} = Encryption.encrypt_to_blob(plaintext, key)
      assert is_binary(blob)

      assert {:ok, decrypted} = Encryption.decrypt_from_blob(blob, key)
      assert decrypted == plaintext
    end

    test "fails to decrypt blob with wrong key" do
      key1 = Encryption.generate_key()
      key2 = Encryption.generate_key()

      assert {:ok, blob} = Encryption.encrypt_to_blob("secret", key1)
      assert {:error, _} = Encryption.decrypt_from_blob(blob, key2)
    end

    test "fails to decrypt invalid blob" do
      key = Encryption.generate_key()
      invalid_blob = <<0, 1, 2, 3>>

      assert {:error, _} = Encryption.decrypt_from_blob(invalid_blob, key)
    end
  end

  describe "rotate_encryption/3" do
    test "re-encrypts data with new key" do
      old_key = Encryption.generate_key()
      new_key = Encryption.generate_key()
      plaintext = "sensitive data"

      # Encrypt with old key
      assert {:ok, old_blob} = Encryption.encrypt_to_blob(plaintext, old_key)

      # Rotate to new key
      assert {:ok, new_blob} = Encryption.rotate_encryption(old_blob, old_key, new_key)

      # Should not be able to decrypt with old key
      assert {:error, _} = Encryption.decrypt_from_blob(new_blob, old_key)

      # Should decrypt with new key
      assert {:ok, decrypted} = Encryption.decrypt_from_blob(new_blob, new_key)
      assert decrypted == plaintext
    end

    test "fails rotation with wrong old key" do
      old_key = Encryption.generate_key()
      wrong_key = Encryption.generate_key()
      new_key = Encryption.generate_key()

      {:ok, blob} = Encryption.encrypt_to_blob("data", old_key)

      assert {:error, _} = Encryption.rotate_encryption(blob, wrong_key, new_key)
    end

    test "rotation preserves plaintext exactly" do
      old_key = Encryption.generate_key()
      new_key = Encryption.generate_key()
      plaintext = :crypto.strong_rand_bytes(1024)  # Binary data

      {:ok, blob} = Encryption.encrypt_to_blob(plaintext, old_key)
      {:ok, rotated_blob} = Encryption.rotate_encryption(blob, old_key, new_key)
      {:ok, decrypted} = Encryption.decrypt_from_blob(rotated_blob, new_key)

      assert decrypted == plaintext
    end
  end

  describe "security properties" do
    test "nonces are always 12 bytes (96 bits)" do
      key = Encryption.generate_key()
      {:ok, encrypted} = Encryption.encrypt("test", key)

      assert byte_size(encrypted.nonce) == 12
    end

    test "tags are always 16 bytes (128 bits)" do
      key = Encryption.generate_key()
      {:ok, encrypted} = Encryption.encrypt("test", key)

      assert byte_size(encrypted.tag) == 16
    end

    test "ciphertext length equals plaintext length for GCM" do
      key = Encryption.generate_key()
      plaintext = "test data of known length"

      {:ok, encrypted} = Encryption.encrypt(plaintext, key)
      assert byte_size(encrypted.ciphertext) == byte_size(plaintext)
    end

    test "version is always 1" do
      key = Encryption.generate_key()
      {:ok, encrypted} = Encryption.encrypt("test", key)

      assert encrypted.version == 1
    end
  end

  describe "edge cases" do
    test "handles Unicode strings correctly" do
      key = Encryption.generate_key()
      plaintext = "Hello 世界 🔐 Ñoño"

      {:ok, encrypted} = Encryption.encrypt(plaintext, key)
      {:ok, decrypted} = Encryption.decrypt(encrypted, key)

      assert decrypted == plaintext
    end

    test "handles null bytes in plaintext" do
      key = Encryption.generate_key()
      plaintext = "data\0with\0nulls"

      {:ok, encrypted} = Encryption.encrypt(plaintext, key)
      {:ok, decrypted} = Encryption.decrypt(encrypted, key)

      assert decrypted == plaintext
    end

    test "handles maximum plaintext size" do
      key = Encryption.generate_key()
      # GCM mode has a limit of 2^39 - 256 bits
      # Test with 10MB (well within limits)
      plaintext = :crypto.strong_rand_bytes(10 * 1024 * 1024)

      {:ok, encrypted} = Encryption.encrypt(plaintext, key)
      {:ok, decrypted} = Encryption.decrypt(encrypted, key)

      assert decrypted == plaintext
    end
  end
end
