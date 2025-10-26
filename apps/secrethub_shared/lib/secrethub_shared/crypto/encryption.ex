defmodule SecretHub.Shared.Crypto.Encryption do
  @moduledoc """
  Encryption and decryption utilities using AES-256-GCM.

  This module provides secure encryption for secrets at rest and in transit.
  All secrets are encrypted using AES-256-GCM with unique nonces and authenticated
  encryption to prevent tampering.

  ## Security Features
  - AES-256-GCM authenticated encryption
  - Random 96-bit nonces (never reused)
  - 128-bit authentication tags
  - Key derivation using PBKDF2-SHA256
  - Constant-time comparison for tags
  """

  @aad "SecretHub-v1"
  # 96 bits for GCM
  @nonce_size 12
  # 128 bits
  @tag_size 16
  # 256 bits
  @key_size 32

  @type encrypted_data :: %{
          ciphertext: binary(),
          nonce: binary(),
          tag: binary(),
          version: integer()
        }

  @doc """
  Encrypts data using AES-256-GCM with the provided encryption key.

  Returns a map containing the ciphertext, nonce, and authentication tag.

  ## Examples

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, encrypted} = Encryption.encrypt("secret data", key)
      iex> encrypted.version
      1
  """
  @spec encrypt(binary(), binary()) :: {:ok, encrypted_data()} | {:error, String.t()}
  def encrypt(plaintext, encryption_key) when byte_size(encryption_key) == @key_size do
    # Generate random nonce (must be unique for each encryption)
    nonce = :crypto.strong_rand_bytes(@nonce_size)

    # Perform AES-256-GCM encryption
    {ciphertext, tag} =
      :crypto.crypto_one_time_aead(
        :aes_256_gcm,
        encryption_key,
        nonce,
        plaintext,
        @aad,
        # encrypt
        true
      )

    {:ok,
     %{
       ciphertext: ciphertext,
       nonce: nonce,
       tag: tag,
       version: 1
     }}
  rescue
    error ->
      {:error, "Encryption failed: #{inspect(error)}"}
  end

  def encrypt(_plaintext, _encryption_key) do
    {:error, "Invalid key size. Expected #{@key_size} bytes (256 bits)"}
  end

  @doc """
  Decrypts data encrypted with AES-256-GCM.

  Verifies the authentication tag before returning the plaintext.

  ## Examples

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, encrypted} = Encryption.encrypt("secret data", key)
      iex> {:ok, plaintext} = Encryption.decrypt(encrypted, key)
      iex> plaintext
      "secret data"
  """
  @spec decrypt(encrypted_data(), binary()) :: {:ok, binary()} | {:error, String.t()}
  def decrypt(%{ciphertext: ciphertext, nonce: nonce, tag: tag}, encryption_key)
      when byte_size(encryption_key) == @key_size do
    # Perform AES-256-GCM decryption with tag verification
    case :crypto.crypto_one_time_aead(
           :aes_256_gcm,
           encryption_key,
           nonce,
           ciphertext,
           @aad,
           tag,
           # decrypt
           false
         ) do
      :error ->
        {:error, "Decryption failed: authentication tag verification failed"}

      plaintext when is_binary(plaintext) ->
        {:ok, plaintext}
    end
  rescue
    error ->
      {:error, "Decryption failed: #{inspect(error)}"}
  end

  def decrypt(_encrypted_data, _encryption_key) do
    {:error, "Invalid encrypted data format or key size"}
  end

  @doc """
  Derives an encryption key from a password using PBKDF2-SHA256.

  Uses 100,000 iterations for key stretching to resist brute-force attacks.

  ## Examples

      iex> salt = :crypto.strong_rand_bytes(32)
      iex> key = Encryption.derive_key("my-password", salt)
      iex> byte_size(key)
      32
  """
  @spec derive_key(String.t(), binary(), non_neg_integer()) :: binary()
  def derive_key(password, salt, iterations \\ 100_000) do
    :crypto.pbkdf2_hmac(:sha256, password, salt, iterations, @key_size)
  end

  @doc """
  Generates a random encryption key suitable for AES-256.

  ## Examples

      iex> key = Encryption.generate_key()
      iex> byte_size(key)
      32
  """
  @spec generate_key() :: binary()
  def generate_key do
    :crypto.strong_rand_bytes(@key_size)
  end

  @doc """
  Encodes encrypted data as a single binary blob for database storage.

  Format: [version(1)][nonce(12)][tag(16)][ciphertext(N)]

  ## Examples

      iex> key = Encryption.generate_key()
      iex> {:ok, encrypted} = Encryption.encrypt("test", key)
      iex> blob = Encryption.encode_encrypted_blob(encrypted)
      iex> byte_size(blob) >= 29
      true
  """
  @spec encode_encrypted_blob(encrypted_data()) :: binary()
  def encode_encrypted_blob(%{version: version, nonce: nonce, tag: tag, ciphertext: ciphertext}) do
    <<version::8, nonce::binary-size(@nonce_size), tag::binary-size(@tag_size),
      ciphertext::binary>>
  end

  @doc """
  Decodes an encrypted blob back into structured data.

  ## Examples

      iex> key = Encryption.generate_key()
      iex> {:ok, encrypted} = Encryption.encrypt("test", key)
      iex> blob = Encryption.encode_encrypted_blob(encrypted)
      iex> {:ok, decoded} = Encryption.decode_encrypted_blob(blob)
      iex> decoded.version
      1
  """
  @spec decode_encrypted_blob(binary()) :: {:ok, encrypted_data()} | {:error, String.t()}
  def decode_encrypted_blob(
        <<version::8, nonce::binary-size(@nonce_size), tag::binary-size(@tag_size),
          ciphertext::binary>>
      ) do
    {:ok,
     %{
       version: version,
       nonce: nonce,
       tag: tag,
       ciphertext: ciphertext
     }}
  end

  def decode_encrypted_blob(_invalid_blob) do
    {:error, "Invalid encrypted blob format"}
  end

  @doc """
  Encrypts data and returns a single binary blob ready for storage.

  This is a convenience function that combines encrypt/2 and encode_encrypted_blob/1.

  ## Examples

      iex> key = Encryption.generate_key()
      iex> {:ok, blob} = Encryption.encrypt_to_blob("secret data", key)
      iex> is_binary(blob)
      true
  """
  @spec encrypt_to_blob(binary(), binary()) :: {:ok, binary()} | {:error, String.t()}
  def encrypt_to_blob(plaintext, encryption_key) do
    case encrypt(plaintext, encryption_key) do
      {:ok, encrypted} ->
        {:ok, encode_encrypted_blob(encrypted)}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Decrypts a binary blob and returns the plaintext.

  This is a convenience function that combines decode_encrypted_blob/1 and decrypt/2.

  ## Examples

      iex> key = Encryption.generate_key()
      iex> {:ok, blob} = Encryption.encrypt_to_blob("secret data", key)
      iex> {:ok, plaintext} = Encryption.decrypt_from_blob(blob, key)
      iex> plaintext
      "secret data"
  """
  @spec decrypt_from_blob(binary(), binary()) :: {:ok, binary()} | {:error, String.t()}
  def decrypt_from_blob(blob, encryption_key) do
    with {:ok, encrypted} <- decode_encrypted_blob(blob),
         {:ok, plaintext} <- decrypt(encrypted, encryption_key) do
      {:ok, plaintext}
    else
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Rotates encryption by re-encrypting data with a new key.

  ## Examples

      iex> old_key = Encryption.generate_key()
      iex> new_key = Encryption.generate_key()
      iex> {:ok, blob} = Encryption.encrypt_to_blob("secret", old_key)
      iex> {:ok, new_blob} = Encryption.rotate_encryption(blob, old_key, new_key)
      iex> {:ok, plaintext} = Encryption.decrypt_from_blob(new_blob, new_key)
      iex> plaintext
      "secret"
  """
  @spec rotate_encryption(binary(), binary(), binary()) :: {:ok, binary()} | {:error, String.t()}
  def rotate_encryption(encrypted_blob, old_key, new_key) do
    with {:ok, plaintext} <- decrypt_from_blob(encrypted_blob, old_key),
         {:ok, new_blob} <- encrypt_to_blob(plaintext, new_key) do
      {:ok, new_blob}
    else
      {:error, reason} -> {:error, reason}
    end
  end
end
