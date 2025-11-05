defmodule SecretHub.Core.AutoUnseal.Providers.GCPKMS do
  @moduledoc """
  Google Cloud KMS provider for auto-unseal (placeholder).

  This module will be implemented in a future task to support
  Google Cloud Key Management Service.
  """

  @spec encrypt(map(), binary()) :: {:ok, binary()} | {:error, term()}
  def encrypt(_config, _plaintext) do
    {:error, :not_implemented}
  end

  @spec decrypt(map(), binary()) :: {:ok, binary()} | {:error, term()}
  def decrypt(_config, _ciphertext) do
    {:error, :not_implemented}
  end
end
