defmodule SecretHub.Core.AutoUnseal.Providers.AWSKMS do
  @moduledoc """
  AWS KMS auto-unseal provider placeholder.

  AWS integration is intentionally disabled in this build because the ExAws
  dependency tree is not included.
  """

  @unsupported {:error, :aws_kms_provider_not_available}

  @spec encrypt(map(), binary()) :: {:ok, binary()} | {:error, term()}
  def encrypt(_config, _plaintext), do: @unsupported

  @spec decrypt(map(), binary()) :: {:ok, binary()} | {:error, term()}
  def decrypt(_config, _ciphertext_blob), do: @unsupported
end
