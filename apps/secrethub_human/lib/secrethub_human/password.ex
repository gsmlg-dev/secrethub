defmodule SecretHub.Human.Password do
  @moduledoc "Slow server hashing of client-derived password verifiers; never accepts a vault key."
  @iterations 210_000

  def hash(verifier, opts \\ []) do
    iterations = Keyword.get(opts, :iterations, @iterations)

    cond do
      not valid?(verifier) ->
        {:error, :invalid_password_hash}

      not valid_iterations?(iterations) ->
        {:error, :invalid_iterations}

      true ->
        salt = :crypto.strong_rand_bytes(16)
        {:ok, %{salt: salt, digest: derive(verifier, salt, iterations), iterations: iterations}}
    end
  end

  def verify(verifier, stored, opts \\ [])

  def verify(verifier, %{salt: salt, digest: digest, iterations: iterations}, _opts)
      when is_binary(salt) and byte_size(salt) == 16 and is_binary(digest) and
             byte_size(digest) == 32 do
    valid?(verifier) and valid_iterations?(iterations) and
      :crypto.hash_equals(derive(verifier, salt, iterations), digest)
  end

  def verify(verifier, nil, opts) do
    iterations = Keyword.get(opts, :iterations, @iterations)

    if valid?(verifier) and valid_iterations?(iterations) do
      :crypto.hash_equals(derive(verifier, <<0::128>>, iterations), <<0::256>>)
    end

    false
  end

  def verify(_verifier, _stored, _opts), do: false

  def valid?(verifier) when is_binary(verifier) and byte_size(verifier) == 44 do
    case Base.decode64(verifier) do
      {:ok, value} when byte_size(value) == 32 -> true
      _ -> false
    end
  end

  def valid?(_), do: false
  defp valid_iterations?(value), do: is_integer(value) and value >= 1000 and value <= 2_000_000

  defp derive(verifier, salt, iterations),
    do: :crypto.pbkdf2_hmac(:sha256, verifier, salt, iterations, 32)
end
