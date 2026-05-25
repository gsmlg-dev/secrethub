defmodule SecretHub.Shared.Crypto.AgentCSRProof do
  @moduledoc """
  Signs and verifies Agent CSR enrollment proofs.

  Proofs bind an Agent TLS CSR to a Core challenge and enrollment id using the
  Agent host SSH key. The signed payload is canonicalized to avoid depending on
  map ordering or transport-specific request encoding.
  """

  @context "secrethub-agent-csr-v1"
  @separator <<0>>
  @ecdsa_named_curves [
    {1, 2, 840, 10045, 3, 1, 7},
    {1, 3, 132, 0, 34},
    {1, 3, 132, 0, 35}
  ]

  @type attrs :: map()
  @type proof :: %{required(String.t()) => String.t()}

  @doc """
  Signs the canonical CSR proof payload with an SSH host private key.
  """
  @spec sign(:public_key.private_key(), attrs()) :: proof()
  def sign(private_key, attrs) do
    algorithm = private_key_algorithm!(private_key)

    signature =
      attrs
      |> payload()
      |> :public_key.sign(:sha256, private_key)

    %{
      "algorithm" => algorithm,
      "signature" => Base.url_encode64(signature, padding: false)
    }
  end

  @doc """
  Verifies a CSR proof with the matching SSH host public key.
  """
  @spec verify(:public_key.public_key(), attrs()) ::
          {:ok, %{algorithm: binary() | nil}} | {:error, atom()}
  def verify(public_key, attrs) do
    with {:ok, algorithm} <- public_key_algorithm(public_key),
         {:ok, signed_payload} <- build_payload(attrs),
         {:ok, proof} <- fetch_proof(attrs),
         {:ok, encoded_signature} <- fetch_signature(proof),
         {:ok, signature} <- decode_signature(encoded_signature),
         {:ok, valid_signature?} <- verify_signature(signed_payload, signature, public_key) do
      if valid_signature? do
        {:ok, %{algorithm: algorithm}}
      else
        {:error, :invalid_signature}
      end
    end
  end

  @doc """
  Builds the canonical payload signed by the host key.
  """
  @spec payload(attrs()) :: binary()
  def payload(attrs) do
    case build_payload(attrs) do
      {:ok, signed_payload} -> signed_payload
      {:error, reason} -> raise ArgumentError, payload_error_message(reason)
    end
  end

  defp build_payload(attrs) do
    with {:ok, enrollment_id} <- required_payload_attr(attrs, :enrollment_id),
         {:ok, challenge} <- required_payload_attr(attrs, :challenge),
         {:ok, csr_pem} <- required_payload_attr(attrs, :csr_pem) do
      signed_payload =
        [
          @context,
          enrollment_id,
          challenge,
          csr_hash(csr_pem)
        ]
        |> Enum.join(@separator)

      {:ok, signed_payload}
    end
  end

  defp fetch_proof(attrs) do
    case raw_attr(attrs, :proof, nil) do
      proof when is_map(proof) -> {:ok, proof}
      _missing_or_invalid -> {:error, :missing_proof}
    end
  end

  defp fetch_signature(proof) do
    case raw_attr(proof, :signature, nil) do
      signature when is_binary(signature) -> {:ok, signature}
      nil -> {:error, :missing_signature}
      _invalid -> {:error, :invalid_signature}
    end
  end

  defp required_payload_attr(attrs, key) do
    case fetch_attr(attrs, key) do
      {:ok, value} ->
        with :ok <- validate_required_binary(value),
             :ok <- validate_no_separator(value) do
          {:ok, value}
        end

      :error ->
        {:error, :missing_required_attr}
    end
  end

  defp fetch_attr(attrs, key) when is_map(attrs) and is_atom(key) do
    case Map.fetch(attrs, key) do
      {:ok, value} -> {:ok, value}
      :error -> Map.fetch(attrs, Atom.to_string(key))
    end
  end

  defp fetch_attr(_attrs, _key), do: :error

  defp validate_required_binary(value) when is_binary(value), do: :ok
  defp validate_required_binary(_value), do: {:error, :invalid_required_attr}

  defp validate_no_separator(value) do
    case :binary.match(value, @separator) do
      :nomatch -> :ok
      {_position, _length} -> {:error, :invalid_payload_value}
    end
  end

  defp decode_signature(signature) do
    case Base.url_decode64(signature, padding: false) do
      {:ok, decoded} -> {:ok, decoded}
      :error -> {:error, :invalid_signature}
    end
  end

  defp verify_signature(signed_payload, signature, public_key) do
    {:ok, :public_key.verify(signed_payload, :sha256, signature, public_key)}
  rescue
    FunctionClauseError -> {:error, :invalid_signature}
    ErlangError -> {:error, :invalid_signature}
  end

  defp csr_hash(csr_pem) do
    :sha256
    |> :crypto.hash(csr_pem)
    |> Base.encode16(case: :lower)
  end

  defp raw_attr(attrs, key, default) when is_map(attrs) and is_atom(key) do
    case Map.fetch(attrs, key) do
      {:ok, value} -> value
      :error -> Map.get(attrs, Atom.to_string(key), default)
    end
  end

  defp raw_attr(_attrs, _key, default), do: default

  defp private_key_algorithm!(
         {:RSAPrivateKey, _version, _modulus, _public_exponent, _private_exponent, _prime1,
          _prime2, _exponent1, _exponent2, _coefficient, _other_prime_infos}
       ) do
    "rsa"
  end

  defp private_key_algorithm!(
         {:ECPrivateKey, _version, _private_key, {:namedCurve, oid}, _public_key, _attributes}
       ) do
    if oid in @ecdsa_named_curves do
      "ecdsa"
    else
      raise ArgumentError, "unsupported private key algorithm"
    end
  end

  defp private_key_algorithm!(_private_key) do
    raise ArgumentError, "unsupported private key algorithm"
  end

  defp public_key_algorithm({:RSAPublicKey, _modulus, _public_exponent}), do: {:ok, "rsa"}

  defp public_key_algorithm({{:ECPoint, point}, {:namedCurve, oid}})
       when is_binary(point) and oid in @ecdsa_named_curves do
    {:ok, "ecdsa"}
  end

  defp public_key_algorithm(_public_key), do: {:error, :unsupported_key_algorithm}

  defp payload_error_message(:missing_required_attr), do: "missing required attr"
  defp payload_error_message(:invalid_required_attr), do: "invalid required attr"
  defp payload_error_message(:invalid_payload_value), do: "invalid payload value"
  defp payload_error_message(reason), do: "invalid payload: #{reason}"
end
