defmodule SecretHub.Agent.UDSAuth do
  @moduledoc "Connection-bound application private-key proof for the UDS auth-v2 exchange."

  def new_challenge(agent_id, connection_id, metadata) do
    with {:ok, algorithm} <- algorithm(metadata.public_key) do
      {:ok,
       %{
         agent_id: agent_id,
         connection_id: connection_id,
         challenge_id: Ecto.UUID.generate(),
         nonce: :crypto.strong_rand_bytes(32),
         certificate_fingerprint: metadata.canonical_fingerprint,
         signature_algorithm: algorithm,
         expires_at: DateTime.add(DateTime.utc_now(), 30, :second),
         principal: metadata
       }}
    end
  end

  def transcript(challenge) do
    fields = [
      "secrethub-uds-auth",
      <<2>>,
      challenge.signature_algorithm,
      challenge.agent_id,
      challenge.connection_id,
      challenge.challenge_id,
      challenge.nonce,
      Base.decode16!(challenge.certificate_fingerprint, case: :lower),
      "authenticate"
    ]

    IO.iodata_to_binary(
      Enum.map(fields, fn bytes -> <<byte_size(bytes)::unsigned-big-32, bytes::binary>> end)
    )
  end

  def verify_proof(challenge, signature, public_key) do
    with true <- DateTime.compare(DateTime.utc_now(), challenge.expires_at) == :lt,
         {:ok, algorithm} <- algorithm(public_key),
         true <- algorithm == challenge.signature_algorithm,
         true <-
           :public_key.verify(
             transcript(challenge),
             :sha256,
             signature,
             public_key,
             signature_options(algorithm)
           ) do
      :ok
    else
      _ -> {:error, "PROOF_FAILED"}
    end
  rescue
    _ -> {:error, "PROOF_FAILED"}
  end

  def algorithm({:RSAPublicKey, modulus, _}) do
    if modulus >= Bitwise.bsl(1, 2047),
      do: {:ok, "rsa-pss-sha256"},
      else: {:error, "INVALID_CERTIFICATE"}
  end

  def algorithm({{:ECPoint, _}, {:namedCurve, curve}})
      when curve in [{1, 2, 840, 10_045, 3, 1, 7}, {1, 3, 132, 0, 34}],
      do: {:ok, "ecdsa-sha256"}

  def algorithm({point, {:namedCurve, curve}})
      when is_binary(point) and curve in [{1, 2, 840, 10_045, 3, 1, 7}, {1, 3, 132, 0, 34}],
      do: {:ok, "ecdsa-sha256"}

  def algorithm(_), do: {:error, "INVALID_CERTIFICATE"}

  defp signature_options("rsa-pss-sha256"),
    do: [rsa_padding: :rsa_pkcs1_pss_padding, rsa_pss_saltlen: 32, rsa_mgf1_md: :sha256]

  defp signature_options("ecdsa-sha256"), do: []
end
