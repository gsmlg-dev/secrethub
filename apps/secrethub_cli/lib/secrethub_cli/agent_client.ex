defmodule SecretHub.CLI.AgentClient do
  @moduledoc "Client for the owner-protected Agent UDS auth-v2 protocol."
  @timeout 5_000

  def get_secret(path, opts) do
    timeout = Keyword.get(opts, :timeout, @timeout)

    with {:ok, socket_path} <- required(opts, :socket_path, "agent socket path"),
         {:ok, certificate_path} <- required(opts, :certificate_path, "agent certificate"),
         {:ok, key_path} <- required(opts, :private_key_path, "agent private key"),
         {:ok, pem} <- File.read(certificate_path),
         {:ok, private_pem} <- File.read(key_path),
         {:ok, key} <- decode_private_key(private_pem),
         {:ok, socket} <-
           :gen_tcp.connect(
             {:local, to_charlist(socket_path)},
             0,
             [:binary, packet: :line, packet_size: 65_536, active: false],
             timeout
           ) do
      try do
        with :ok <- authenticate(socket, pem, key, timeout),
             {:ok, data} <- request(socket, "get_secret", %{path: path}, timeout) do
          {:ok, normalize_secret(data)}
        end
      after
        :gen_tcp.close(socket)
      end
    else
      {:error, reason} when is_binary(reason) -> {:error, reason}
      _ -> {:error, "Agent connection or key material unavailable"}
    end
  end

  defp authenticate(socket, pem, key, timeout) do
    with {:ok, data} <-
           request(
             socket,
             "authenticate",
             %{auth_version: 2, certificate: Base.encode64(pem)},
             timeout
           ),
         {:ok, transcript, public_key} <- challenge_transcript(data, pem, key),
         signature <-
           :public_key.sign(
             transcript,
             :sha256,
             key,
             signature_options(data["signature_algorithm"])
           ),
         true <-
           :public_key.verify(
             transcript,
             :sha256,
             signature,
             public_key,
             signature_options(data["signature_algorithm"])
           ),
         {:ok, %{"authenticated" => true, "auth_version" => 2}} <-
           request(
             socket,
             "authenticate_proof",
             Map.take(data, [
               "auth_version",
               "connection_id",
               "challenge_id",
               "signature_algorithm"
             ])
             |> Map.put("signature", Base.encode64(signature)),
             timeout
           ) do
      :ok
    else
      {:error, reason} -> {:error, reason}
      _ -> {:error, "PROOF_FAILED"}
    end
  rescue
    _ -> {:error, "PROOF_FAILED"}
  end

  defp challenge_transcript(data, pem, key) do
    with 2 <- data["auth_version"],
         algorithm when algorithm in ["rsa-pss-sha256", "ecdsa-sha256"] <-
           data["signature_algorithm"],
         true <- algorithm == key_algorithm(key),
         [{:Certificate, der, :not_encrypted}] <- :public_key.pem_decode(pem),
         fingerprint <- :crypto.hash(:sha256, der),
         true <- data["certificate_fingerprint"] == Base.encode16(fingerprint, case: :lower),
         {:ok, <<_::256>> = nonce} <- Base.decode64(data["challenge"]),
         {:ok, expiry, 0} <- DateTime.from_iso8601(data["expires_at"]),
         true <- DateTime.diff(expiry, DateTime.utc_now(), :second) in 0..30,
         true <-
           Enum.all?(["agent_id", "connection_id", "challenge_id"], fn field ->
             is_binary(data[field]) and byte_size(data[field]) in 1..255
           end) do
      fields = [
        "secrethub-uds-auth",
        <<2>>,
        algorithm,
        data["agent_id"],
        data["connection_id"],
        data["challenge_id"],
        nonce,
        fingerprint,
        "authenticate"
      ]

      transcript =
        IO.iodata_to_binary(
          Enum.map(fields, fn bytes -> <<byte_size(bytes)::unsigned-big-32, bytes::binary>> end)
        )

      {:OTPCertificate, tbs, _, _} = :public_key.pkix_decode_cert(der, :otp)
      {:OTPSubjectPublicKeyInfo, {:PublicKeyAlgorithm, _, parameters}, public_key} = elem(tbs, 7)

      public_key =
        case public_key do
          {:RSAPublicKey, _, _} -> public_key
          _ -> {public_key, parameters}
        end

      {:ok, transcript, public_key}
    else
      _ -> {:error, "PROOF_FAILED"}
    end
  end

  defp decode_private_key(pem) do
    case :public_key.pem_decode(pem) do
      [entry] -> {:ok, :public_key.pem_entry_decode(entry)}
      _ -> {:error, "Invalid agent private key"}
    end
  rescue
    _ -> {:error, "Invalid agent private key"}
  end

  defp key_algorithm(key) when elem(key, 0) == :RSAPrivateKey, do: "rsa-pss-sha256"
  defp key_algorithm(key) when elem(key, 0) == :ECPrivateKey, do: "ecdsa-sha256"
  defp key_algorithm(_), do: nil

  defp signature_options("rsa-pss-sha256"),
    do: [rsa_padding: :rsa_pkcs1_pss_padding, rsa_pss_saltlen: 32, rsa_mgf1_md: :sha256]

  defp signature_options("ecdsa-sha256"), do: []

  defp required(opts, key, name) do
    case Keyword.get(opts, key) do
      value when is_binary(value) and value != "" -> {:ok, value}
      _ -> {:error, "Missing required #{name}"}
    end
  end

  defp request(socket, action, params, timeout) do
    id = Base.encode16(:crypto.strong_rand_bytes(16), case: :lower)

    with :ok <-
           :gen_tcp.send(
             socket,
             Jason.encode!(%{request_id: id, action: action, params: params}) <> "\n"
           ),
         {:ok, line} <- :gen_tcp.recv(socket, 0, timeout),
         {:ok, %{"request_id" => ^id} = response} <- Jason.decode(line) do
      case response do
        %{"status" => "ok", "data" => data} when is_map(data) ->
          {:ok, data}

        %{"status" => "error", "error" => %{"code" => code}} when is_binary(code) ->
          {:error, code}

        _ ->
          {:error, "Invalid Agent response"}
      end
    else
      _ -> {:error, "Agent unavailable"}
    end
  end

  defp normalize_secret(%{"value" => value}) when is_map(value), do: value
  defp normalize_secret(%{"value" => value}), do: %{"value" => value}
  defp normalize_secret(data), do: data
end
