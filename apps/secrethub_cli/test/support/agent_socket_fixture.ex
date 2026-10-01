defmodule SecretHub.CLI.AgentSocketFixture do
  def material(dir, key \\ X509.PrivateKey.new_rsa(2048)) do
    pem = X509.Certificate.self_signed(key, "/CN=consumer") |> X509.Certificate.to_pem()
    cert_path = Path.join(dir, "app.crt")
    key_path = Path.join(dir, "app.key")
    File.write!(cert_path, pem)
    File.write!(key_path, X509.PrivateKey.to_pem(key))

    %{
      certificate_path: cert_path,
      private_key_path: key_path,
      pem: pem,
      public_key: X509.PublicKey.derive(key)
    }
  end

  def start(path, owner, material) do
    Task.async(fn ->
      {:ok, listener} =
        :gen_tcp.listen(0, [
          :binary,
          ifaddr: {:local, to_charlist(path)},
          packet: :line,
          active: false
        ])

      send(owner, :agent_socket_ready)
      {:ok, socket} = :gen_tcp.accept(listener, 5000)
      auth = receive_json(socket)
      send(owner, {:auth_request, auth})
      nonce = :crypto.strong_rand_bytes(32)
      [{:Certificate, der, _}] = :public_key.pem_decode(material.pem)
      fingerprint = :crypto.hash(:sha256, der)

      algorithm =
        case material.public_key do
          {:RSAPublicKey, _, _} -> "rsa-pss-sha256"
          _ -> "ecdsa-sha256"
        end

      data = %{
        auth_version: 2,
        agent_id: "agent-1",
        connection_id: "connection-1",
        challenge_id: "challenge-1",
        challenge: Base.encode64(nonce),
        certificate_fingerprint: Base.encode16(fingerprint, case: :lower),
        signature_algorithm: algorithm,
        expires_at: DateTime.to_iso8601(DateTime.add(DateTime.utc_now(), 30, :second))
      }

      send_json(socket, %{request_id: auth["request_id"], status: "ok", data: data})
      proof = receive_json(socket)

      fields = [
        "secrethub-uds-auth",
        <<2>>,
        algorithm,
        "agent-1",
        "connection-1",
        "challenge-1",
        nonce,
        fingerprint,
        "authenticate"
      ]

      transcript =
        IO.iodata_to_binary(
          Enum.map(fields, fn bytes -> <<byte_size(bytes)::unsigned-big-32, bytes::binary>> end)
        )

      options =
        if algorithm == "rsa-pss-sha256",
          do: [rsa_padding: :rsa_pkcs1_pss_padding, rsa_pss_saltlen: 32, rsa_mgf1_md: :sha256],
          else: []

      verified =
        :public_key.verify(
          transcript,
          :sha256,
          Base.decode64!(proof["params"]["signature"]),
          material.public_key,
          options
        )

      send(owner, {:proof_verified, verified})

      send_json(socket, %{
        request_id: proof["request_id"],
        status: "ok",
        data: %{authenticated: verified, auth_version: 2, app_id: "app-1"}
      })

      request = receive_json(socket)
      send(owner, {:secret_request, request})

      send_json(socket, %{
        request_id: request["request_id"],
        status: "ok",
        data: %{value: "from-agent", version: 7, revision: 10}
      })

      :gen_tcp.close(socket)
      :gen_tcp.close(listener)
    end)
  end

  defp receive_json(socket) do
    {:ok, line} = :gen_tcp.recv(socket, 0, 5000)
    Jason.decode!(line)
  end

  defp send_json(socket, value), do: :gen_tcp.send(socket, Jason.encode!(value) <> "\n")
end
