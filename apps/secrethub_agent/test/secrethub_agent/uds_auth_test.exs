defmodule SecretHub.Agent.UDSAuthTest do
  use ExUnit.Case, async: true
  alias SecretHub.Agent.UDSAuth

  test "RSA modulus must have at least 2048 bits" do
    assert {:error, "INVALID_CERTIFICATE"} =
             UDSAuth.algorithm({:RSAPublicKey, Bitwise.bsl(1, 2046), 65_537})

    assert {:ok, "rsa-pss-sha256"} =
             UDSAuth.algorithm({:RSAPublicKey, Bitwise.bsl(1, 2047), 65_537})
  end

  test "transcript matches independently encoded big-endian length vector" do
    challenge = %{
      agent_id: "agent-1",
      connection_id: "connection-1",
      challenge_id: "challenge-1",
      signature_algorithm: "rsa-pss-sha256",
      nonce: :binary.list_to_bin(Enum.to_list(0..31)),
      certificate_fingerprint:
        Base.encode16(:binary.list_to_bin(Enum.to_list(32..63)), case: :lower)
    }

    expected =
      Base.decode16!(
        "000000127365637265746875622d7564732d6175746800000001020000000e7273612d7073732d736861323536000000076167656e742d310000000c636f6e6e656374696f6e2d310000000b6368616c6c656e67652d3100000020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000020202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f0000000c61757468656e746963617465",
        case: :lower
      )

    assert UDSAuth.transcript(challenge) == expected
  end

  test "challenges are random, bounded and carry canonical certificate identity" do
    key = X509.PrivateKey.new_rsa(2048)

    metadata = %{
      app_id: Ecto.UUID.generate(),
      canonical_fingerprint: String.duplicate("ab", 32),
      public_key: X509.PublicKey.derive(key)
    }

    {:ok, challenge} = UDSAuth.new_challenge("agent-1", "connection-1", metadata)
    {:ok, other} = UDSAuth.new_challenge("agent-1", "connection-2", metadata)
    assert byte_size(challenge.nonce) == 32
    refute challenge.nonce == other.nonce
    assert challenge.signature_algorithm == "rsa-pss-sha256"
    assert DateTime.diff(challenge.expires_at, DateTime.utc_now(), :second) in 0..30
  end

  test "RSA-PSS and ECDSA proofs reject changed fields and wrong keys" do
    for private_key <- [X509.PrivateKey.new_rsa(2048), X509.PrivateKey.new_ec(:secp256r1)] do
      public_key = X509.PublicKey.derive(private_key)

      metadata = %{
        app_id: Ecto.UUID.generate(),
        canonical_fingerprint: String.duplicate("ab", 32),
        public_key: public_key
      }

      {:ok, challenge} = UDSAuth.new_challenge("agent-1", "connection-1", metadata)

      opts =
        if challenge.signature_algorithm == "rsa-pss-sha256",
          do: [rsa_padding: :rsa_pkcs1_pss_padding, rsa_pss_saltlen: 32, rsa_mgf1_md: :sha256],
          else: []

      signature = :public_key.sign(UDSAuth.transcript(challenge), :sha256, private_key, opts)
      assert :ok = UDSAuth.verify_proof(challenge, signature, public_key)
      wrong_key = X509.PrivateKey.new_rsa(2048) |> X509.PublicKey.derive()
      assert {:error, "PROOF_FAILED"} = UDSAuth.verify_proof(challenge, signature, wrong_key)

      assert {:error, "PROOF_FAILED"} =
               UDSAuth.verify_proof(%{challenge | connection_id: "other"}, signature, public_key)

      assert {:error, "PROOF_FAILED"} =
               UDSAuth.verify_proof(%{challenge | agent_id: "other"}, signature, public_key)

      assert {:error, "PROOF_FAILED"} =
               UDSAuth.verify_proof(
                 %{challenge | expires_at: DateTime.add(DateTime.utc_now(), -1, :second)},
                 signature,
                 public_key
               )

      assert {:error, "PROOF_FAILED"} = UDSAuth.verify_proof(challenge, <<0>>, public_key)
    end
  end
end
