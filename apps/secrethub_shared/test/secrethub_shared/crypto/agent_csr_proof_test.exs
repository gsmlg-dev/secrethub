defmodule SecretHub.Shared.Crypto.AgentCSRProofTest do
  use ExUnit.Case, async: true

  alias SecretHub.Shared.Crypto.AgentCSRProof

  describe "sign/2 and verify/2" do
    test "signs and verifies an RSA host-key proof" do
      private_key = :public_key.generate_key({:rsa, 2048, 65_537})
      public_key = :ssh_file.extract_public_key(private_key)

      attrs = %{
        enrollment_id: "enrollment-1",
        challenge: "challenge-1",
        csr_pem: """
        -----BEGIN CERTIFICATE REQUEST-----
        csr-body
        -----END CERTIFICATE REQUEST-----
        """
      }

      proof = AgentCSRProof.sign(private_key, attrs)

      assert %{"algorithm" => "rsa", "signature" => signature} = proof
      assert is_binary(signature)

      assert {:ok, %{algorithm: "rsa"}} =
               AgentCSRProof.verify(public_key, Map.put(attrs, :proof, proof))
    end

    test "rejects a proof when the CSR changes after signing" do
      private_key = :public_key.generate_key({:rsa, 2048, 65_537})
      public_key = :ssh_file.extract_public_key(private_key)

      signed_attrs = %{
        enrollment_id: "enrollment-1",
        challenge: "challenge-1",
        csr_pem: "csr-a"
      }

      proof = AgentCSRProof.sign(private_key, signed_attrs)
      verified_attrs = %{signed_attrs | csr_pem: "csr-b"}

      assert {:error, :invalid_signature} =
               AgentCSRProof.verify(public_key, Map.put(verified_attrs, :proof, proof))
    end

    test "rejects attrs without a proof" do
      private_key = :public_key.generate_key({:rsa, 2048, 65_537})
      public_key = :ssh_file.extract_public_key(private_key)

      attrs = %{
        enrollment_id: "enrollment-1",
        challenge: "challenge-1",
        csr_pem: "csr-a"
      }

      assert {:error, :missing_proof} = AgentCSRProof.verify(public_key, attrs)
    end

    test "derives the verified algorithm from the public key" do
      {private_key, public_key} = rsa_key_pair()
      attrs = valid_attrs()

      proof =
        private_key
        |> AgentCSRProof.sign(attrs)
        |> Map.put("algorithm", "ed25519")

      assert {:ok, %{algorithm: "rsa"}} =
               AgentCSRProof.verify(public_key, Map.put(attrs, :proof, proof))
    end

    test "rejects payload values containing NUL during sign" do
      {private_key, _public_key} = rsa_key_pair()
      attrs = %{valid_attrs() | challenge: "challenge-1" <> <<0>> <> "suffix"}

      assert_raise ArgumentError, ~r/invalid payload value/, fn ->
        AgentCSRProof.sign(private_key, attrs)
      end
    end

    test "rejects payload values containing NUL during verify" do
      {private_key, public_key} = rsa_key_pair()
      attrs = valid_attrs()
      proof = AgentCSRProof.sign(private_key, attrs)
      nul_attrs = %{attrs | challenge: "challenge-1" <> <<0>> <> "suffix"}

      assert {:error, :invalid_payload_value} =
               AgentCSRProof.verify(public_key, Map.put(nul_attrs, :proof, proof))
    end

    test "rejects missing required attrs during verify" do
      {_private_key, public_key} = rsa_key_pair()
      proof = unsigned_proof()

      attrs =
        valid_attrs()
        |> Map.delete(:enrollment_id)
        |> Map.put(:proof, proof)

      assert {:error, :missing_required_attr} = AgentCSRProof.verify(public_key, attrs)
    end

    test "rejects invalid required attr types during verify" do
      {_private_key, public_key} = rsa_key_pair()
      attrs = %{valid_attrs() | enrollment_id: 123}

      assert {:error, :invalid_required_attr} =
               AgentCSRProof.verify(public_key, Map.put(attrs, :proof, unsigned_proof()))
    end

    test "raises a clear error when signing with missing required attrs" do
      {private_key, _public_key} = rsa_key_pair()
      attrs = Map.delete(valid_attrs(), :enrollment_id)

      assert_raise ArgumentError, ~r/missing required attr/, fn ->
        AgentCSRProof.sign(private_key, attrs)
      end
    end

    test "rejects unsupported public key shapes during verify" do
      attrs = Map.put(valid_attrs(), :proof, unsigned_proof())

      assert {:error, :unsupported_key_algorithm} =
               AgentCSRProof.verify({:UnsupportedPublicKey, <<1, 2, 3>>}, attrs)
    end

    test "rejects malformed EC public key tuples during verify" do
      attrs = Map.put(valid_attrs(), :proof, unsigned_proof())

      assert {:error, :unsupported_key_algorithm} =
               AgentCSRProof.verify({{:ECPoint, "bad"}, "bad"}, attrs)
    end

    test "rejects malformed named-curve EC public key tuples during verify" do
      attrs = Map.put(valid_attrs(), :proof, unsigned_proof())

      malformed_public_key =
        {{:ECPoint, <<4, 1, 2, 3>>}, {:namedCurve, {1, 2, 840, 10045, 3, 1, 7}}}

      assert {:error, :invalid_signature} = AgentCSRProof.verify(malformed_public_key, attrs)
    end

    @tag :tmp_dir
    test "rejects Ed25519 public keys before signature verification", %{tmp_dir: tmp_dir} do
      public_key_path = generate_key!(tmp_dir, "ssh_host_ed25519_key", "ed25519") <> ".pub"
      [{public_key, _attrs}] = :ssh_file.decode(File.read!(public_key_path), :public_key)

      attrs = Map.put(valid_attrs(), :proof, unsigned_proof())

      assert {:error, :unsupported_key_algorithm} = AgentCSRProof.verify(public_key, attrs)
    end
  end

  defp rsa_key_pair do
    private_key = :public_key.generate_key({:rsa, 2048, 65_537})
    public_key = :ssh_file.extract_public_key(private_key)

    {private_key, public_key}
  end

  defp valid_attrs do
    %{
      enrollment_id: "enrollment-1",
      challenge: "challenge-1",
      csr_pem: "csr-a"
    }
  end

  defp unsigned_proof do
    %{
      "algorithm" => "rsa",
      "signature" => Base.url_encode64("signature", padding: false)
    }
  end

  defp generate_key!(tmp_dir, name, type) do
    path = Path.join(tmp_dir, name)

    {_, 0} =
      System.cmd("ssh-keygen", [
        "-q",
        "-t",
        type,
        "-N",
        "",
        "-f",
        path
      ])

    path
  end
end
