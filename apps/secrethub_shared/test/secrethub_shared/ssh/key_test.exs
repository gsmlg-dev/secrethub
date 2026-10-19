defmodule SecretHub.Shared.SSH.KeyTest do
  use ExUnit.Case, async: true

  alias SecretHub.Shared.SSH.Key

  @moduletag :tmp_dir

  setup_all do
    Application.ensure_all_started(:ssh)
    :ok
  end

  for algorithm <- ["ed25519", "rsa"] do
    @algorithm algorithm
    test "imports independent OpenSSH #{@algorithm} keys and matches OpenSSH fingerprints", ctx do
      path = fixture(ctx.tmp_dir, @algorithm)
      assert {:ok, imported} = Key.import_private(File.read!(path))
      expected = path |> then(&File.read!(&1 <> ".pub")) |> public_line()
      assert imported.public.public_line == expected
      {fingerprint, 0} = System.cmd("ssh-keygen", ["-lf", path <> ".pub", "-E", "sha256"])
      assert imported.public.fingerprint == Enum.at(String.split(fingerprint), 1)
      assert {:ok, again} = Key.import_private(imported.private_pem)
      assert again.public == imported.public
      assert {:ok, decoded} = Key.decode_public(imported.public.encoded)
      assert decoded == imported.public
    end
  end

  test "Ed25519 signs SSH wire data and an independent verifier accepts it", ctx do
    path = fixture(ctx.tmp_dir, "ed25519")
    pem = File.read!(path)
    [_, encoded | _] = path |> then(&File.read!(&1 <> ".pub")) |> String.split()
    <<11::32, "ssh-ed25519", 32::32, pub::binary-size(32)>> = Base.decode64!(encoded)

    assert {:ok, <<11::32, "ssh-ed25519", 64::32, signature::binary-size(64)>>} =
             Key.sign(pem, "ssh authentication payload", 0)

    assert :crypto.verify(:eddsa, :none, "ssh authentication payload", signature, [pub, :ed25519])
    refute :crypto.verify(:eddsa, :none, "altered", signature, [pub, :ed25519])
    assert {:error, _} = Key.sign(pem, "payload", 2)
  end

  test "RSA signatures require SHA2 and verify independently", ctx do
    path = fixture(ctx.tmp_dir, "rsa", ["-m", "PEM"])
    pem = File.read!(path)
    [entry] = :public_key.pem_decode(pem)
    {:RSAPrivateKey, _, n, e, _, _, _, _, _, _, _} = :public_key.pem_entry_decode(entry)

    for {flag, algorithm, digest} <- [{2, "rsa-sha2-256", :sha256}, {4, "rsa-sha2-512", :sha512}] do
      assert {:ok, wire} = Key.sign(pem, "payload", flag)
      <<alg_len::32, alg::binary-size(alg_len), sig_len::32, sig::binary-size(sig_len)>> = wire
      assert alg == algorithm
      assert :public_key.verify("payload", digest, sig, {:RSAPublicKey, n, e})
      refute :public_key.verify("altered", digest, sig, {:RSAPublicKey, n, e})
    end

    assert {:error, _} = Key.sign(pem, "payload", 0)
    assert {:error, _} = Key.sign(pem, "payload", 6)
  end

  test "generation produces supported importable keys" do
    for algorithm <- ["ed25519", "rsa"] do
      assert {:ok, key} = Key.generate(algorithm)
      assert {:ok, imported} = Key.import_private(key.private_pem)
      assert imported.public == key.public
    end

    assert {:error, _} = Key.generate("dsa")
  end

  test "public host-key inventory accepts ECDSA and rejects forged framing", ctx do
    path = fixture(ctx.tmp_dir, "ecdsa")
    line = File.read!(path <> ".pub")
    assert {:ok, public} = Key.decode_public(line)
    assert public.type == "ecdsa-sha2-nistp256"
    assert {:error, _} = Key.import_private(File.read!(path))
    assert {:error, _} = Key.decode_public("ssh-rsa " <> public.encoded)
    assert {:error, _} = Key.decode_public(Base.encode64(public.blob <> "garbage"))
    assert {:error, _} = Key.decode_public("command=evil " <> line)
    assert {:error, _} = Key.decode_public(line <> line)
    assert {:error, _} = Key.decode_public("not-a-key")
  end

  test "encrypted, multiple and weak private keys are refused", ctx do
    strong = fixture(ctx.tmp_dir, "rsa") |> File.read!()
    weak = fixture(ctx.tmp_dir, "rsa", ["-b", "1024"]) |> File.read!()
    encrypted = fixture(ctx.tmp_dir, "ed25519", ["-N", "secret"]) |> File.read!()
    assert {:error, _} = Key.import_private(weak)
    assert {:error, _} = Key.import_private(encrypted)
    assert {:error, _} = Key.import_private(strong <> strong)
    assert {:error, _} = Key.import_private("invalid")
    assert {:error, _} = Key.import_private(strong <> "unexpected data")
  end

  test "OpenSSH containers cannot substitute another key's public header", ctx do
    for algorithm <- ["ed25519", "rsa"] do
      private = fixture(ctx.tmp_dir, algorithm) |> File.read!()
      other = fixture(ctx.tmp_dir, algorithm) |> then(&File.read!(&1 <> ".pub"))
      [_, encoded | _] = String.split(other)
      other_public = Base.decode64!(encoded)

      payload =
        private
        |> String.split("\n")
        |> Enum.reject(&String.starts_with?(&1, "-----"))
        |> Enum.join()
        |> Base.decode64!()

      <<"openssh-key-v1\0", 4::32, "none", 4::32, "none", 0::32, 1::32, size::32,
        _old::binary-size(size), rest::binary>> = payload

      forged =
        <<"openssh-key-v1\0", 4::32, "none", 4::32, "none", 0::32, 1::32,
          byte_size(other_public)::32, other_public::binary, rest::binary>>

      pem =
        "-----BEGIN OPENSSH PRIVATE KEY-----\n" <>
          Base.encode64(forged) <> "\n-----END OPENSSH PRIVATE KEY-----\n"

      assert {:error, _} = Key.import_private(pem)
    end
  end

  defp fixture(dir, algorithm, extra \\ []) do
    path = Path.join(dir, "#{algorithm}-#{System.unique_integer([:positive])}")
    bits = if algorithm == "rsa", do: ["-b", "2048"], else: []

    {_, 0} =
      System.cmd("ssh-keygen", ["-q", "-t", algorithm, "-N", "", "-f", path] ++ bits ++ extra)

    path
  end

  defp public_line(text), do: text |> String.split() |> Enum.take(2) |> Enum.join(" ")
end
