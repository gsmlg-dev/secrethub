defmodule SecretHub.Shared.SecurityRedactionTest do
  use ExUnit.Case, async: true
  alias SecretHub.Shared.Crypto.Encryption
  alias SecretHub.Shared.Schemas.Secret

  test "secret structs and failed changesets redact plaintext values" do
    marker = "disposable-redaction-marker"
    refute inspect(%Secret{value: marker}) =~ marker
    changeset = Secret.changeset(%Secret{}, %{value: marker})
    refute inspect(changeset) =~ marker
  end

  test "encryption errors contain bounded reasons rather than argument inspection" do
    key = :crypto.strong_rand_bytes(32)

    assert Encryption.encrypt(%{"private" => "disposable-redaction-marker"}, key) ==
             {:error, "Encryption failed"}

    assert Encryption.decrypt(
             %{
               nonce: %{"private" => "disposable-redaction-marker"},
               tag: <<0::128>>,
               ciphertext: "disposable-redaction-marker"
             },
             key
           ) ==
             {:error, "Decryption failed"}
  end
end
