defmodule SecretHub.Agent.SSH.KeyStoreTest do
  use ExUnit.Case, async: true
  alias SecretHub.Agent.SSH.KeyStore
  @moduletag :tmp_dir

  test "creates owner-only key files per uid and generation", %{tmp_dir: root} do
    assert KeyStore.generations(1000, root) == []

    assert {:ok, %{generation: 1, public: public, private_pem: pem}} =
             KeyStore.create(1000, 1, root)

    assert pem =~ "PRIVATE KEY"
    assert {:error, :exists} = KeyStore.create(1000, 1, root)
    assert KeyStore.generations(1000, root) == [1]
    assert KeyStore.uids(root) == [1000]

    assert {:ok, %{mode: dir_mode}} = File.stat(Path.join(root, "1000"))
    assert Bitwise.band(dir_mode, 0o777) == 0o700
    assert {:ok, %{mode: file_mode}} = File.stat(Path.join([root, "1000", "1.key"]))
    assert Bitwise.band(file_mode, 0o777) == 0o600

    assert {:ok, %{generation: 1}} = KeyStore.find_by_blob(1000, public.blob, root)
    assert {:error, :not_found} = KeyStore.find_by_blob(1001, public.blob, root)
  end

  test "prune keeps only listed generations", %{tmp_dir: root} do
    for generation <- 1..3, do: {:ok, _} = KeyStore.create(1000, generation, root)
    :ok = KeyStore.prune(1000, [2, 3], root)
    assert KeyStore.generations(1000, root) == [2, 3]
  end

  test "ignores foreign files and invalid names", %{tmp_dir: root} do
    File.mkdir_p!(Path.join(root, "notauid"))
    File.mkdir_p!(Path.join(root, "1000"))
    File.write!(Path.join([root, "1000", "junk"]), "x")
    assert KeyStore.uids(root) == [1000]
    assert KeyStore.generations(1000, root) == []
  end
end
