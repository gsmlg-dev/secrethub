defmodule SecretHub.Agent.SSH.KeyStoreTest do
  # Not async: one test mutates the global SECRET_HUB_AGENT_STATE_DIR.
  use ExUnit.Case, async: false
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

  test "empty, loose-mode and symlinked keys are not loaded", %{tmp_dir: root} do
    {:ok, %{private_pem: pem}} = KeyStore.create(1000, 1, root)
    File.mkdir_p!(Path.join(root, "1000"))
    File.write!(Path.join([root, "1000", "2.key"]), "")
    File.chmod!(Path.join([root, "1000", "2.key"]), 0o600)
    File.write!(Path.join([root, "1000", "3.key"]), pem)
    File.chmod!(Path.join([root, "1000", "3.key"]), 0o644)
    File.ln_s!(Path.join([root, "1000", "1.key"]), Path.join([root, "1000", "4.key"]))

    assert KeyStore.generations(1000, root) == [1]
    assert {:error, :not_found} = KeyStore.load(1000, 3, root)
    assert {:error, :not_found} = KeyStore.load(1000, 4, root)
  end

  test "a failed create leaves no temporary or partial key file", %{tmp_dir: root} do
    {:ok, _} = KeyStore.create(1000, 1, root)
    assert {:error, :exists} = KeyStore.create(1000, 1, root)
    assert File.ls!(Path.join(root, "1000")) == ["1.key"]
  end

  test "root honours the state dir environment override" do
    previous = System.get_env("SECRET_HUB_AGENT_STATE_DIR")
    System.put_env("SECRET_HUB_AGENT_STATE_DIR", "/tmp/kstest")

    on_exit(fn ->
      if previous,
        do: System.put_env("SECRET_HUB_AGENT_STATE_DIR", previous),
        else: System.delete_env("SECRET_HUB_AGENT_STATE_DIR")
    end)

    assert KeyStore.root() == "/tmp/kstest/ssh-identities"
  end
end
