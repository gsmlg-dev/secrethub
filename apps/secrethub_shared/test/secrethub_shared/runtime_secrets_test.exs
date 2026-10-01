defmodule SecretHub.Shared.RuntimeSecretsTest do
  use ExUnit.Case, async: true

  alias SecretHub.Shared.RuntimeSecrets

  @tag :tmp_dir
  test "reads private file-backed material without needing build-time environment", %{
    tmp_dir: dir
  } do
    path = Path.join(dir, "secret")
    File.write!(path, "runtime-only\n")
    File.chmod!(path, 0o600)
    env = %{"VALUE_FILE" => path}
    assert {:ok, "runtime-only"} = RuntimeSecrets.read("VALUE", get_env: &Map.get(env, &1))
  end

  test "missing required values and conflicting sources fail with bounded errors" do
    assert {:error, :missing} = RuntimeSecrets.read("VALUE", get_env: fn _ -> nil end)
    env = %{"VALUE" => "do-not-print", "VALUE_FILE" => "/private/do-not-print"}

    assert {:error, :conflicting_sources} =
             RuntimeSecrets.read("VALUE", get_env: &Map.get(env, &1))

    assert {:ok, nil} = RuntimeSecrets.read("VALUE", required: false, get_env: fn _ -> nil end)
  end

  @tag :tmp_dir
  test "empty oversized missing and Nix-store files are refused", %{tmp_dir: dir} do
    path = Path.join(dir, "secret")

    for value <- ["\n", String.duplicate("a", 4097)] do
      File.write!(path, value)

      assert {:error, _} =
               RuntimeSecrets.read("VALUE",
                 get_env: fn
                   "VALUE_FILE" -> path
                   _ -> nil
                 end
               )
    end

    for invalid <- [Path.join(dir, "missing"), dir, "/nix/store/test-secret"] do
      assert {:error, _} =
               RuntimeSecrets.read("VALUE",
                 get_env: fn
                   "VALUE_FILE" -> invalid
                   _ -> nil
                 end
               )
    end
  end

  test "environment values remain runtime inputs and empty values do not fall back" do
    assert {:ok, "runtime-only"} =
             RuntimeSecrets.read("VALUE",
               get_env: fn
                 "VALUE" -> "runtime-only"
                 _ -> nil
               end
             )

    assert {:error, :empty} =
             RuntimeSecrets.read("VALUE",
               get_env: fn
                 "VALUE" -> ""
                 _ -> nil
               end
             )
  end
end
