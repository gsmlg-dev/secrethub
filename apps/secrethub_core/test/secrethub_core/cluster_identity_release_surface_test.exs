defmodule SecretHub.Core.ClusterIdentityReleaseSurfaceTest do
  use ExUnit.Case, async: true

  @repo_root Path.expand("../../../..", __DIR__)

  test "Core Dockerfiles leave runtime identities to the operator" do
    for path <- ["Dockerfile.core", "Dockerfile.core-standalone"] do
      dockerfile = read!(path)
      refute dockerfile =~ "ENV SECRET_HUB_CLUSTER_NODE_ID="
      assert runtime_stage(dockerfile) =~ "RELEASE_DISTRIBUTION=none"
    end
  end

  test "release workflow documents required runtime identity without build defaults" do
    workflow = read!(".github/workflows/release.yml")

    refute workflow =~ "BUILD_CLUSTER_NODE_ID"
    refute workflow =~ "SECRET_HUB_CLUSTER_NODE_ID:"

    for input <- [
          "SECRET_HUB_CLUSTER_NODE_ID",
          "AUDIT_HMAC_KEY",
          "AUDIT_HMAC_KEY_ID",
          "SECRET_HUB_MANAGEMENT_ORIGIN",
          "RELEASE_DISTRIBUTION=none"
        ] do
      assert workflow =~ input
    end

    assert workflow =~ "docs/security/runtime-contract.md"
  end

  test "active Core deployment examples pass a stable runtime identity" do
    deploy = read!("docs/deploy.md")
    readme = read!("README.md")

    deploy
    |> executable_core_blocks()
    |> Enum.each(fn block ->
      assert block =~ "SECRET_HUB_CLUSTER_NODE_ID",
             "Core execution block is missing stable node identity:\n#{block}"
    end)

    assert readme =~ "-e SECRET_HUB_CLUSTER_NODE_ID=core-replica-a"

    assert readme =~
             "| Core | `PHX_SERVER=true`, `DATABASE_URL`, `SECRET_KEY_BASE`, `PHX_HOST`, `SECRET_HUB_CLUSTER_NODE_ID` |"
  end

  test "Nix service requires a stable runtime identity without build defaults" do
    flake = read!("flake.nix")

    refute flake =~ "build-only-nix-core-package"

    assert flake =~ "nodeId = lib.mkOption"
    assert flake =~ "SECRET_HUB_CLUSTER_NODE_ID = cfg.nodeId"
  end

  defp read!(path), do: File.read!(Path.join(@repo_root, path))

  defp runtime_stage(dockerfile) do
    [_builder, runtime] = String.split(dockerfile, " AS runtime", parts: 2)
    runtime
  end

  defp executable_core_blocks(markdown) do
    ~r/```bash\n(.*?)```/s
    |> Regex.scan(markdown, capture: :all_but_first)
    |> List.flatten()
    |> Enum.filter(fn block ->
      (block =~ "docker run" and
         (block =~ "/core:" or block =~ "/core-standalone:")) or
        block =~ "bin/secrethub_core"
    end)
  end
end
