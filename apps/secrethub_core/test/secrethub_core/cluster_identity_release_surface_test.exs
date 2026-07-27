defmodule SecretHub.Core.ClusterIdentityReleaseSurfaceTest do
  use ExUnit.Case, async: true

  @repo_root Path.expand("../../../..", __DIR__)

  test "Core Dockerfiles provide build identities without defaulting production runtime identities" do
    core = read!("Dockerfile.core")
    standalone = read!("Dockerfile.core-standalone")

    assert core =~ "ENV SECRET_HUB_CLUSTER_NODE_ID=build-only-"
    refute runtime_stage(core) =~ "ENV SECRET_HUB_CLUSTER_NODE_ID="

    assert standalone =~ "ENV SECRET_HUB_CLUSTER_NODE_ID=build-only-"
    refute runtime_stage(standalone) =~ "ENV SECRET_HUB_CLUSTER_NODE_ID="
  end

  test "release workflow wires build identity and generated runtime examples" do
    workflow = read!(".github/workflows/release.yml")

    assert workflow =~ "BUILD_CLUSTER_NODE_ID: 'build-only-"

    assert count(workflow, "SECRET_HUB_CLUSTER_NODE_ID: ${{ env.BUILD_CLUSTER_NODE_ID }}") >=
             3

    assert workflow =~ "-e SECRET_HUB_CLUSTER_NODE_ID=core-replica-a"
    assert workflow =~ "-e SECRET_HUB_CLUSTER_NODE_ID=secrethub-core-standalone"
    assert workflow =~ "export SECRET_HUB_CLUSTER_NODE_ID=core-replica-a"
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

  test "Nix build and service module wire build and stable runtime identities" do
    flake = read!("flake.nix")

    assert flake =~
             ~s(SECRET_HUB_CLUSTER_NODE_ID="build-only-nix-core-package")

    assert flake =~ "nodeId = lib.mkOption"
    assert flake =~ "SECRET_HUB_CLUSTER_NODE_ID = cfg.nodeId"
  end

  defp read!(path), do: File.read!(Path.join(@repo_root, path))

  defp runtime_stage(dockerfile) do
    [_builder, runtime] = String.split(dockerfile, " AS runtime", parts: 2)
    runtime
  end

  defp count(contents, needle) do
    contents
    |> String.split(needle)
    |> length()
    |> Kernel.-(1)
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
