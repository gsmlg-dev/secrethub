defmodule SecretHub.Core.ApplicationTest do
  use ExUnit.Case, async: false

  alias SecretHub.Core.{
    Agents.ConnectionManager,
    Application,
    Cache,
    ClusterState,
    LeaseManager,
    Repo,
    Vault.SealState,
    Workers.ClientAuthCRLRefresher
  }

  @runtime_children [
    Repo,
    SealState,
    ClusterState,
    LeaseManager,
    ConnectionManager,
    ClientAuthCRLRefresher
  ]

  setup do
    original_env = Elixir.Application.get_env(:secrethub_core, :env)

    on_exit(fn ->
      restore_application_env(:env, original_env)
    end)

    :ok
  end

  test "includes database-backed children in dependency order in development and production" do
    for env <- [:dev, :prod] do
      Elixir.Application.put_env(:secrethub_core, :env, env)

      assert Enum.map(Application.children(), &child_id/1) == [Cache | @runtime_children]
    end
  end

  test "excludes database-backed children in test runtime" do
    Elixir.Application.put_env(:secrethub_core, :env, :test)

    assert Enum.map(Application.children(), &child_id/1) == [Cache]
  end

  test "nil bootstrap environment excludes database-backed children" do
    Elixir.Application.delete_env(:secrethub_core, :env)

    child_ids = Enum.map(Application.children(), &child_id/1)

    assert child_ids == [Cache]
    Enum.each(@runtime_children, &refute(&1 in child_ids))
  end

  test "central config records the Config environment" do
    config_path = Path.expand("../../../../config/config.exs", __DIR__)

    for env <- [:dev, :test, :prod] do
      config = Config.Reader.read!(config_path, env: env)

      assert config
             |> Keyword.fetch!(:secrethub_core)
             |> Keyword.fetch!(:env) == env
    end
  end

  test "sandbox repair stops runtime children in reverse dependency order" do
    test_helper = File.read!(Path.expand("../test_helper.exs", __DIR__))

    assert [_, repair_children] =
             Regex.run(
               ~r/repair_child_ids = \[(.*?)\]\n\n  for child_id <- repair_child_ids/s,
               test_helper
             )

    assert Regex.scan(~r/SecretHub\.Core(?:\.[A-Z][A-Za-z]+)+/, repair_children)
           |> List.flatten() == [
             "SecretHub.Core.Agents.ConnectionManager",
             "SecretHub.Core.LeaseManager",
             "SecretHub.Core.ClusterState",
             "SecretHub.Core.Vault.SealState"
           ]
  end

  test "development config provides a deterministic cluster node identity default" do
    original_node_id = System.get_env("SECRET_HUB_CLUSTER_NODE_ID")
    System.delete_env("SECRET_HUB_CLUSTER_NODE_ID")

    on_exit(fn ->
      restore_system_env("SECRET_HUB_CLUSTER_NODE_ID", original_node_id)
    end)

    config_path = Path.expand("../../../../config/dev.exs", __DIR__)
    config = Config.Reader.read!(config_path)

    assert config
           |> Keyword.fetch!(:secrethub_core)
           |> Keyword.fetch!(:cluster_node_id) == "secrethub-dev"
  end

  defp child_id(module) when is_atom(module), do: module
  defp child_id({module, _opts}) when is_atom(module), do: module
  defp child_id(%{id: id}), do: id

  defp restore_application_env(key, nil),
    do: Elixir.Application.delete_env(:secrethub_core, key)

  defp restore_application_env(key, value),
    do: Elixir.Application.put_env(:secrethub_core, key, value)

  defp restore_system_env(key, nil), do: System.delete_env(key)
  defp restore_system_env(key, value), do: System.put_env(key, value)
end
