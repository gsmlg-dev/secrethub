defmodule SecretHub.Core.ApplicationTest do
  use ExUnit.Case, async: false

  alias SecretHub.Core.{Application, ClusterState, Repo, Vault.SealState}

  setup do
    original_env = Elixir.Application.get_env(:secrethub_core, :env)

    on_exit(fn ->
      Elixir.Application.put_env(:secrethub_core, :env, original_env)
    end)

    :ok
  end

  test "includes ClusterState after Repo and SealState outside test runtime" do
    Elixir.Application.put_env(:secrethub_core, :env, :prod)

    child_ids = Application.children() |> Enum.map(&child_id/1)

    assert Enum.find_index(child_ids, &(&1 == Repo)) <
             Enum.find_index(child_ids, &(&1 == SealState))

    assert Enum.find_index(child_ids, &(&1 == SealState)) <
             Enum.find_index(child_ids, &(&1 == ClusterState))
  end

  test "excludes ClusterState in test runtime" do
    Elixir.Application.put_env(:secrethub_core, :env, :test)

    refute ClusterState in Enum.map(Application.children(), &child_id/1)
  end

  defp child_id(module) when is_atom(module), do: module
  defp child_id({module, _opts}) when is_atom(module), do: module
  defp child_id(%{id: id}), do: id
end
