defmodule SecretHub.Human.RepoBoundaryTest do
  use ExUnit.Case, async: true

  alias SecretHub.Human.Repo, as: HumanRepo

  test "registers only the Human repository for the Human application" do
    assert Application.fetch_env!(:secrethub_human, :ecto_repos) == [HumanRepo]
  end

  test "uses the PostgreSQL adapter without joining the Core repository list" do
    assert HumanRepo.__adapter__() == Ecto.Adapters.Postgres
    refute HumanRepo in Application.fetch_env!(:secrethub_core, :ecto_repos)
  end

  test "uses a dedicated sandboxed Human test database" do
    config = Application.fetch_env!(:secrethub_human, HumanRepo)

    assert config[:database] ==
             "secrethub_human_test#{System.get_env("MIX_TEST_PARTITION")}"

    assert config[:pool] == Ecto.Adapters.SQL.Sandbox
  end

  test "resolves migrations from the Human application priv directory" do
    assert Ecto.Migrator.migrations_path(HumanRepo) ==
             Application.app_dir(:secrethub_human, "priv/repo/migrations")
  end
end
