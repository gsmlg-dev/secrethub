defmodule SecretHub.Core.Release do
  @moduledoc """
  Release tasks for SecretHub Core.

  Used to run migrations and other tasks in production releases
  where Mix is not available.

  ## Usage

      # Run all pending migrations
      bin/secrethub_core eval "SecretHub.Core.Release.migrate()"

      # Rollback last migration
      bin/secrethub_core eval "SecretHub.Core.Release.rollback(SecretHub.Core.Repo, 1)"
  """

  @app :secrethub_core

  def migrate do
    load_app()

    for repo <- repos() do
      {:ok, _, _} = Ecto.Migrator.with_repo(repo, &Ecto.Migrator.run(&1, :up, all: true))
    end
  end

  def rollback(repo, version) do
    load_app()
    {:ok, _, _} = Ecto.Migrator.with_repo(repo, &Ecto.Migrator.run(&1, :down, to: version))
  end

  defp repos do
    Application.fetch_env!(@app, :ecto_repos)
  end

  defp load_app do
    Application.load(@app)
  end
end
