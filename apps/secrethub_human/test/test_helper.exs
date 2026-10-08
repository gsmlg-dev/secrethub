ExUnit.start()
Ecto.Migrator.run(SecretHub.Human.Repo, :up, all: true, log: false)
Ecto.Adapters.SQL.Sandbox.mode(SecretHub.Human.Repo, :manual)
