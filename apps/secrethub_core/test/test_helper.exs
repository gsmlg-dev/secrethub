ExUnit.start()

# Set up Ecto Sandbox for testing
Ecto.Adapters.SQL.Sandbox.mode(SecretHub.Core.Repo, :manual)
