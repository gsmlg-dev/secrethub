ExUnit.start()

# Start applications (Repo will be started with Sandbox pool from config/test.exs)
{:ok, _} = Application.ensure_all_started(:secrethub_core)
{:ok, _} = Application.ensure_all_started(:secrethub_web)

# Set up Ecto Sandbox for database isolation in tests
Ecto.Adapters.SQL.Sandbox.mode(SecretHub.Core.Repo, :manual)

# Import support modules
Code.require_file("support/conn_case.ex", __DIR__)
Code.require_file("support/channel_case.ex", __DIR__)
