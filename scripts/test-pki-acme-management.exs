# Scoped management contracts without starting unrelated endpoints/engines.
for app <- [:postgrex, :ecto_sql, :phoenix, :phoenix_live_view, :jose] do
  Application.ensure_all_started(app)
end

Application.load(:castore)
{:ok, endpoint} = SecretHub.Web.Endpoint.start_link(server: false)
Process.unlink(endpoint)
{:ok, repo} = SecretHub.Core.Repo.start_link()
Ecto.Adapters.SQL.Sandbox.mode(SecretHub.Core.Repo, :manual)
Process.unlink(repo)
ExUnit.start()

Code.require_file(
  "apps/secrethub_web/test/secrethub_web_web/controllers/acme_management_test.exs"
)
