# SecretHub Human

SecretHub Human is the single umbrella application that owns the Human domain and its web
interface. It may call the public SecretHub Core boundary in one direction (`Human -> Core`),
but it must not use `SecretHub.Core.Repo`, Core schemas, direct Core tables, or cross-context
Ecto associations.

## Milestone 0 scope

Milestone 0 provides the isolated Human application, Repo, Endpoint, health surface, runtime
role selection, and combined-release foundation. Accounts, vault contents, Bitwarden
compatibility, dynamic secret reveals, and organizations are explicitly deferred.

The local service ports are:

- Core HTTP: `4664`
- trusted Agent mTLS: `4665`
- Human HTTP: `4666`

Human currently exposes `GET /` and `GET /health`.

## Runtime roles

Set `SECRETHUB_ROLE` to one of `all`, `core`, `human`, or `agent`:

- `all` and `human` enable the Human Repo, PubSub, and Endpoint.
- `core` and `agent` disable the entire Human supervision tree.
- The default is `core` in production and `all` in development and test.

In Milestone 0, roles select Human enablement only. Core and Web are not gated. The `human`
role therefore still uses the combined `secrethub_core` release as a facade foundation and
retains the existing Core/Web production requirements.

The combined production release requires these database and endpoint secrets when Human is
enabled:

- `DATABASE_URL`: Core PostgreSQL URL.
- `SECRET_KEY_BASE`: Core Endpoint signing secret.
- `HUMAN_DATABASE_URL`: independent Human PostgreSQL URL.
- `HUMAN_SECRET_KEY_BASE`: Human Endpoint signing secret.

It also retains the existing required `SECRET_HUB_CLUSTER_NODE_ID` Core node identity.
`HUMAN_DB_POOL_SIZE` controls the Human Repo pool and defaults to `40`.
`HUMAN_ENDPOINT_HOST` defaults to `localhost`, and `HUMAN_ENDPOINT_PORT` defaults to `4666`.
Set `PHX_SERVER=true` to start enabled HTTP endpoints.

When Human is disabled, no Human Repo, PubSub, or Endpoint process starts, and no
`HUMAN_DATABASE_URL`, `HUMAN_SECRET_KEY_BASE`, `HUMAN_ENDPOINT_HOST`,
`HUMAN_ENDPOINT_PORT`, or `HUMAN_DB_POOL_SIZE` value is required.

## Database lifecycle

Human uses databases independent from Core:

- development: `secrethub_human_dev`
- test: `secrethub_human_test`

From the umbrella root, manage each Repo explicitly:

```sh
# Core
mix ecto.create -r SecretHub.Core.Repo
mix ecto.migrate -r SecretHub.Core.Repo
mix ecto.migrations -r SecretHub.Core.Repo

# Human
mix ecto.create -r SecretHub.Human.Repo
mix ecto.migrate -r SecretHub.Human.Repo
mix ecto.migrations -r SecretHub.Human.Repo
```

The existing `db-setup`, `db-reset`, and `db-migrate` commands manage both Repos while keeping
the Core seed script Core-only. In a built release, migrate Human independently with:

```sh
bin/secrethub_core eval "SecretHub.Human.Release.migrate()"
```
