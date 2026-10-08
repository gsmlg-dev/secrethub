# Disposable test-only fixture. Invoke with MIX_ENV=test; never use production data.
if Application.get_env(:secrethub_core, :env) != :test, do: raise("test environment required")
fixture = System.fetch_env!("HUMAN_CLIENT_FIXTURE") |> File.read!() |> Jason.decode!()
Logger.configure(level: :warning)
{:ok, _} = Application.ensure_all_started(:telemetry)

:telemetry.attach(
  "official-client-paths",
  [:phoenix, :endpoint, :stop],
  fn _, _, %{conn: conn}, _ ->
    if conn.request_path == "/api/ciphers" and conn.method == "POST" do
      if path = System.get_env("HUMAN_CLIENT_CIPHER_CAPTURE") do
        File.write!(path, Jason.encode!(conn.body_params))
        File.chmod!(path, 0o600)
      end
    end

    IO.puts(
      "CLIENT_REQUEST " <>
        conn.method <> " " <> conn.request_path <> " " <> to_string(conn.status)
    )
  end,
  nil
)

for {app, repo} <- [
      {:secrethub_core, SecretHub.Core.Repo},
      {:secrethub_human, SecretHub.Human.Repo}
    ] do
  config =
    Application.fetch_env!(app, repo)
    |> Keyword.put(:pool, DBConnection.ConnectionPool)
    |> Keyword.put(:log, false)

  Application.put_env(app, repo, config)
end

Application.put_env(
  :secrethub_human,
  SecretHub.HumanWeb.Endpoint,
  Application.fetch_env!(:secrethub_human, SecretHub.HumanWeb.Endpoint)
  |> Keyword.put(:server, true)
  |> Keyword.put(:url, scheme: "https", host: "127.0.0.1", port: 14_666)
  |> Keyword.put(:http, nil)
  |> Keyword.put(:https,
    ip: {127, 0, 0, 1},
    port: 14_666,
    certfile: System.fetch_env!("HUMAN_CLIENT_CERT"),
    keyfile: System.fetch_env!("HUMAN_CLIENT_KEY")
  )
)

{:ok, _} = Application.ensure_all_started(:secrethub_human)

{:ok, _, _} =
  Ecto.Migrator.with_repo(
    SecretHub.Human.Repo,
    &Ecto.Migrator.run(&1, :up, all: true, log: false)
  )

attrs = Map.take(fixture, ~w(email password_hash encrypted_key public_key encrypted_private_key))
{:ok, _} = SecretHub.Human.Accounts.provision(attrs, server_iterations: 1000)
IO.puts("HUMAN_OFFICIAL_CLIENT_FIXTURE_READY")

other_user =
  if path = System.get_env("HUMAN_OTHER_FIXTURE") do
    attrs =
      path
      |> File.read!()
      |> Jason.decode!()
      |> Map.take(~w(email password_hash encrypted_key public_key encrypted_private_key))

    {:ok, other_user} = SecretHub.Human.Accounts.provision(attrs, server_iterations: 1000)
    other_user
  end

if System.get_env("HUMAN_UI_BACKEND") == "true" do
  {:ok, _} = Supervisor.start_child(SecretHub.Core.Supervisor, SecretHub.Core.Repo)

  {:ok, _, _} =
    Ecto.Migrator.with_repo(
      SecretHub.Core.Repo,
      &Ecto.Migrator.run(&1, :up, all: true, log: false)
    )

  Code.require_file("apps/secrethub_core/test/human_access/postgres_fixture.exs")
  backend = SecretHub.Core.HumanAccess.PostgresFixture.start()
  # The harness records only the owned directory, so its runner can stop the fixture after exit.
  if path = System.get_env("HUMAN_UI_BACKEND_DIRECTORY"), do: File.write!(path, backend.directory)
  Application.put_env(:secrethub_core, :human_dynamic_enabled, true)
  Application.put_env(:secrethub_core, :human_identity_adapter, SecretHub.Human.CoreIdentity)

  :ok =
    SecretHub.Core.HumanAccess.configure_mounts(%{
      "postgres-browser" => %{
        engine: SecretHub.Core.HumanAccess.PostgreSQLBackend,
        connection: backend.connection,
        roles: %{
          "reader" => %{schema: "public", privileges: [:select]},
          "reviewed" => %{schema: "public", privileges: [:select]}
        }
      }
    })

  {:ok, session} =
    SecretHub.Human.Accounts.authenticate(fixture["email"], fixture["password_hash"], %{
      identifier: "fixture-provisioner"
    })

  for {role, approval} <- [{"reader", false}, {"reviewed", true}] do
    {:ok, _} =
      SecretHub.Core.HumanAccess.provision_grant(%{
        subject_id: session.actor.user_id,
        mount_id: "postgres-browser",
        role_id: role,
        allowed_operations: ~w(issue read renew revoke request_approval),
        max_ttl: 120,
        require_device: true,
        require_approval: approval,
        approver_subject_ids: [other_user.id]
      })
  end

  :ok = SecretHub.Human.Accounts.revoke_session(session.actor, session.actor.session_id)
  IO.puts("HUMAN_BROWSER_BACKEND_READY")
end
