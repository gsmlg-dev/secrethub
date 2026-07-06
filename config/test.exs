import Config

# Set test environment flag
config :secrethub_core, env: :test

# Disable SealState in test mode (it tries to write to DB during init, before Sandbox is set up)
config :secrethub_core, start_seal_state: false

# Configure the database
# Supports both Unix socket (devenv) and TCP (CI) connections
database_name = "secrethub_test#{System.get_env("MIX_TEST_PARTITION")}"

test_pool_size =
  System.get_env("TEST_DB_POOL_SIZE", "20")
  |> String.to_integer()

db_config = [
  username: System.get_env("PGUSER", "secrethub"),
  password: System.get_env("PGPASSWORD", "secrethub_dev_password"),
  database: database_name,
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: test_pool_size
]

project_socket_dir = Path.expand("../.devenv/state/postgres", __DIR__)

socket_port = fn socket_dir ->
  configured_port =
    Path.join(socket_dir, "postgresql.conf")
    |> File.read()
    |> case do
      {:ok, contents} ->
        Regex.run(~r/^port\s*=\s*(\d+)/m, contents, capture: :all_but_first)

      {:error, _reason} ->
        nil
    end
    |> case do
      [port] -> port
      _ -> nil
    end

  socket_file_port =
    socket_dir
    |> Path.join(".s.PGSQL.*")
    |> Path.wildcard()
    |> List.first()
    |> case do
      nil -> nil
      path -> Path.basename(path) |> String.replace_prefix(".s.PGSQL.", "")
    end

  (configured_port || socket_file_port || System.get_env("PGPORT") || "5432")
  |> String.to_integer()
end

database_url_config = fn database_url ->
  uri = URI.parse(database_url)
  query = URI.decode_query(uri.query || "")

  url_config =
    case uri.userinfo && String.split(uri.userinfo, ":", parts: 2) do
      [username, password] ->
        [username: URI.decode(username), password: URI.decode(password)]

      [username] ->
        [username: URI.decode(username)]

      _ ->
        []
    end

  url_config =
    case query["host"] || uri.host do
      "/" <> _ = socket_dir ->
        port = query["port"] || uri.port || socket_port.(socket_dir)

        url_config
        |> Keyword.put(:socket_dir, socket_dir)
        |> Keyword.put(:port, String.to_integer(to_string(port)))

      hostname when is_binary(hostname) ->
        port = query["port"] || uri.port || System.get_env("DATABASE_PORT", "5432")

        url_config
        |> Keyword.put(:hostname, hostname)
        |> Keyword.put(:port, String.to_integer(to_string(port)))

      _ ->
        url_config
    end

  case uri.path do
    "/" <> url_database when url_database != "" ->
      Keyword.put(url_config, :database, URI.decode(url_database))

    _ ->
      url_config
  end
end

db_config =
  cond do
    database_url = System.get_env("DATABASE_TEST_URL") || System.get_env("DATABASE_URL") ->
      db_config
      |> Keyword.merge(database_url_config.(database_url))
      |> Keyword.put(:database, database_name)

    socket_dir = System.get_env("PGHOST") ->
      # Use Unix domain socket (devenv local development)
      db_config
      |> Keyword.put(:socket_dir, socket_dir)
      |> Keyword.put(:port, socket_port.(socket_dir))

    devenv_state = System.get_env("DEVENV_STATE") ->
      socket_dir = Path.join(devenv_state, "postgres")

      db_config
      |> Keyword.put(:socket_dir, socket_dir)
      |> Keyword.put(:port, socket_port.(socket_dir))

    File.dir?(project_socket_dir) ->
      db_config
      |> Keyword.put(:socket_dir, project_socket_dir)
      |> Keyword.put(:port, socket_port.(project_socket_dir))

    true ->
      # Use TCP connection (CI environment)
      db_config
      |> Keyword.put(:hostname, System.get_env("DATABASE_HOST", "localhost"))
      |> Keyword.put(:port, String.to_integer(System.get_env("DATABASE_PORT", "5432")))
  end

config :secrethub_core, SecretHub.Core.Repo, db_config

# We don't run a server during test. If one is required,
# you can enable the server option below.
config :secrethub_web, SecretHub.Web.Endpoint,
  http: [ip: {127, 0, 0, 1}, port: 4002],
  secret_key_base: "2ZOJa2EtaKKkdOjsRG7Ph4JsrwXMy1A1zDkWadar3rKTkRmfTMnO0nSVfIUjaiA7",
  server: false

# In test we don't send emails
config :secrethub_web, SecretHub.Web.Mailer, adapter: Swoosh.Adapters.Test

# Disable swoosh api client as it is only required for production adapters
config :swoosh, :api_client, false

# Print only warnings and errors during test
config :logger, level: :warning

# Initialize plugs at runtime for faster test compilation
config :phoenix, :plug_init_mode, :runtime

# Enable helpful, but potentially expensive runtime checks
config :phoenix_live_view,
  enable_expensive_runtime_checks: true

# Disable agent application in test mode so unit tests can manage their own processes
config :secrethub_agent,
  enabled: false,
  socket_path: "/tmp/secrethub_test_agent.sock"
