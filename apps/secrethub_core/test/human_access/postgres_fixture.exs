defmodule SecretHub.Core.HumanAccess.PostgresFixture do
  @moduledoc false

  def start do
    directory =
      Path.join(
        System.tmp_dir!(),
        "sh-human-pg-" <> Base.encode16(:crypto.strong_rand_bytes(6), case: :lower)
      )

    File.mkdir_p!(directory)
    File.chmod!(directory, 0o700)
    data = Path.join(directory, "data")
    password_file = Path.join(directory, "password")
    password = Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false)
    File.write!(password_file, password)
    File.chmod!(password_file, 0o600)

    {_, 0} =
      System.cmd(
        "initdb",
        [
          "-D",
          data,
          "--username=human_fixture",
          "--auth-host=scram-sha-256",
          "--auth-local=scram-sha-256",
          "--pwfile",
          password_file
        ],
        stderr_to_stdout: true
      )

    {_, 0} =
      System.cmd(
        "pg_ctl",
        [
          "-D",
          data,
          "-l",
          Path.join(directory, "server.log"),
          "-o",
          "-k #{directory} -p 6543 -h '' -c password_encryption=scram-sha-256",
          "-w",
          "start"
        ],
        stderr_to_stdout: true
      )

    File.rm!(password_file)

    %{
      directory: directory,
      data: data,
      connection: [
        socket_dir: directory,
        port: 6543,
        database: "postgres",
        username: "human_fixture",
        password: password
      ]
    }
  end

  def stop(fixture) do
    {_, 0} =
      System.cmd("pg_ctl", ["-D", fixture.data, "-m", "fast", "-w", "stop"],
        stderr_to_stdout: true
      )

    File.rm_rf!(fixture.directory)
  end

  def query(fixture, sql, params \\ []) do
    {:ok, conn} = Postgrex.start_link(fixture.connection)

    try do
      Postgrex.query(conn, sql, params)
    after
      GenServer.stop(conn)
    end
  end

  def login(connection_opts) do
    parent = self()

    {pid, ref} =
      spawn_monitor(fn ->
        {:ok, connection} =
          Postgrex.start_link(Keyword.put(connection_opts, :backoff_type, :stop))

        result = Postgrex.query(connection, "SELECT current_user", [], timeout: 3000)
        send(parent, {self(), :login_result, result})
        GenServer.stop(connection)
      end)

    receive do
      {^pid, :login_result, result} ->
        Process.demonitor(ref, [:flush])
        result

      {:DOWN, ^ref, :process, ^pid, _} ->
        {:error, :connection_failed}
    after
      5000 ->
        Process.exit(pid, :kill)
        Process.demonitor(ref, [:flush])
        {:error, :connection_failed}
    end
  end
end
