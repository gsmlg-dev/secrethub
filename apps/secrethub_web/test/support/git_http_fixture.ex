defmodule SecretHub.Web.GitHTTPFixture do
  @moduledoc """
  Disposable authenticated Git smart-HTTP server for credential helper tests.

  Requests must carry HTTP Basic credentials matching `:user`/`:password`;
  accepted requests are served by the real `git http-backend` CGI over the
  repositories in `:root`.
  """
  @behaviour Plug
  import Plug.Conn

  def start(root, user, password) do
    {:ok, pid} =
      Bandit.start_link(
        plug: {__MODULE__, %{root: root, user: user, password: password}},
        ip: {127, 0, 0, 1},
        port: 0,
        startup_log: false
      )

    {:ok, {_ip, port}} = ThousandIsland.listener_info(pid)
    {pid, port}
  end

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, opts) do
    expected = "Basic " <> Base.encode64(opts.user <> ":" <> opts.password)

    case get_req_header(conn, "authorization") do
      [^expected] ->
        backend(conn, opts)

      _ ->
        conn
        |> put_resp_header("www-authenticate", ~s(Basic realm="secrethub-test"))
        |> send_resp(401, "unauthorized")
    end
  end

  defp backend(conn, opts) do
    {:ok, body, conn} = read_body(conn, length: 16_000_000)
    input = Path.join(System.tmp_dir!(), "git-http-#{System.unique_integer([:positive])}")
    File.write!(input, body)

    env = [
      {"GIT_PROJECT_ROOT", opts.root},
      {"GIT_HTTP_EXPORT_ALL", "1"},
      {"PATH_INFO", conn.request_path},
      {"REQUEST_METHOD", conn.method},
      {"QUERY_STRING", conn.query_string},
      {"CONTENT_TYPE", List.first(get_req_header(conn, "content-type")) || ""},
      {"GIT_PROTOCOL", List.first(get_req_header(conn, "git-protocol")) || ""},
      {"REMOTE_USER", opts.user},
      {"REMOTE_ADDR", "127.0.0.1"}
    ]

    {output, 0} =
      System.cmd("sh", ["-c", ~s(exec git http-backend < "$1"), "sh", input], env: env)

    File.rm(input)
    {headers, payload} = split_cgi(output)

    conn =
      Enum.reduce(headers, conn, fn
        {"status", _}, acc -> acc
        {name, value}, acc -> put_resp_header(acc, name, value)
      end)

    status =
      case List.keyfind(headers, "status", 0) do
        {_, value} -> value |> String.split(" ") |> hd() |> String.to_integer()
        nil -> 200
      end

    send_resp(conn, status, payload)
  end

  defp split_cgi(output) do
    [head, payload] =
      case String.split(output, "\r\n\r\n", parts: 2) do
        [head, payload] -> [head, payload]
        [_] -> String.split(output, "\n\n", parts: 2)
      end

    headers =
      head
      |> String.split(~r/\r?\n/, trim: true)
      |> Enum.map(fn line ->
        [name, value] = String.split(line, ":", parts: 2)
        {String.downcase(name), String.trim(value)}
      end)

    {headers, payload}
  end
end
