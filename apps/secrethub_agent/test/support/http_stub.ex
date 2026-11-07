defmodule SecretHub.Agent.HTTPTest do
  @moduledoc false
  require ExUnit.Assertions

  def verify_on_exit! do
    server()
    :ok
  end

  def expect(name, count \\ 1, callback) do
    Agent.update(server(), fn state ->
      %{state | expectations: state.expectations ++ List.duplicate(callback, count)}
    end)

    name
  end

  def stub(name, callback) do
    Agent.update(server(), &%{&1 | stub: callback})
    name
  end

  def transport(_name) do
    server = server()

    fn method, url, options ->
      callback =
        Agent.get_and_update(server, fn
          %{expectations: [callback | rest]} = state ->
            {callback, %{state | expectations: rest}}

          state ->
            {state.stub, state}
        end)

      if is_nil(callback),
        do: ExUnit.Assertions.flunk("unexpected HTTP request: #{method} #{url}")

      conn = Plug.Test.conn(method, url, Keyword.get(options, :body, ""))
      conn = %{conn | req_headers: Keyword.get(options, :headers, [])}

      conn =
        Plug.Parsers.call(
          conn,
          Plug.Parsers.init(parsers: [:json], pass: ["*/*"], json_decoder: Jason)
        )

      response = callback.(conn)

      {:ok,
       HTTP.Response.new(
         status: response.status,
         headers: HTTP.Headers.new(response.resp_headers),
         body: response.resp_body
       )}
    end
  end

  def json(conn, body) do
    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.resp(conn.status || 200, Jason.encode!(body))
  end

  defp server do
    case Process.get(__MODULE__) do
      nil ->
        {:ok, server} = Agent.start_link(fn -> %{expectations: [], stub: nil} end)
        Process.unlink(server)
        Process.put(__MODULE__, server)

        ExUnit.Callbacks.on_exit(fn ->
          try do
            remaining = Agent.get(server, & &1.expectations)
            ExUnit.Assertions.assert(remaining == [], "not all expected HTTP requests were sent")
          after
            Agent.stop(server)
          end
        end)

        server

      server ->
        server
    end
  end
end
