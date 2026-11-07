defmodule SecretHub.Web.HTTPFetchApiClientTest do
  use ExUnit.Case, async: true

  alias SecretHub.Web.HTTPFetchApiClient

  test "returns streamed JSON as bytes with response headers for Swoosh adapters" do
    url =
      serve("""
      HTTP/1.1 202 Accepted\r
      Content-Type: application/json\r
      Transfer-Encoding: chunked\r
      X-Result: one\r
      X-Result: two\r
      \r
      B\r
      {"ok":true}\r
      0\r
      \r
      """)

    assert :ok = HTTPFetchApiClient.init()

    assert {:ok, 202, headers, "{\"ok\":true}"} =
             HTTPFetchApiClient.post(
               [url],
               [{"content-type", "application/json"}],
               "{}",
               %Swoosh.Email{}
             )

    assert {"content-type", "application/json"} in headers

    assert Enum.filter(headers, &(elem(&1, 0) == "x-result")) ==
             [{"x-result", "one"}, {"x-result", "two"}]

    assert_receive {:request, request}
    assert String.downcase(request) =~ "user-agent: swoosh/#{Swoosh.version()}"
  end

  test "returns an error when the provider closes an incomplete response" do
    url = serve("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort")

    assert {:error, _reason} = HTTPFetchApiClient.post(url, [], "message", %Swoosh.Email{})
  end

  defp serve(response) do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, {_ip, port}} = :inet.sockname(listener)
    owner = self()

    server =
      spawn_link(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 5_000)

        try do
          request = read_headers(socket, "")
          send(owner, {:request, request})
          :ok = :gen_tcp.send(socket, response)
        after
          :gen_tcp.close(socket)
        end
      end)

    on_exit(fn ->
      :gen_tcp.close(listener)
      if Process.alive?(server), do: Process.exit(server, :kill)
    end)

    "http://127.0.0.1:#{port}/mail"
  end

  defp read_headers(socket, buffer) do
    if String.contains?(buffer, "\r\n\r\n") do
      buffer
    else
      {:ok, chunk} = :gen_tcp.recv(socket, 0, 5_000)
      read_headers(socket, buffer <> chunk)
    end
  end
end
