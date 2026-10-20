defmodule SecretHub.Web.UnifiedAgentTLSFixture do
  @moduledoc false

  alias SecretHub.Core.PKI.CSR

  def generate!(dir) do
    File.mkdir_p!(dir)
    ca!(dir, "ca")
    ca!(dir, "unknown-ca")
    leaf!(dir, "server", "ca", "serverAuth", "DNS:localhost")

    leaf!(
      dir,
      "client",
      "ca",
      "clientAuth",
      "URI:urn:secrethub:agent:tls-test,URI:urn:secrethub:hostkey-sha256:tls-test-host"
    )

    leaf!(dir, "unknown-client", "unknown-ca", "clientAuth", "DNS:unknown")

    %{
      dir: dir,
      ca: path(dir, "ca.crt"),
      cert: path(dir, "server.crt"),
      key: path(dir, "server.key")
    }
  end

  def config(fixture) do
    [
      adapter: Bandit.PhoenixAdapter,
      server: true,
      http: false,
      secret_key_base: String.duplicate("unified-agent-test", 8),
      pubsub_server: SecretHub.Web.PubSub,
      https: [
        ip: {127, 0, 0, 1},
        port: 0,
        certfile: fixture.cert,
        keyfile: fixture.key,
        thousand_island_options: [
          transport_options: [
            cacertfile: to_charlist(fixture.ca),
            verify: :verify_peer,
            fail_if_no_peer_cert: false,
            versions: [:"tlsv1.2"]
          ]
        ]
      ]
    ]
  end

  def enrollment_attrs(fixture) do
    [entry] = fixture.dir |> Path.join("client.key") |> File.read!() |> :public_key.pem_decode()
    private_key = :public_key.pem_entry_decode(entry)
    public_key = :ssh_file.extract_public_key(private_key)

    public =
      :ssh_file.encode([{public_key, []}], :openssh_key) |> IO.iodata_to_binary() |> String.trim()

    %{
      "hostname" => "unified-tls-test",
      "machine_id" => "tls-#{System.unique_integer([:positive])}",
      "os" => "linux",
      "arch" => "x86_64",
      "agent_version" => "1.2.3",
      "ssh_host_key_algorithm" => "rsa",
      "ssh_host_public_key" => public,
      "ssh_host_key_fingerprint" => CSR.ssh_fingerprint(public_key)
    }
  end

  def connect(fixture, port, opts \\ []) do
    :ssl.connect(
      ~c"localhost",
      port,
      Keyword.merge(
        [
          active: false,
          mode: :binary,
          verify: :verify_peer,
          cacertfile: to_charlist(fixture.ca),
          server_name_indication: ~c"localhost",
          versions: [:"tlsv1.2"]
        ],
        opts
      ),
      5_000
    )
  end

  def request(socket, method, path, body \\ "", headers \\ []) do
    :ok =
      :ssl.send(socket, [
        method,
        " ",
        path,
        " HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n",
        "Content-Type: application/json\r\nContent-Length: ",
        to_string(byte_size(body)),
        "\r\n",
        Enum.map(headers, fn {key, value} -> [key, ": ", value, "\r\n"] end),
        "\r\n",
        body
      ])

    receive_all(socket, "")
  end

  def upgrade(socket, params \\ "", headers \\ []) do
    :ok =
      :ssl.send(socket, [
        "GET /agent/socket/websocket?vsn=2.0.0",
        params,
        " HTTP/1.1\r\nHost: localhost\r\n",
        "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n",
        "Sec-WebSocket-Key: ",
        Base.encode64(:crypto.strong_rand_bytes(16)),
        "\r\n",
        Enum.map(headers, fn {key, value} -> [key, ": ", value, "\r\n"] end),
        "\r\n"
      ])

    {:ok, response} = :ssl.recv(socket, 0, 5_000)
    response
  end

  def join_runtime(socket) do
    payload = Jason.encode!(["1", "1", "agent:runtime", "phx_join", %{"agent_id" => "forged"}])
    mask = :crypto.strong_rand_bytes(4)

    masked =
      for {byte, i} <- Enum.with_index(:binary.bin_to_list(payload)),
          into: <<>>,
          do: <<Bitwise.bxor(byte, :binary.at(mask, rem(i, 4)))>>

    :ok = :ssl.send(socket, [<<0x81, 0x80 + byte_size(payload)>>, mask, masked])
    {:ok, <<0x81, len, rest::binary>>} = :ssl.recv(socket, 0, 5_000)

    {length, rest} =
      case len do
        126 ->
          <<size::16, body::binary>> = rest
          {size, body}

        size when size < 126 ->
          {size, rest}
      end

    payload =
      if byte_size(rest) < length do
        {:ok, more} = :ssl.recv(socket, length - byte_size(rest), 5_000)
        rest <> more
      else
        rest
      end

    payload |> binary_part(0, length) |> Jason.decode!()
  end

  defp receive_all(socket, acc) do
    case :ssl.recv(socket, 0, 5_000) do
      {:ok, data} -> receive_all(socket, acc <> data)
      {:error, :closed} -> acc
      {:error, reason} -> raise "TLS response failed: #{inspect(reason)}"
    end
  end

  defp ca!(dir, name) do
    openssl!([
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-days",
      "1",
      "-subj",
      "/CN=#{name}",
      "-keyout",
      path(dir, "#{name}.key"),
      "-out",
      path(dir, "#{name}.crt")
    ])
  end

  defp leaf!(dir, name, ca, usage, san) do
    openssl!([
      "req",
      "-new",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-subj",
      "/CN=#{name}",
      "-keyout",
      path(dir, "#{name}.key"),
      "-out",
      path(dir, "#{name}.csr")
    ])

    ext = path(dir, "#{name}.ext")

    File.write!(
      ext,
      "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=#{usage}\nsubjectAltName=#{san}\n"
    )

    openssl!([
      "x509",
      "-req",
      "-in",
      path(dir, "#{name}.csr"),
      "-CA",
      path(dir, "#{ca}.crt"),
      "-CAkey",
      path(dir, "#{ca}.key"),
      "-CAcreateserial",
      "-days",
      "1",
      "-extfile",
      ext,
      "-out",
      path(dir, "#{name}.crt")
    ])
  end

  defp openssl!(args) do
    case System.cmd("openssl", args, stderr_to_stdout: true) do
      {_, 0} -> :ok
      {output, status} -> raise "openssl failed (#{status}): #{output}"
    end
  end

  defp path(dir, name), do: Path.join(dir, name)
end
