defmodule SecretHub.Agent.SSH.ServerTest do
  use ExUnit.Case, async: true
  alias SecretHub.Agent.SSH.{Helper, Identity, Server}
  @moduletag :tmp_dir

  setup do
    dir =
      Path.join(
        System.user_home!(),
        "sh-" <> Integer.to_string(System.unique_integer([:positive]))
      )

    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf(dir) end)
    task_supervisor = start_supervised!({Task.Supervisor, []})
    %{dir: dir, task_supervisor: task_supervisor}
  end

  test "first use enrolls locally, lists Core-authorized keys and signs without key material",
       ctx do
    {:ok, identity} = Identity.current()
    parent = self()
    key_root = Path.join(ctx.dir, "keys")

    request = fn
      "identity_report", payload ->
        send(parent, {:report, payload})
        {:ok, %{"accepted" => true}}

      "identities", payload ->
        send(parent, {:identities, payload})
        {:ok, local} = SecretHub.Agent.SSH.KeyStore.load(identity.uid, 1, key_root)

        {:ok, %{"identities" => [%{"public_key" => local.public.public_line, "generation" => 1}]}}

      "authorize_sign", payload ->
        send(parent, {:authorize, payload})
        {:ok, %{"allowed" => true, "public_key" => payload["public_key"]}}
    end

    path = Path.join(ctx.dir, "sign.sock")

    start_supervised!(
      {Server,
       path: path,
       kind: :signing,
       task_supervisor: ctx.task_supervisor,
       request: request,
       key_root: key_root}
    )

    {:ok, socket} = :gen_tcp.connect({:local, path}, 0, [:binary, active: false, packet: 4])
    :ok = :gen_tcp.send(socket, <<11>>)
    assert {:ok, <<12, 1::32, _::binary>>} = :gen_tcp.recv(socket, 0, 2000)
    assert_receive {:report, %{"uid" => uid, "generation" => 1, "public_key" => line}}
    assert uid == identity.uid
    refute line =~ "PRIVATE"
    assert_receive {:identities, %{"uid" => ^uid, "username" => user}}
    assert user == identity.username

    {:ok, local} = SecretHub.Agent.SSH.KeyStore.load(identity.uid, 1, key_root)
    blob = local.public.blob
    data = "challenge"
    sign = <<13, byte_size(blob)::32, blob::binary, byte_size(data)::32, data::binary, 0::32>>
    :ok = :gen_tcp.send(socket, sign)
    assert {:ok, <<14, _::binary>>} = :gen_tcp.recv(socket, 0, 2000)
    assert_receive {:authorize, %{"public_key" => _}}

    :ok = :gen_tcp.send(socket, <<17>>)
    assert {:ok, <<5>>} = :gen_tcp.recv(socket, 0, 2000)
    :gen_tcp.close(socket)
    assert {:ok, %{mode: mode}} = File.stat(path)
    assert Bitwise.band(mode, 0o777) == 0o660
  end

  test "a key unknown locally or denied by Core is not signed", ctx do
    {:ok, identity} = Identity.current()
    key_root = Path.join(ctx.dir, "keys")
    {:ok, local} = SecretHub.Agent.SSH.KeyStore.create(identity.uid, 1, key_root)
    {:ok, other} = SecretHub.Shared.SSH.Key.generate("ed25519")
    blob = local.public.blob
    path = Path.join(ctx.dir, "deny.sock")

    start_supervised!(
      {Server,
       path: path,
       kind: :signing,
       task_supervisor: ctx.task_supervisor,
       key_root: key_root,
       request: fn "authorize_sign", _ -> {:error, :denied} end}
    )

    {:ok, socket} = :gen_tcp.connect({:local, path}, 0, [:binary, active: false, packet: 4])

    for key <- [blob, other.public.blob] do
      sign = <<13, byte_size(key)::32, key::binary, 1::32, "x", 0::32>>
      :ok = :gen_tcp.send(socket, sign)
      assert {:ok, <<5>>} = :gen_tcp.recv(socket, 0, 2000)
    end

    :gen_tcp.close(socket)
  end

  test "Core allowed=false or a different returned key is not signed", ctx do
    {:ok, identity} = Identity.current()
    key_root = Path.join(ctx.dir, "keys")
    {:ok, local} = SecretHub.Agent.SSH.KeyStore.create(identity.uid, 1, key_root)
    {:ok, other} = SecretHub.Shared.SSH.Key.generate("ed25519")
    blob = local.public.blob
    sign = <<13, byte_size(blob)::32, blob::binary, 1::32, "x", 0::32>>

    replies = [
      %{"allowed" => false, "public_key" => local.public.encoded},
      %{"allowed" => true, "public_key" => other.public.encoded}
    ]

    for {reply, index} <- Enum.with_index(replies) do
      path = Path.join(ctx.dir, "bad#{index}.sock")

      start_supervised!(
        Supervisor.child_spec(
          {Server,
           path: path,
           kind: :signing,
           task_supervisor: ctx.task_supervisor,
           key_root: key_root,
           request: fn "authorize_sign", _ -> {:ok, reply} end},
          id: {:bad, index}
        )
      )

      {:ok, socket} = :gen_tcp.connect({:local, path}, 0, [:binary, active: false, packet: 4])
      :ok = :gen_tcp.send(socket, sign)
      assert {:ok, <<5>>} = :gen_tcp.recv(socket, 0, 2000)
      :gen_tcp.close(socket)
    end
  end

  test "public lookup rejects forged fields and never accepts private RPCs", ctx do
    parent = self()

    request = fn op, payload ->
      send(parent, {op, payload})
      {:ok, %{"lines" => []}}
    end

    path = Path.join(ctx.dir, "lookup.sock")

    start_supervised!(
      {Server, path: path, kind: :lookup, task_supervisor: ctx.task_supervisor, request: request}
    )

    assert {:error, _} =
             Helper.lookup(path, %{
               "operation" => "authorized_keys",
               "username" => "nobody",
               "key" => Base.encode64("bad")
             })

    refute_receive {"authorized_keys", _}

    assert {:error, _} =
             Helper.lookup(path, %{"operation" => "authorize_sign", "username" => "root"})

    assert {:error, _} =
             Helper.lookup(path, %{
               "operation" => "known_hosts",
               "reason" => "ORDER",
               "host" => "example.com",
               "port" => 22,
               "uid" => 0
             })

    refute_receive {_, _}
  end

  test "an abruptly killed listener safely reclaims its own stale Unix socket", ctx do
    path = Path.join(ctx.dir, "crash.sock")

    spec =
      {Server,
       path: path,
       kind: :signing,
       task_supervisor: ctx.task_supervisor,
       key_root: Path.join(ctx.dir, "keys"),
       request: fn _, _ -> {:ok, %{"identities" => []}} end}

    supervisor =
      start_supervised!(%{
        id: :crash_supervisor,
        start: {Supervisor, :start_link, [[spec], [strategy: :one_for_one]]},
        type: :supervisor
      })

    [{_, server, _, _}] = Supervisor.which_children(supervisor)
    monitor = Process.monitor(server)
    Process.exit(server, :kill)
    assert_receive {:DOWN, ^monitor, _, _, :killed}
    Process.sleep(100)
    assert Process.alive?(supervisor)
    {:ok, socket} = :gen_tcp.connect({:local, path}, 0, [:binary, active: false, packet: 4])
    :ok = :gen_tcp.send(socket, <<11>>)
    assert {:ok, <<12, 0::32>>} = :gen_tcp.recv(socket, 0, 1000)
    :gen_tcp.close(socket)
  end

  test "untrusted parents and regular, symlink or live socket paths are preserved", ctx do
    path = Path.join(ctx.dir, "protected.sock")
    opts = [path: path, kind: :lookup, task_supervisor: ctx.task_supervisor]
    File.chmod!(ctx.dir, 0o777)
    assert {:error, {:ssh_listener_unavailable, _}} = start_supervised({Server, opts})
    File.chmod!(ctx.dir, 0o755)
    File.write!(path, "keep")
    assert {:error, {:ssh_listener_unavailable, _}} = start_supervised({Server, opts})
    assert File.read!(path) == "keep"
    File.rm!(path)
    File.ln_s!(Path.join(ctx.dir, "missing"), path)
    assert {:error, {:ssh_listener_unavailable, _}} = start_supervised({Server, opts})
    assert {:ok, _} = File.read_link(path)
    File.rm!(path)
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ifaddr: {:local, path}])
    assert {:error, {:ssh_listener_unavailable, _}} = start_supervised({Server, opts})
    assert {:ok, socket} = :gen_tcp.connect({:local, path}, 0, [:binary, active: false])
    :gen_tcp.close(socket)
    :gen_tcp.close(listener)
  end

  test "one deadline bounds fragmented framing instead of restarting per read", ctx do
    path = Path.join(ctx.dir, "deadline.sock")

    start_supervised!(
      {Server,
       path: path,
       kind: :signing,
       task_supervisor: ctx.task_supervisor,
       timeout: 200,
       key_root: Path.join(ctx.dir, "keys"),
       request: fn _, _ -> {:ok, %{"identities" => []}} end}
    )

    {:ok, socket} = :gen_tcp.connect({:local, path}, 0, [:binary, active: false, packet: :raw])
    Process.sleep(125)
    :gen_tcp.send(socket, <<1::32>>)
    Process.sleep(125)
    :gen_tcp.send(socket, <<11>>)
    assert {:error, :closed} = :gen_tcp.recv(socket, 0, 1000)
  end

  test "listener cleanup permits a clean service restart and outages fail closed", ctx do
    path = Path.join(ctx.dir, "restart.sock")

    spec =
      {Server,
       path: path,
       kind: :lookup,
       task_supervisor: ctx.task_supervisor,
       request: fn _, _ -> {:error, :core_unavailable} end}

    start_supervised!(spec)
    stop_supervised!({Server, :lookup})
    refute File.exists?(path)
    start_supervised!(spec)

    assert {:error, _} =
             Helper.lookup(path, %{
               "operation" => "known_hosts",
               "reason" => "ORDER",
               "host" => "example.com",
               "port" => 22
             })

    assert {:error, :account_service_unavailable} =
             Identity.command("getent", ["group", "secrethub-no-such-group"])
  end

  test "oversized frames close before allocation and idle clients time out", ctx do
    path = Path.join(ctx.dir, "bounded.sock")

    start_supervised!(
      {Server,
       path: path,
       kind: :signing,
       task_supervisor: ctx.task_supervisor,
       timeout: 50,
       request: fn _, _ -> flunk("not called") end}
    )

    {:ok, socket} = :gen_tcp.connect({:local, path}, 0, [:binary, active: false])
    :gen_tcp.send(socket, <<1_048_577::32>>)
    assert {:error, :closed} = :gen_tcp.recv(socket, 0, 1000)
    {:ok, idle} = :gen_tcp.connect({:local, path}, 0, [:binary, active: false])
    assert {:error, :closed} = :gen_tcp.recv(idle, 0, 1000)
  end
end
