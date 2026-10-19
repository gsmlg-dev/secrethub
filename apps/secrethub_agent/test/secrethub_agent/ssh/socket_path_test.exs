defmodule SecretHub.Agent.SSH.SocketPathTest do
  use ExUnit.Case, async: false
  import ExUnit.CaptureIO
  alias SecretHub.Agent.SSH.{Helper, SocketPath}

  setup do
    name = ".shp-" <> Base.url_encode64(:crypto.strong_rand_bytes(9), padding: false)
    dir = Path.join(System.user_home!(), name)
    File.mkdir!(dir)
    on_exit(fn -> File.rm_rf(dir) end)
    %{dir: dir}
  end

  test "listener rejects symlink and writable ancestors above a safe direct parent", ctx do
    real = Path.join(ctx.dir, "real")
    File.mkdir_p!(Path.join(real, "nested"))
    linked = Path.join(ctx.dir, "linked")
    File.ln_s!(real, linked)

    assert {:error, _} = SocketPath.prepare(Path.join(linked, "nested/lookup.sock"))
    File.chmod!(real, 0o777)
    assert {:error, _} = SocketPath.prepare(Path.join(real, "nested/lookup.sock"))
  end

  test "helper rejects an attacker precreated socket below sticky tmp", _ctx do
    dir =
      Path.join(
        System.tmp_dir!(),
        "shp-" <> Base.url_encode64(:crypto.strong_rand_bytes(9), padding: false)
      )

    File.mkdir!(dir)
    on_exit(fn -> File.rm_rf(dir) end)
    path = Path.join(dir, "lookup.sock")
    task = reply_server(path, fn _ -> :ok end)
    assert {:error, :lookup_unavailable} = Helper.lookup(path, %{})
    Task.shutdown(task, :brutal_kill)
  end

  test "helper authenticates secure home delegation and rejects an inode replaced during reply",
       ctx do
    path = Path.join(ctx.dir, "lookup.sock")
    task = reply_server(path, fn _ -> :ok end)
    assert {:ok, []} = Helper.lookup(path, %{})
    Task.await(task)
    File.rm!(path)

    task =
      reply_server(path, fn socket_path ->
        File.rename!(socket_path, socket_path <> ".old")

        {:ok, replacement} =
          :gen_tcp.listen(0, [:binary, active: false, ifaddr: {:local, socket_path}])

        :gen_tcp.close(replacement)
      end)

    assert {:error, :lookup_unavailable} = Helper.lookup(path, %{})
    Task.await(task)
  end

  test "helper refuses symlink or writable ancestors", ctx do
    real = Path.join(ctx.dir, "real")
    File.mkdir_p!(Path.join(real, "nested"))
    linked = Path.join(ctx.dir, "linked")
    File.ln_s!(real, linked)
    path = Path.join(real, "nested/lookup.sock")
    task = reply_server(path, fn _ -> :ok end)

    assert {:error, :lookup_unavailable} =
             Helper.lookup(Path.join(linked, "nested/lookup.sock"), %{})

    File.chmod!(real, 0o777)
    assert {:error, :lookup_unavailable} = Helper.lookup(path, %{})
    Task.shutdown(task, :brutal_kill)
  end

  test "malformed socket paths give sanitized failure and empty stdout", ctx do
    for path <- [
          "relative.sock",
          "/tmp/../tmp/socket",
          ctx.dir <> "/bad\0socket",
          "/" <> String.duplicate("x", 108)
        ] do
      assert capture_io(fn ->
               assert capture_io(:stderr, fn ->
                        assert Helper.run([
                                 "fetch-ssh-host-keys",
                                 "--socket",
                                 path,
                                 "ORDER",
                                 "example.com",
                                 "22"
                               ]) == 1
                      end) == "SSH lookup unavailable\n"
             end) == ""
    end
  end

  defp reply_server(path, before_reply) do
    parent = self()

    task =
      Task.async(fn ->
        {:ok, listener} =
          :gen_tcp.listen(0, [:binary, active: false, packet: 4, ifaddr: {:local, path}])

        send(parent, {:listening, self()})
        {:ok, socket} = :gen_tcp.accept(listener)
        {:ok, _request} = :gen_tcp.recv(socket, 0, 2000)
        before_reply.(path)
        :ok = :gen_tcp.send(socket, Jason.encode!(%{"ok" => true, "lines" => []}))
        :gen_tcp.close(socket)
        :gen_tcp.close(listener)
      end)

    assert_receive {:listening, pid}
    assert pid == task.pid
    task
  end
end
