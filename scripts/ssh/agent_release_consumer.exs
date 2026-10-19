# Packaged public-helper qualification with an injected public lookup fixture.
# This proves release/Unix-consumer behavior, not real Core authorization.
# Build the Agent release first, then run with the same OTP/Elixir toolchain:
#   elixir -pa '/tmp/secrethub-ssh-agent-final-release/lib/*/ebin' \
#     scripts/ssh/agent_release_consumer.exs /tmp/secrethub-ssh-agent-final-release
# Requires passwordless sudo for an isolated /run fixture and nobody consumers.
# Uses a temporary artifact copy; does not modify the supplied release.

alias SecretHub.Agent.SSH.{Helper, Server}
alias SecretHub.Shared.SSH.Key
[source_release] = System.argv()

root =
  Path.join(
    "/run",
    "secrethub-ssh-consumer-" <> Base.url_encode64(:crypto.strong_rand_bytes(12), padding: false)
  )

{uid, 0} = System.cmd("id", ["-u"])
{gid, 0} = System.cmd("id", ["-g"])
uid = String.trim(uid)
gid = String.trim(gid)
{_, 0} = System.cmd("sudo", ["-n", "mkdir", "--", root])

try do
  {_, 0} = System.cmd("sudo", ["-n", "chown", uid <> ":" <> gid, "--", root])
  File.chmod!(root, 0o755)
  release = Path.join(root, "release")
  {:ok, _} = File.cp_r(Path.expand(source_release), release)
  {primary_group, 0} = System.cmd("id", ["-gn"])
  primary_group = String.trim(primary_group)
  keypath = Path.join(root, "key")
  {_, 0} = System.cmd("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", keypath])
  {:ok, key} = Key.decode_public(File.read!(keypath <> ".pub"))
  {:ok, tasks} = Task.Supervisor.start_link()
  File.rm!(keypath)
  parent = self()

  request = fn
    "authorized_keys", %{"username" => "nobody"} ->
      {:ok, %{"lines" => ["no-agent-forwarding " <> key.public_line]}}

    "authorized_keys", _ ->
      {:ok, %{"lines" => []}}

    "known_hosts", payload ->
      send(parent, {:peer, payload})
      {:ok, %{"lines" => ["example.com " <> key.public_line]}}
  end

  socket = Path.join(root, "lookup.sock")

  {:ok, server} =
    Server.start_link(path: socket, kind: :lookup, task_supervisor: tasks, request: request)

  try do
    File.rm(Path.join(release, "releases/COOKIE"))
    blocked_config = Path.join(root, "private.toml")
    File.write!(blocked_config, "must never be read")
    File.chmod!(blocked_config, 0)

    snapshot = fn ->
      Path.wildcard(release <> "/**", match_dot: true)
      |> Enum.map(fn path -> {path, File.stat!(path).mtime} end)
    end

    before = snapshot.()

    base = [
      "-n",
      "-u",
      "nobody",
      "-g",
      primary_group,
      "env",
      "-i",
      "HOME=/nonexistent",
      "SECRET_HUB_AGENT_CONFIG_FILE=" <> blocked_config,
      "ERL_FLAGS=+S 2:2",
      release <> "/bin/secrethub_agent"
    ]

    run = fn args -> System.cmd("sudo", base ++ args, stderr_to_stdout: true) end
    {out, 0} = run.(["fetch-ssh-keys", "--socket", socket, "nobody", key.encoded])
    true = out == "no-agent-forwarding " <> key.public_line <> "\n"
    {"", 0} = run.(["fetch-ssh-keys", "--socket", socket, "ungranted", key.encoded])

    for reason <- ["ORDER", "HOSTNAME", "ADDRESS"] do
      {out, 0} = run.(["fetch-ssh-host-keys", "--socket", socket, reason, "example.com", "22"])
      true = out == "example.com " <> key.public_line <> "\n"

      receive do
        {:peer, %{"uid" => 65534, "username" => "nobody", "reason" => ^reason}} -> :ok
      after
        2000 -> raise "wrong kernel peer identity"
      end
    end

    {"SSH lookup unavailable\n", 1} =
      run.([
        "fetch-ssh-host-keys",
        "--socket",
        socket <> ".missing",
        "ORDER",
        "example.com",
        "22"
      ])

    # Socket ownership alone is insufficient: this root listener deliberately
    # gives its socket to the delegated service UID, but retains kernel UID 0.
    counterfeit = Path.join(root, "counterfeit.sock")
    ready = Path.join(root, "ready")

    script = ~S"""
    [path, ready, uid, gid] = System.argv()
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, packet: 4, ifaddr: {:local, path}])
    File.chown!(path, String.to_integer(uid))
    File.chgrp!(path, String.to_integer(gid))
    File.chmod!(path, 0o660)
    File.touch!(ready)
    {:ok, socket} = :gen_tcp.accept(listener, 5000)
    case :gen_tcp.recv(socket, 0, 2000) do
      {:ok, _} -> :gen_tcp.send(socket, ~s({"ok":true,"lines":[]}))
      _ -> :ok
    end
    :gen_tcp.close(socket)
    :gen_tcp.close(listener)
    """

    counterfeit_task =
      Task.async(fn ->
        System.cmd(
          "sudo",
          [
            "-n",
            "env",
            "ERL_FLAGS=+S 2:2",
            System.find_executable("elixir"),
            "-e",
            script,
            "--",
            counterfeit,
            ready,
            uid,
            gid
          ],
          stderr_to_stdout: true
        )
      end)

    Enum.reduce_while(1..100, :waiting, fn _, _ ->
      if File.exists?(ready),
        do: {:halt, :ready},
        else:
          (
            Process.sleep(50)
            {:cont, :waiting}
          )
    end) == :ready || raise "counterfeit listener did not start"

    {:error, :lookup_unavailable} = Helper.lookup(counterfeit, %{})
    {"", 0} = Task.await(counterfeit_task, 10_000)

    true = before == snapshot.()
    false = File.exists?(Path.join(release, "tmp"))
    false = File.exists?(Path.join(release, "releases/COOKIE"))
  after
    GenServer.stop(server)
    Supervisor.stop(tasks)
  end
after
  case File.rm_rf(root) do
    {:ok, _} ->
      :ok

    {:error, :eacces, ^root} ->
      {_, 0} = System.cmd("sudo", ["-n", "rmdir", "--", root])

    {:error, reason, path} ->
      raise File.Error, reason: reason, path: path, action: "remove qualification fixture"
  end
end

IO.puts(
  "PASS: nobody packaged helpers, all lookup reasons, UID65534 binding, counterfeit peer rejection, deny/exit errors, unreadable configuration, absent cookie, immutable release"
)
