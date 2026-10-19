# Explicit local qualification only. Requires disposable PG, passwordless sudo,
# OpenSSH tools and SECRETHUB_SSH_RELEASE pointing at a built Agent release.
# MIX_ENV=test mix run --no-start -r scripts/ssh/test_boot.exs scripts/ssh/qualify_openssh.exs
ExUnit.start(assert_receive_timeout: 15_000)
{:ok, _} = Application.ensure_all_started(:secrethub_web)
{:ok, _} = Application.ensure_all_started(:phoenix_socket_client)

case SecretHub.Core.Repo.start_link() do
  {:ok, repo} -> Process.unlink(repo)
  {:error, {:already_started, _}} -> :ok
end

Ecto.Adapters.SQL.Sandbox.mode(SecretHub.Core.Repo, :manual)

defmodule SecretHub.SSH.OpenSSHQualification do
  use ExUnit.Case, async: false
  alias SecretHub.Core.{Repo, RuntimeDatabaseFixture, SSH}
  alias SecretHub.Core.Agents.ConnectionManager
  alias SecretHub.Core.PKI.{CA, Issuer}
  alias SecretHub.Core.Vault.SealState
  alias SecretHub.Shared.Schemas.Agent
  alias SecretHub.Shared.SSH.{Key, Profiles}
  alias SecretHub.Agent.{Connection, IdentityStore}
  alias SecretHub.Agent.SSH.Server

  @moduletag timeout: 240_000
  setup_all do
    RuntimeDatabaseFixture.prepare_template()
  end

  setup tags do
    RuntimeDatabaseFixture.setup(tags, default_repo: true)
  end

  test "real mTLS runtime, peer UIDs, packaged helpers and isolated OpenSSH enforce directed access" do
    release = System.fetch_env!("SECRETHUB_SSH_RELEASE")
    assert File.regular?(Path.join(release, "bin/secrethub_agent"))
    suffix = Base.encode16(:crypto.strong_rand_bytes(4), case: :lower)
    root = "/run/secrethub-ssh-qualification-" <> suffix
    group = "shq" <> suffix
    users = ["shq" <> suffix <> "a", "shq" <> suffix <> "b"]
    sudo!("install", ["-d", "-m", "755", root])
    on_exit(fn -> sudo!("rm", ["-rf", "--", root]) end)
    sudo!("groupadd", ["-U", "gao,nobody", group])
    on_exit(fn -> sudo!("groupdel", [group]) end)

    for user <- users do
      password = Base.url_encode64(:crypto.strong_rand_bytes(32))
      {hash, 0} = System.cmd("openssl", ["passwd", "-6", password])

      sudo!("useradd", [
        "-M",
        "-g",
        "users",
        "-d",
        root <> "/" <> user,
        "-s",
        System.find_executable("bash"),
        "-p",
        String.trim(hash),
        user
      ])

      on_exit(fn -> sudo!("userdel", [user]) end)
      sudo!("install", ["-d", "-m", "755", "-o", user, root <> "/" <> user])
    end

    sudo!("cp", ["-a", release, root <> "/release"])
    sudo!("chown", ["-R", "root:root", root <> "/release"])
    sudo!("install", ["-d", "-m", "755", "-o", "gao", root <> "/fixture"])
    fixture = root <> "/fixture"
    source_lookup = fixture <> "/source.sock"
    signing = fixture <> "/sign.sock"
    destination_lookup = fixture <> "/target.sock"
    destination_signing = fixture <> "/target-sign.sock"
    port = free_port()
    host_path = fixture <> "/host"
    command!("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", host_path])
    {:ok, host} = Key.decode_public(File.read!(host_path <> ".pub"))

    start_supervised!(SealState)
    await(fn -> SealState.status().state == :not_initialized end)
    {:ok, shares} = SealState.initialize(3, 2)
    Enum.each(Enum.take(shares, 2), &SealState.unseal/1)
    {:ok, _} = CA.generate_root_ca("SSH qualification", "SecretHub Test", key_size: 2048)
    start_supervised!({ConnectionManager, name: ConnectionManager})
    {:ok, server_tls} = Issuer.issue_server_certificate("localhost", ["localhost", "127.0.0.1"])

    for {name, data} <- [
          {"server.pem", server_tls.certificate_pem},
          {"server.key", server_tls.private_key_pem},
          {"ca.pem", server_tls.ca_certificate_pem}
        ] do
      File.write!(fixture <> "/" <> name, data)
      File.chmod!(fixture <> "/" <> name, 0o600)
    end

    old_endpoint = Application.get_env(:secrethub_web, SecretHub.Web.AgentEndpoint)

    Application.put_env(:secrethub_web, SecretHub.Web.AgentEndpoint,
      adapter: Bandit.PhoenixAdapter,
      server: true,
      pubsub_server: SecretHub.Web.PubSub,
      url: [host: "localhost", port: 0],
      https: [
        ip: {127, 0, 0, 1},
        port: 0,
        certfile: fixture <> "/server.pem",
        keyfile: fixture <> "/server.key",
        thousand_island_options: [
          transport_options: [
            cacertfile: to_charlist(fixture <> "/ca.pem"),
            verify: :verify_peer,
            fail_if_no_peer_cert: true,
            versions: [:"tlsv1.2", :"tlsv1.3"]
          ]
        ]
      ]
    )

    on_exit(fn ->
      Supervisor.terminate_child(SecretHub.Web.Supervisor, SecretHub.Web.AgentEndpoint)
      Supervisor.delete_child(SecretHub.Web.Supervisor, SecretHub.Web.AgentEndpoint)
      Application.put_env(:secrethub_web, SecretHub.Web.AgentEndpoint, old_endpoint || [])
    end)

    {:ok, _} = Supervisor.start_child(SecretHub.Web.Supervisor, SecretHub.Web.AgentEndpoint)
    {:ok, {_, tls_port}} = SecretHub.Web.AgentEndpoint.server_info(:https)
    endpoint = "wss://localhost:#{tls_port}/agent/socket/websocket"

    previous =
      for key <- [:ssh_lookup_enabled, :ssh_signing_enabled],
          into: %{},
          do: {key, Application.get_env(:secrethub_agent, key)}

    for key <- Map.keys(previous), do: Application.put_env(:secrethub_agent, key, true)

    on_exit(fn ->
      Enum.each(previous, fn {key, value} ->
        if is_nil(value),
          do: Application.delete_env(:secrethub_agent, key),
          else: Application.put_env(:secrethub_agent, key, value)
      end)
    end)

    start_supervised!({Task.Supervisor, name: SecretHub.Agent.SSH.Tasks, max_children: 40})
    source = connect!("ssh-source", endpoint, server_tls.ca_certificate_pem, fixture)
    peer = agent_peer!()
    destination = connect!("ssh-target", endpoint, server_tls.ca_certificate_pem, fixture, peer)
    await(fn -> Enum.all?(SSH.snapshot().agents, &is_binary(&1.ssh_inventory_seen_at)) end)
    tasks = SecretHub.Agent.SSH.Tasks

    for {kind, path, connection} <- [
          {:lookup, source_lookup, source},
          {:signing, signing, source},
          {:lookup, destination_lookup, destination},
          {:signing, destination_signing, destination}
        ] do
      pid =
        start_supervised!(%{
          id: path,
          start:
            {Server, :start_link,
             [
               [
                 kind: kind,
                 path: path,
                 task_supervisor: tasks,
                 request: fn operation, payload ->
                   ssh_request(connection, operation, payload)
                 end
               ]
             ]}
        })

      assert Process.alive?(pid)
      sudo!("chgrp", [group, path])
    end

    source_uid = command!("id", ["-u"]) |> String.trim() |> String.to_integer()

    changes = [
      %{"op" => "group_upsert", "id" => "sources", "name" => "Sources"},
      %{"op" => "group_members", "group_id" => "sources", "agent_ids" => ["ssh-source"]},
      %{
        "op" => "endpoint_upsert",
        "agent_id" => "ssh-target",
        "aliases" => ["127.0.0.1", "localhost"],
        "port" => port,
        "host_keys" => [host.public_line],
        "approved" => true
      },
      %{
        "op" => "endpoint_upsert",
        "agent_id" => "ssh-source",
        "aliases" => ["127.0.0.2"],
        "port" => port,
        "host_keys" => [host.public_line],
        "approved" => true
      },
      %{
        "op" => "identity_upsert",
        "agent_id" => "ssh-source",
        "username" => "gao",
        "uid" => source_uid,
        "algorithm" => "ed25519"
      },
      %{
        "op" => "identity_upsert",
        "agent_id" => "ssh-source",
        "username" => "nobody",
        "uid" => 65534,
        "algorithm" => "ed25519"
      },
      %{
        "op" => "identity_upsert",
        "agent_id" => "ssh-target",
        "username" => "gao",
        "uid" => source_uid,
        "algorithm" => "ed25519"
      },
      rule("gao", Enum.at(users, 0), "allow", "gao-allow"),
      rule("nobody", Enum.at(users, 1), "allow", "nobody-allow")
    ]

    {:ok, snapshot} = SSH.apply_changes(changes, SSH.snapshot().revision)

    for identity <- snapshot.identities do
      File.write!(
        fixture <> "/" <> identity.agent_id <> "-" <> identity.username <> ".pub",
        identity.public_key <> "\n"
      )
    end

    {:ok, client} =
      Profiles.client(
        base: root <> "/release",
        hosts: ["127.0.0.1", "localhost"],
        lookup_socket: source_lookup,
        signing_socket: signing
      )

    File.write!(fixture <> "/client", client)

    File.write!(
      fixture <> "/pinned_hosts",
      "[127.0.0.1]:#{port} #{host.public_line}\n[127.0.0.2]:#{port} #{host.public_line}\n"
    )

    {:ok, managed_server} =
      Profiles.server(base: root <> "/release", lookup_socket: destination_lookup, users: users)

    fallback = fixture <> "/fallback"
    ca = fixture <> "/user-ca"

    for path <- [fallback, ca],
        do: command!("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", path])

    command!("ssh-keygen", [
      "-q",
      "-s",
      ca,
      "-I",
      "ssh-qualification",
      "-n",
      Enum.join(users, ","),
      "-V",
      "+1h",
      fallback <> ".pub"
    ])

    for user <- users do
      sudo!("install", ["-d", "-m", "700", "-o", user, root <> "/" <> user <> "/.ssh"])
      sudo!("cp", [fallback <> ".pub", root <> "/" <> user <> "/.ssh/authorized_keys"])
      sudo!("chown", [user, root <> "/" <> user <> "/.ssh/authorized_keys"])
    end

    config = """
    Port #{port}
    ListenAddress 127.0.0.1
    HostKey #{host_path}
    PidFile #{fixture}/sshd.pid
    UsePAM no
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    PermitRootLogin no
    AllowUsers #{Enum.join(users, " ")}
    AuthorizedKeysFile .ssh/authorized_keys
    TrustedUserCAKeys #{ca}.pub
    LogLevel VERBOSE
    #{managed_server}
    """

    File.write!(fixture <> "/sshd_config", config)
    sudo!("sshd", ["-t", "-f", fixture <> "/sshd_config"])
    sudo!("sshd", ["-f", fixture <> "/sshd_config", "-E", fixture <> "/sshd.log"])

    on_exit(fn ->
      File.write!(
        "/tmp/secrethub-ssh-qualification-#{suffix}-sshd.log",
        sudo!("cat", [fixture <> "/sshd.log"])
      )

      if File.exists?(fixture <> "/sshd.pid") do
        pid = File.read!(fixture <> "/sshd.pid") |> String.trim()
        sudo!("kill", ["-TERM", pid])
      end
    end)

    await(fn -> File.exists?(fixture <> "/sshd.pid") end)

    {:ok, reverse_server} =
      Profiles.server(base: root <> "/release", lookup_socket: source_lookup, users: users)

    reverse_config =
      config
      |> String.replace("ListenAddress 127.0.0.1", "ListenAddress 127.0.0.2")
      |> String.replace("sshd.pid", "reverse-sshd.pid")
      |> String.replace(managed_server, reverse_server)

    File.write!(fixture <> "/reverse_config", reverse_config)
    sudo!("sshd", ["-t", "-f", fixture <> "/reverse_config"])
    sudo!("sshd", ["-f", fixture <> "/reverse_config", "-E", fixture <> "/reverse-sshd.log"])

    on_exit(fn ->
      File.write!(
        "/tmp/secrethub-ssh-qualification-#{suffix}-reverse-sshd.log",
        sudo!("cat", [fixture <> "/reverse-sshd.log"])
      )

      if File.exists?(fixture <> "/reverse-sshd.pid") do
        sudo!("kill", ["-TERM", File.read!(fixture <> "/reverse-sshd.pid") |> String.trim()])
      end
    end)

    await(fn -> File.exists?(fixture <> "/reverse-sshd.pid") end)

    for user <- users do
      effective =
        sudo!("sshd", [
          "-T",
          "-f",
          fixture <> "/sshd_config",
          "-C",
          "user=#{user},host=localhost,addr=127.0.0.1"
        ])
        |> String.downcase()

      assert effective =~ "authorizedkeysfile none"
      assert effective =~ "trustedusercakeys none"
    end

    {listed, 0} =
      System.cmd("ssh-add", ["-L"], env: [{"SSH_AUTH_SOCK", signing}], stderr_to_stdout: true)

    assert listed =~ identity(snapshot, "ssh-source", "gao").public_key
    refute listed =~ identity(snapshot, "ssh-source", "nobody").public_key

    {fingerprints, 0} =
      System.cmd("ssh-add", ["-l"], env: [{"SSH_AUTH_SOCK", signing}], stderr_to_stdout: true)

    assert fingerprints =~ "ED25519"

    {other_list, 0} =
      sudo_as("nobody", group, ["env", "SSH_AUTH_SOCK=" <> signing, "ssh-add", "-L"])

    assert other_list =~ identity(snapshot, "ssh-source", "nobody").public_key
    refute other_list =~ identity(snapshot, "ssh-source", "gao").public_key

    {_, other_sign_exit} =
      sudo_as("nobody", group, [
        "env",
        "SSH_AUTH_SOCK=" <> signing,
        "ssh-add",
        "-T",
        fixture <> "/ssh-source-gao.pub"
      ])

    assert other_sign_exit != 0

    File.chmod!(signing, 0o600)

    try do
      {_, inaccessible_exit} =
        sudo_as("nobody", group, ["env", "SSH_AUTH_SOCK=" <> signing, "ssh-add", "-l"])

      assert inaccessible_exit != 0
    after
      File.chmod!(signing, 0o660)
    end

    {_, 0} =
      System.cmd("ssh-add", ["-T", fixture <> "/ssh-source-gao.pub"],
        env: [{"SSH_AUTH_SOCK", signing}],
        stderr_to_stdout: true
      )

    base_args = [
      "-F",
      fixture <> "/client",
      "-o",
      "BatchMode=yes",
      "-o",
      "ConnectTimeout=10",
      "-o",
      "IdentitiesOnly=yes",
      "-p",
      to_string(port)
    ]

    {effective_client, 0} =
      System.cmd("ssh", base_args ++ ["-G", "127.0.0.1"], stderr_to_stdout: true)

    for setting <- [
          "stricthostkeychecking true",
          "verifyhostkeydns false",
          "forwardagent no",
          "userknownhostsfile /dev/null",
          "globalknownhostsfile /dev/null"
        ] do
      assert effective_client =~ setting
    end

    assert_login!(base_args, fixture, "gao", Enum.at(users, 0), 0, group)
    assert_login!(base_args, fixture, "nobody", Enum.at(users, 1), 0, group)
    wrong_user = assert_login!(base_args, fixture, "gao", Enum.at(users, 1), 255, group)
    assert wrong_user =~ "Permission denied"

    source_key =
      identity(snapshot, "ssh-source", "gao").public_key |> Key.decode_public() |> elem(1)

    {public_lookup, 0} =
      sudo_as("nobody", group, [
        root <> "/release/bin/secrethub_agent",
        "fetch-ssh-keys",
        "--socket",
        destination_lookup,
        Enum.at(users, 0),
        source_key.encoded
      ])

    assert String.trim(public_lookup) == "no-agent-forwarding " <> source_key.public_line

    reverse_key =
      identity(snapshot, "ssh-target", "gao").public_key |> Key.decode_public() |> elem(1)

    {"", 0} =
      sudo_as("nobody", group, [
        root <> "/release/bin/secrethub_agent",
        "fetch-ssh-keys",
        "--socket",
        source_lookup,
        Enum.at(users, 0),
        reverse_key.encoded
      ])

    denied = rule("gao", Enum.at(users, 0), "deny", "gao-deny")

    pinned = [
      "-o",
      "KnownHostsCommand=none",
      "-o",
      "UserKnownHostsFile=" <> fixture <> "/pinned_hosts"
    ]

    {reverse_output, 255} =
      System.cmd(
        "ssh",
        pinned ++
          ["-o", "IdentityAgent=" <> destination_signing, "-o", "StrictHostKeyChecking=yes"] ++
          base_args ++
          ["-i", fixture <> "/ssh-target-gao.pub", Enum.at(users, 0) <> "@127.0.0.2", "true"],
        stderr_to_stdout: true
      )

    assert reverse_output =~ "Permission denied"

    {:ok, _} =
      SSH.apply_changes(
        [%{"op" => "group_members", "group_id" => "sources", "agent_ids" => []}],
        SSH.snapshot().revision
      )

    assert_login!(base_args, fixture, "gao", Enum.at(users, 0), 255, group)
    assert_login!(base_args, fixture, "nobody", Enum.at(users, 1), 255, group)

    {:ok, _} =
      SSH.apply_changes(
        [%{"op" => "group_members", "group_id" => "sources", "agent_ids" => ["ssh-source"]}],
        SSH.snapshot().revision
      )

    {:ok, _} = SSH.apply_changes([denied], SSH.snapshot().revision)
    assert_login!(base_args, fixture, "gao", Enum.at(users, 0), 255, group)
    assert_login!(base_args, fixture, "nobody", Enum.at(users, 1), 0, group)
    # A local key file and user certificate exist, but the generated managed
    # account profile excludes both alternate authorization sources.
    for certificate <- [false, true] do
      args =
        pinned ++
          base_args ++
          ["-o", "IdentityAgent=none", "-i", fallback] ++
          if(certificate,
            do: ["-o", "CertificateFile=" <> fallback <> "-cert.pub"],
            else: ["-o", "CertificateFile=none"]
          ) ++
          [Enum.at(users, 0) <> "@127.0.0.1", "true"]

      {output, code} = System.cmd("ssh", args, stderr_to_stdout: true)
      assert code == 255
      assert output =~ "Permission denied"
    end

    {:ok, _} =
      SSH.apply_changes([%{"op" => "rule_delete", "id" => "gao-deny"}], SSH.snapshot().revision)

    {:ok, wrong_host} = Key.generate("ed25519")

    {:ok, _} =
      SSH.apply_changes(
        [
          %{
            "op" => "endpoint_upsert",
            "agent_id" => "ssh-target",
            "aliases" => ["127.0.0.1", "localhost"],
            "port" => port,
            "host_keys" => [wrong_host.public.public_line],
            "approved" => true
          }
        ],
        SSH.snapshot().revision
      )

    wrong_host = assert_login!(base_args, fixture, "gao", Enum.at(users, 0), 255, group)
    assert wrong_host =~ "Host key verification failed"

    IO.puts(
      "SSH qualification: real mTLS, two source UIDs/two target accounts, SSH-agent sign, helper nobody, directed/wrong-user/reverse/group-removal/deny/revoke/host-key/local-file/CA checks passed; fixture #{suffix}"
    )
  end

  defp connect!(agent_id, endpoint, ca, fixture, peer \\ nil) do
    key = X509.PrivateKey.new_rsa(2048)
    csr = X509.CSR.new(key, "/CN=#{agent_id}")

    enrollment = %{
      id: nil,
      agent_id: agent_id,
      ssh_host_key_fingerprint: "fixture",
      required_csr_fields: %{
        "san" => %{
          "uri" => ["urn:secrethub:agent:" <> agent_id, "urn:secrethub:hostkey-sha256:fixture"],
          "dns" => []
        }
      }
    }

    {:ok, cert} = Issuer.issue_agent_certificate_from_csr(enrollment, csr)

    Repo.insert!(%Agent{
      agent_id: agent_id,
      name: agent_id,
      status: :trusted_connected,
      ssh_host_key_fingerprint: "fixture",
      certificate_id: cert.id
    })

    [{:Certificate, der, _}] = :public_key.pem_decode(cert.certificate_pem)

    assert {:ok, %{agent_id: ^agent_id}} =
             SecretHub.Core.PKI.Verifier.verify_agent_certificate(der)

    connect_info = %{
      "trusted_websocket_endpoint" => endpoint,
      "expected_core_server_name" => "localhost",
      "core_ca_cert_pem" => ca
    }

    state_dir = fixture <> "/" <> agent_id

    :ok =
      IdentityStore.write(state_dir, %{
        agent_id: agent_id,
        certificate_pem: cert.certificate_pem,
        private_key_pem: X509.PrivateKey.to_pem(key),
        ca_chain_pem: ca,
        connect_info: connect_info,
        identity: %{"agent_id" => agent_id}
      })

    parent = self()

    opts = [
      agent_id: agent_id,
      core_url: endpoint,
      cert_pem: cert.certificate_pem,
      private_key: key,
      ca_pem: ca,
      expected_server_name: "localhost",
      state_dir: state_dir,
      on_runtime_accepted: fn payload -> send(parent, {:accepted, agent_id, payload}) end
    ]

    if peer do
      {:ok, _} =
        :peer.call(peer, GenServer, :start, [
          Connection,
          Keyword.delete(opts, :on_runtime_accepted),
          [name: Connection]
        ])

      await(fn -> :peer.call(peer, Connection, :status, [Connection]) == :connected end, 600)
      {:peer, peer}
    else
      connection =
        start_supervised!(%{id: agent_id, start: {GenServer, :start_link, [Connection, opts]}})

      assert_receive {:accepted, ^agent_id, %{"status" => "accepted"}}, 15_000
      connection
    end
  end

  # A deployed Agent owns one socket-client supervisor per BEAM. Run the second
  # real Connection in its own VM, retaining the production registration names.
  defp agent_peer! do
    {:ok, peer, _} =
      :peer.start_link(%{connection: :standard_io, args: [~c"+S", ~c"2:2"]})

    Process.unlink(peer)
    on_exit(fn -> :peer.stop(peer) end)
    :ok = :peer.call(peer, :code, :add_paths, [:code.get_path()])
    {:ok, _} = :peer.call(peer, Application, :ensure_all_started, [:logger])
    :ok = :peer.call(peer, Logger, :configure, [[level: :warning]])
    {:ok, _} = :peer.call(peer, Application, :ensure_all_started, [:phoenix_socket_client])

    :ok =
      :peer.call(peer, Application, :put_all_env, [
        [{:secrethub_agent, Application.get_all_env(:secrethub_agent)}]
      ])

    {:ok, _} =
      :peer.call(peer, Code, :eval_string, [
        "{:ok, pid} = Task.Supervisor.start_link(name: SecretHub.Agent.SSH.Tasks, max_children: 40); Process.unlink(pid); :ok"
      ])

    peer
  end

  defp ssh_request({:peer, peer}, operation, payload),
    do: :peer.call(peer, Connection, :ssh_request, [Connection, operation, payload, 5000], 6000)

  defp ssh_request(connection, operation, payload),
    do: Connection.ssh_request(connection, operation, payload, 5000)

  defp rule(source_user, destination_user, effect, id),
    do: %{
      "op" => "rule_upsert",
      "id" => id,
      "effect" => effect,
      "enabled" => true,
      "source_kind" => "group",
      "source_id" => "sources",
      "source_user" => source_user,
      "destination_kind" => "agent",
      "destination_id" => "ssh-target",
      "destination_user" => destination_user
    }

  defp identity(snapshot, agent, user),
    do: Enum.find(snapshot.identities, &(&1.agent_id == agent and &1.username == user))

  defp assert_login!(base, fixture, source, target, expected, group) do
    args =
      [System.find_executable("ssh")] ++
        base ++
        [
          "-i",
          fixture <> "/ssh-source-" <> source <> ".pub",
          target <> "@127.0.0.1",
          "printf SSH_QUALIFIED"
        ]

    {output, code} =
      if source == "gao",
        do: System.cmd(hd(args), tl(args), stderr_to_stdout: true),
        else: sudo_as(source, group, args)

    if code != expected do
      IO.puts("failure sshd log: " <> sudo!("cat", [fixture <> "/sshd.log"]))
    end

    assert code == expected,
           "SSH source=#{source} target=#{target}: expected #{expected}, got #{code}: #{output}"

    if expected == 0, do: assert(output =~ "SSH_QUALIFIED")
    output
  end

  # OpenSSH drops subprocess privileges to the account's passwd primary group.
  # The fixture group is supplementary; forcing it as primary prevents that drop.
  defp sudo_as(user, _group, args),
    do:
      System.cmd(
        "sudo",
        [
          "-n",
          "-u",
          user,
          "env",
          "-i",
          "PATH=/run/current-system/sw/bin",
          "HOME=/var/empty"
        ] ++ args,
        stderr_to_stdout: true
      )

  defp sudo!(exe, args), do: command!("sudo", ["-n", System.find_executable(exe) || exe] ++ args)

  defp command!(exe, args) do
    case System.cmd(exe, args, stderr_to_stdout: true) do
      {output, 0} -> output
      {output, code} -> flunk("#{exe} failed (#{code}): #{output}")
    end
  end

  defp free_port do
    {:ok, socket} = :gen_tcp.listen(0, ip: {127, 0, 0, 1})
    {:ok, {_, port}} = :inet.sockname(socket)
    :gen_tcp.close(socket)
    port
  end

  defp await(fun, attempts \\ 200)
  defp await(_, 0), do: flunk("timed out waiting for owned fixture")

  defp await(fun, attempts) do
    unless fun.() do
      Process.sleep(25)
      await(fun, attempts - 1)
    end
  end
end
