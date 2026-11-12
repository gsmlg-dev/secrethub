# Explicit local qualification only. Requires disposable PG, passwordless sudo,
# OpenSSH tools and SECRETHUB_SSH_RELEASE pointing at a built Agent release
# (MIX_ENV=prod mix release secrethub_agent --overwrite -> _build/prod/rel/secrethub_agent).
# Uses the device-held identity model: Agents enroll and sign with local keys;
# Core approves identities and authorizes signatures without key material.
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
  import Ecto.Query, only: [from: 2]
  alias SecretHub.Core.{Repo, RuntimeDatabaseFixture, SSH}
  alias SecretHub.Core.Agents.ConnectionManager
  alias SecretHub.Core.PKI.{CA, Issuer}
  alias SecretHub.Core.Vault.SealState
  alias SecretHub.Shared.Schemas.{Agent, AuditLog}
  alias SecretHub.Shared.SSH.{Key, Profiles}
  alias SecretHub.Agent.{Connection, IdentityStore}
  alias SecretHub.Agent.SSH.{KeyStore, Server}

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

    # Device-held keys live under <state_dir>/ssh-identities. The listeners get
    # an explicit key root; each Connection's inventory reconcile resolves the
    # same root through :state_dir, so rotation and pruning act on these files.
    source_keys = fixture <> "/ssh-source/ssh-identities"
    destination_keys = fixture <> "/ssh-target/ssh-identities"

    settings = %{
      ssh_lookup_enabled: true,
      ssh_signing_enabled: true,
      state_dir: fixture <> "/ssh-source"
    }

    previous =
      for key <- Map.keys(settings),
          into: %{},
          do: {key, Application.get_env(:secrethub_agent, key)}

    Enum.each(settings, fn {key, value} -> Application.put_env(:secrethub_agent, key, value) end)
    previous_state_env = System.get_env("SECRET_HUB_AGENT_STATE_DIR")
    System.delete_env("SECRET_HUB_AGENT_STATE_DIR")

    on_exit(fn ->
      Enum.each(previous, fn {key, value} ->
        if is_nil(value),
          do: Application.delete_env(:secrethub_agent, key),
          else: Application.put_env(:secrethub_agent, key, value)
      end)

      if previous_state_env, do: System.put_env("SECRET_HUB_AGENT_STATE_DIR", previous_state_env)
    end)

    start_supervised!({Task.Supervisor, name: SecretHub.Agent.SSH.Tasks, max_children: 40})
    source = connect!("ssh-source", endpoint, server_tls.ca_certificate_pem, fixture)
    peer = agent_peer!(fixture <> "/ssh-target")
    destination = connect!("ssh-target", endpoint, server_tls.ca_certificate_pem, fixture, peer)
    await(fn -> Enum.all?(SSH.snapshot().agents, &is_binary(&1.ssh_inventory_seen_at)) end)
    tasks = SecretHub.Agent.SSH.Tasks

    servers =
      for {kind, path, connection, key_root} <- [
            {:lookup, source_lookup, source, source_keys},
            {:signing, signing, source, source_keys},
            {:lookup, destination_lookup, destination, destination_keys},
            {:signing, destination_signing, destination, destination_keys}
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
                   key_root: key_root,
                   request: fn operation, payload ->
                     ssh_request(connection, operation, payload)
                   end
                 ]
               ]}
          })

        assert Process.alive?(pid)
        sudo!("chgrp", [group, path])
        pid
      end

    source_uid = command!("id", ["-u"]) |> String.trim() |> String.to_integer()

    # Enrollment: a local user's first identity list on a signing socket makes
    # the Agent generate generation 1 locally and report only its public key.
    # Core records a pending identity that is not served until approved.
    for {user, socket, agent} <- [
          {"gao", signing, "ssh-source"},
          {"nobody", signing, "ssh-source"},
          {"gao", destination_signing, "ssh-target"}
        ] do
      {pending_list, _} = list_identities(user, socket, group)
      await(fn -> identity(SSH.snapshot(), agent, user) end)
      pending = identity(SSH.snapshot(), agent, user)

      assert %{status: "pending", origin: "agent", requested_generation: 1} = pending
      assert pending.name == user <> "@" <> agent
      assert Enum.map(pending.keys, & &1.generation) == [1]
      refute pending_list =~ current_key(pending)
    end

    snapshot = SSH.snapshot()
    gao = identity(snapshot, "ssh-source", "gao")
    nobody = identity(snapshot, "ssh-source", "nobody")
    reverse = identity(snapshot, "ssh-target", "gao")
    assert gao.local_uid == source_uid

    # Private keys stay owner-only in the Agent key store; a local user cannot
    # read even their own key and can use it only through the signing socket.
    for {uid, root} <- [{source_uid, source_keys}, {nobody.local_uid, source_keys}] do
      assert KeyStore.generations(uid, root) == [1]
      {:ok, %{mode: mode}} = File.stat(Path.join([root, to_string(uid), "1.key"]))
      assert Bitwise.band(mode, 0o777) == 0o600
    end

    {_, unreadable} =
      sudo_as("nobody", group, [
        "cat",
        Path.join([source_keys, to_string(nobody.local_uid), "1.key"])
      ])

    assert unreadable != 0

    changes =
      Enum.map([gao, nobody, reverse], &%{"op" => "identity_approve", "id" => &1.id}) ++
        [
          %{"op" => "group_upsert", "id" => "sources", "kind" => "identity", "name" => "Sources"},
          %{"op" => "group_members", "group_id" => "sources", "member_ids" => [nobody.id]},
          endpoint("ssh-target", ["127.0.0.1", "localhost"], port, host.public_line),
          endpoint("ssh-source", ["127.0.0.2"], port, host.public_line),
          rule("gao-allow", "allow", {"identity", gao.id}, Enum.at(users, 0)),
          rule("nobody-allow", "allow", {"identity_group", "sources"}, Enum.at(users, 1))
        ]

    {:ok, snapshot} = SSH.apply_changes(changes, SSH.snapshot().revision)

    assert Enum.all?(
             [gao, nobody, reverse],
             &(identity_by_id(snapshot, &1.id).status == "active")
           )

    Enum.each(snapshot.identities, &write_public!(fixture, &1))

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

    assert listed =~ current_key(identity(snapshot, "ssh-source", "gao"))
    refute listed =~ current_key(identity(snapshot, "ssh-source", "nobody"))

    {fingerprints, 0} =
      System.cmd("ssh-add", ["-l"], env: [{"SSH_AUTH_SOCK", signing}], stderr_to_stdout: true)

    assert fingerprints =~ "ED25519"

    {other_list, 0} =
      sudo_as("nobody", group, ["env", "SSH_AUTH_SOCK=" <> signing, "ssh-add", "-L"])

    assert other_list =~ current_key(identity(snapshot, "ssh-source", "nobody"))
    refute other_list =~ current_key(identity(snapshot, "ssh-source", "gao"))

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

    # The Agent signed locally above. Core's runtime replies authorize only and
    # never carry key material.
    account = %{"uid" => source_uid, "username" => "gao"}

    {:ok, authorized} =
      ssh_request(
        source,
        "authorize_sign",
        Map.put(account, "public_key", current_key(identity(snapshot, "ssh-source", "gao")))
      )

    assert field(authorized, "allowed") == true
    assert field(authorized, "public_key") == current_key(identity(snapshot, "ssh-source", "gao"))
    assert field(authorized, "generation") == 1

    assert Enum.map(Map.keys(authorized), &to_string/1) --
             ~w(allowed public_key generation revision) == []

    {:ok, listed_reply} = ssh_request(source, "identities", account)

    for reply <- [authorized, listed_reply] do
      refute Enum.any?(Map.keys(reply), &(to_string(&1) =~ "private"))
      refute inspect(reply, limit: :infinity, printable_limit: :infinity) =~ "PRIVATE KEY"
    end

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
      identity(snapshot, "ssh-source", "gao") |> current_key() |> Key.decode_public() |> elem(1)

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

    # The approved target identity has no outgoing rule, so the reverse edge
    # is denied by default.
    reverse_key =
      identity(snapshot, "ssh-target", "gao") |> current_key() |> Key.decode_public() |> elem(1)

    {"", 0} =
      sudo_as("nobody", group, [
        root <> "/release/bin/secrethub_agent",
        "fetch-ssh-keys",
        "--socket",
        source_lookup,
        Enum.at(users, 0),
        reverse_key.encoded
      ])

    denied = rule("gao-deny", "deny", {"identity", gao.id}, Enum.at(users, 0))

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

    # Removing an identity from its identity group revokes only the access
    # granted through that group.
    {:ok, _} =
      SSH.apply_changes(
        [%{"op" => "group_members", "group_id" => "sources", "member_ids" => []}],
        SSH.snapshot().revision
      )

    assert_login!(base_args, fixture, "nobody", Enum.at(users, 1), 255, group)
    assert_login!(base_args, fixture, "gao", Enum.at(users, 0), 0, group)

    {:ok, _} =
      SSH.apply_changes(
        [%{"op" => "group_members", "group_id" => "sources", "member_ids" => [nobody.id]}],
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

    # Rotation: Core requests generation 2; the Agent generates it on its next
    # inventory heartbeat and reports only the public key. The superseded key
    # stays valid for the grace period.
    {:ok, _} =
      SSH.apply_changes([%{"op" => "identity_rotate", "id" => gao.id}], SSH.snapshot().revision)

    send(source, :ssh_inventory)
    await(fn -> generations(identity(SSH.snapshot(), "ssh-source", "gao")) == [1, 2] end, 600)
    rotated = identity(SSH.snapshot(), "ssh-source", "gao")
    assert rotated.status == "active" and rotated.requested_generation == 2
    [previous_key, rotated_key] = Enum.sort_by(rotated.keys, & &1.generation)
    refute is_nil(previous_key.not_after)
    assert is_nil(rotated_key.not_after)
    assert KeyStore.generations(source_uid, source_keys) == [1, 2]

    {rotated_list, 0} =
      System.cmd("ssh-add", ["-L"], env: [{"SSH_AUTH_SOCK", signing}], stderr_to_stdout: true)

    assert rotated_list =~ previous_key.public_key
    assert rotated_list =~ rotated_key.public_key
    # The generation 1 public file still names the superseded key.
    assert_login!(base_args, fixture, "gao", Enum.at(users, 0), 0, group)
    write_public!(fixture, rotated)
    assert_login!(base_args, fixture, "gao", Enum.at(users, 0), 0, group)

    # No Agent private key reached Core state, the audit chain, or the
    # Connection and listener process state.
    private_pems =
      for {uid, root} <- [
            {source_uid, source_keys},
            {nobody.local_uid, source_keys},
            {source_uid, destination_keys}
          ],
          generation <- KeyStore.generations(uid, root),
          {:ok, key} <- [KeyStore.load(uid, generation, root)],
          do: key.private_pem

    assert length(private_pems) == 4

    audit =
      Repo.all(
        from(log in AuditLog, where: like(log.event_type, "ssh.%"), select: log.event_data)
      )

    for {label, term} <- [{"Core snapshot", SSH.snapshot()}, {"SSH audit", audit}] do
      refute inspect(term, limit: :infinity, printable_limit: :infinity) =~ "PRIVATE KEY"
      refute_private_material!(label, term, private_pems)
    end

    refute_private_material!("source Connection", :sys.get_state(source), private_pems)

    refute_private_material!(
      "target Connection",
      :peer.call(peer, :sys, :get_state, [Connection]),
      private_pems
    )

    Enum.each(
      servers,
      &refute_private_material!("SSH listener", :sys.get_state(&1), private_pems)
    )

    {:ok, wrong_host} = Key.generate("ed25519")

    {:ok, _} =
      SSH.apply_changes(
        [endpoint("ssh-target", ["127.0.0.1", "localhost"], port, wrong_host.public.public_line)],
        SSH.snapshot().revision
      )

    wrong_host = assert_login!(base_args, fixture, "gao", Enum.at(users, 0), 255, group)
    assert wrong_host =~ "Host key verification failed"

    {:ok, _} =
      SSH.apply_changes(
        [endpoint("ssh-target", ["127.0.0.1", "localhost"], port, host.public_line)],
        SSH.snapshot().revision
      )

    assert_login!(base_args, fixture, "gao", Enum.at(users, 0), 0, group)

    # Revocation takes effect immediately; other identities keep their access,
    # and the next reconcile discards the retired identity's local keys.
    {:ok, _} =
      SSH.apply_changes([%{"op" => "identity_revoke", "id" => gao.id}], SSH.snapshot().revision)

    revoked = assert_login!(base_args, fixture, "gao", Enum.at(users, 0), 255, group)
    assert revoked =~ "Permission denied"
    assert_login!(base_args, fixture, "nobody", Enum.at(users, 1), 0, group)
    send(source, :ssh_inventory)
    await(fn -> KeyStore.generations(source_uid, source_keys) == [] end, 600)

    IO.puts(
      "SSH qualification: real mTLS, device-held identity enrollment/approval, two source UIDs/two target accounts, local SSH-agent sign, no private key in Core/audit/process state, helper nobody, directed/wrong-user/reverse/identity-group-removal/deny/rotation/host-key/revocation/local-file/CA checks passed; fixture #{suffix}"
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
  # The peer reconciles its own key store, so it gets its own state_dir.
  defp agent_peer!(state_dir) do
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

    :ok = :peer.call(peer, Application, :put_env, [:secrethub_agent, :state_dir, state_dir])

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

  defp rule(id, effect, {source_kind, source_id}, destination_user),
    do: %{
      "op" => "rule_upsert",
      "id" => id,
      "effect" => effect,
      "enabled" => true,
      "source_kind" => source_kind,
      "source_id" => source_id,
      "destination_kind" => "endpoint",
      "destination_id" => "ssh-target",
      "destination_user" => destination_user
    }

  defp endpoint(agent_id, aliases, port, host_key),
    do: %{
      "op" => "endpoint_upsert",
      "agent_id" => agent_id,
      "aliases" => aliases,
      "port" => port,
      "host_keys" => [host_key],
      "approved" => true
    }

  defp list_identities("gao", socket, _group),
    do: System.cmd("ssh-add", ["-L"], env: [{"SSH_AUTH_SOCK", socket}], stderr_to_stdout: true)

  defp list_identities(user, socket, group),
    do: sudo_as(user, group, ["env", "SSH_AUTH_SOCK=" <> socket, "ssh-add", "-L"])

  defp identity(snapshot, agent, user),
    do:
      Enum.find(
        snapshot.identities,
        &(&1.origin == "agent" and &1.agent_id == agent and &1.local_username == user)
      )

  defp identity_by_id(snapshot, id), do: Enum.find(snapshot.identities, &(&1.id == id))

  defp generations(nil), do: []
  defp generations(identity), do: identity.keys |> Enum.map(& &1.generation) |> Enum.sort()

  defp current_key(identity),
    do: identity.keys |> Enum.max_by(& &1.generation) |> Map.fetch!(:public_key)

  defp write_public!(fixture, %{origin: "agent"} = identity),
    do:
      File.write!(
        fixture <> "/" <> identity.agent_id <> "-" <> identity.local_username <> ".pub",
        current_key(identity) <> "\n"
      )

  defp field(reply, key), do: Map.get(reply, key, Map.get(reply, String.to_atom(key)))

  defp refute_private_material!(label, term, private_pems) do
    encoded = :erlang.term_to_binary(term)

    for pem <- private_pems,
        {_, der, _} <- :public_key.pem_decode(pem),
        needle <- [pem, der] do
      assert :binary.match(encoded, needle) == :nomatch,
             "#{label} holds SSH identity private key material"
    end
  end

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
