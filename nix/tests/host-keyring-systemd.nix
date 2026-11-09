# Real systemd qualification of the host keyring service profile.
#
# The Agent module generates provider sockets and service units; a stub Agent
# binary serves those sockets under test control (the real provider's Core
# path is covered by ExUnit). This exercises the pinned systemd's
# LoadCredential= acquisition, per-UID delivery, and the mandatory
# secrethub-exec main-process launcher.
{ pkgs, agentModule, launcher }:
let
  dbEntry = "11111111-2222-4333-8444-555555555555";
  tokenEntry = "22222222-2222-4333-8444-555555555555";

  # Serves each configured provider socket. /run/hk-control/NAME selects:
  #   "ok VALUE"      send VALUE (escaped newlines as \n)
  #   "deny"          close without bytes
  #   "limit N VALUE" send VALUE to the first N connections, then deny
  # Connection counts are written to /run/secrethub-agent/NAME.count.
  stubAgent = pkgs.writeTextFile {
    name = "secrethub-agent-provider-stub";
    destination = "/bin/secrethub_agent";
    executable = true;
    text = ''
      #!${pkgs.python3}/bin/python3
      import json, os, socket, struct, threading

      # User-profile mode: no providers; bind the Agent socket and record the
      # runtime settings the module passed, then wait.
      if "SECRET_HUB_AGENT_CREDENTIAL_PROVIDERS" not in os.environ:
          keys = ["SECRET_HUB_AGENT_STATE_DIR", "SECRET_HUB_AGENT_HOST_KEY_PATH",
                  "SECRET_HUB_AGENT_SOCKET_PATH", "SECRET_HUB_AGENT_CORE_URL"]
          with open(os.path.join(os.environ["SECRET_HUB_AGENT_STATE_DIR"], "stub-env.json"), "w") as out:
              json.dump({k: os.environ.get(k) for k in keys}, out)
          sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
          sock.bind(os.environ["SECRET_HUB_AGENT_SOCKET_PATH"])
          sock.listen(1)
          threading.Event().wait()

      config = json.load(open(os.environ["SECRET_HUB_AGENT_CREDENTIAL_PROVIDERS"]))
      state = {}

      def serve(name, sock):
          while True:
              conn, _ = sock.accept()
              with conn:
                  creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
                  _pid, uid, _gid = struct.unpack("3i", creds)
                  try:
                      control = open("/run/hk-control/" + name).read()
                  except OSError:
                      control = "deny"
                  seen = state.get(name)
                  count = seen[1] + 1 if seen and seen[0] == control else 1
                  state[name] = (control, count)
                  with open("/run/secrethub-agent/" + name + ".count", "w") as out:
                      out.write(str(count))
                  if uid not in config["allowed_uids"]:
                      continue
                  parts = control.split(" ", 2)
                  if parts[0] == "ok":
                      conn.sendall(" ".join(parts[1:]).replace("\\n", "\n").encode())
                  elif parts[0] == "limit" and count <= int(parts[1]):
                      conn.sendall(parts[2].encode())

      for name in config["providers"]:
          path = os.path.join(config["socket_dir"], name + ".sock")
          sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
          sock.bind(path)
          os.chmod(path, 0o600)
          sock.listen(8)
          threading.Thread(target=serve, args=(name, sock), daemon=True).start()

      threading.Event().wait()
    '';
  };

  report = file: [
    "${pkgs.bash}/bin/sh"
    "-c"
    ''printf %s "''${DB_PASSWORD-}" > ${file}.value; id -u > ${file}.uid; ls "$CREDENTIALS_DIRECTORY" > ${file}.creds''
  ];
in
pkgs.testers.runNixOSTest {
  name = "secrethub-host-keyring-systemd";

  nodes.machine = { pkgs, ... }: {
    imports = [ agentModule ];

    environment.etc."hk-dummy-host-key".text = "test-only";
    users.users.alice = { isSystemUser = true; group = "alice"; };
    # Interactive user with a lingering user manager for the per-user Agent.
    users.users.bob = { isNormalUser = true; linger = true; };
    users.groups.alice = { };

    services.secrethub-agent = {
      enable = true;
      coreUrl = "https://core.example.test:4665";
      hostKeyPath = "/etc/hk-dummy-host-key";
      package = stubAgent;
      cliPackage = launcher;
      userAgent.enable = true;
      credentialProviders = {
        db.entryId = dbEntry;
        token.entryId = tokenEntry;
      };
      serviceCredentials = {
        svc-alice = {
          credentials.db = "db";
          environment.DB_PASSWORD = "db";
          command = report "/tmp/alice";
        };
        svc-dynamic = {
          credentials.token = "token";
          # DynamicUser implies PrivateTmp; report through a preserved runtime directory.
          command = report "/run/hk-dynamic/dynamic";
        };
        # A successful ExecStartPre= acquisition must not validate the main
        # process: systemd acquires the credential again for it.
        svc-prestart = {
          credentials.db = "db";
          environment.DB_PASSWORD = "db";
          command = [ "${pkgs.coreutils}/bin/touch" "/tmp/prestart-main-started" ];
        };
      };
    };

    systemd.services.svc-alice.serviceConfig = { Type = "oneshot"; User = "alice"; };
    systemd.services.svc-dynamic.serviceConfig = {
      Type = "oneshot";
      DynamicUser = true;
      RuntimeDirectory = "hk-dynamic";
      RuntimeDirectoryPreserve = true;
    };
    systemd.services.svc-prestart.serviceConfig = {
      Type = "oneshot";
      ExecStartPre = "${launcher}/bin/secrethub-exec --credential db -- ${pkgs.coreutils}/bin/true";
    };
  };

  testScript = ''
    canary = "canary-7f3a-value"

    machine.wait_for_unit("secrethub-agent.service")
    machine.wait_for_file("/run/secrethub-credentials/db.sock")
    machine.succeed("test \"$(stat -c %a /run/secrethub-credentials)\" = 700")
    machine.succeed("install -d -m 0755 /run/hk-control")

    with subtest("each service UID receives only its configured credential"):
        machine.succeed(f"printf '%s' 'ok {canary}\\nline-2' > /run/hk-control/db")
        machine.succeed("printf '%s' 'ok token-1' > /run/hk-control/token")
        machine.succeed("systemctl start svc-alice.service svc-dynamic.service")
        assert machine.succeed("cat /tmp/alice.value") == canary + "\nline-2"
        assert machine.succeed("cat /tmp/alice.creds").split() == ["db"]
        assert machine.succeed("cat /run/hk-dynamic/dynamic.creds").split() == ["token"]
        alice = machine.succeed("id -u alice").strip()
        assert machine.succeed("cat /tmp/alice.uid").strip() == alice
        dynamic = machine.succeed("cat /run/hk-dynamic/dynamic.uid").strip()
        assert dynamic not in ("0", alice)
        machine.fail("sudo -u alice cat /run/secrethub-credentials/db.sock")

    with subtest("credential values never appear in unit text or the store"):
        machine.fail(f"systemctl cat svc-alice.service svc-dynamic.service secrethub-agent.service | grep -F {canary}")
        machine.fail(f"grep -rlF {canary} /etc/systemd")

    with subtest("denial or outage prevents the next activation"):
        machine.succeed("rm -f /tmp/alice.*; printf deny > /run/hk-control/db")
        machine.fail("systemctl start svc-alice.service")
        machine.fail("test -e /tmp/alice.value")
        machine.succeed("systemctl stop secrethub-agent.service")
        machine.succeed(f"printf '%s' 'ok {canary}' > /run/hk-control/db")
        machine.fail("systemctl start svc-alice.service")
        machine.fail("test -e /tmp/alice.value")
        machine.succeed("systemctl start secrethub-agent.service")
        machine.wait_for_file("/run/secrethub-credentials/db.sock")
        machine.succeed("systemctl start svc-alice.service")
        machine.succeed("test -e /tmp/alice.value")

    with subtest("pre-start success followed by main-process denial cannot start the target"):
        machine.succeed(f"printf '%s' 'limit 1 {canary}' > /run/hk-control/db")
        machine.fail("systemctl start svc-prestart.service")
        machine.fail("test -e /tmp/prestart-main-started")
        assert int(machine.succeed("cat /run/secrethub-agent/db.count")) >= 2

    with subtest("the per-user Agent runs with its own key, state and private socket"):
        uid = machine.succeed("id -u bob").strip()
        sock = f"/run/user/{uid}/secrethub/agent.sock"
        machine.wait_until_succeeds(f"test -S {sock}", timeout=120)
        machine.succeed(f"test \"$(stat -c '%U %a' /run/user/{uid}/secrethub)\" = 'bob 700'")
        key = "/home/bob/.local/state/secrethub-agent/user-host-key"
        machine.succeed(f"test \"$(stat -c '%U %a' {key})\" = 'bob 600'")
        machine.succeed(f"grep -q 'BEGIN OPENSSH PRIVATE KEY' {key}")
        env = machine.succeed("cat /home/bob/.local/state/secrethub-agent/stub-env.json")
        assert f'"SECRET_HUB_AGENT_SOCKET_PATH": "{sock}"' in env, env
        assert '"SECRET_HUB_AGENT_STATE_DIR": "/home/bob/.local/state/secrethub-agent"' in env, env
        assert "ssh_host" not in env, env
        machine.fail(f"sudo -u alice test -r {sock}")
        # Login sessions export the socket path; pam_systemd provides XDG_RUNTIME_DIR.
        machine.succeed("grep -F 'SECRET_HUB_AGENT_SOCKET_PATH=\"$XDG_RUNTIME_DIR/secrethub/agent.sock\"' /etc/set-environment")
        session = machine.succeed(f"su - bob -c 'XDG_RUNTIME_DIR=/run/user/{uid}; . /etc/set-environment; echo $SECRET_HUB_AGENT_SOCKET_PATH'").strip()
        assert session == sock, session
        machine.succeed("su - bob -c 'command -v secrethub-exec'")
        # The system Agent and its private socket directory are unaffected.
        machine.succeed("systemctl is-active secrethub-agent.service")
        machine.succeed("test \"$(stat -c %a /run/secrethub-agent)\" = 700")

    with subtest("raw empty EOF fails in the main launcher"):
        machine.succeed("printf deny > /run/hk-control/db")
        machine.fail("systemctl start svc-prestart.service")
        machine.succeed("journalctl -u svc-prestart.service | grep -F 'secrethub-exec'")
  '';
}
