# Real systemd qualification of the NixOS Agent SSH socket directories.
#
# Verifies that systemd does not revert shared SSH parent directories back to
# RuntimeDirectoryMode=0700 / primary group after startup or service restart,
# covering both default and configurable (including nested) SSH socket paths.
{ pkgs, agentModule }:
let
  # Minimal stub speaking the lookup JSON framing and OpenSSH agent
  # SSH_AGENTC_REQUEST_IDENTITIES protocol so real `ssh-add -L` and the
  # module-installed `secrethub-fetch-ssh-keys` helper exercise actual Unix
  # socket traversal and group boundaries under systemd.
  stubAgent = pkgs.writeTextFile {
    name = "secrethub-agent-ssh-stub";
    destination = "/bin/secrethub_agent";
    executable = true;
    text = ''
      #!${pkgs.python3}/bin/python3
      import grp, json, os, socket, struct, sys, threading

      SSH_AGENTC_REQUEST_IDENTITIES = 11
      SSH_AGENT_IDENTITIES_ANSWER = 12
      SSH_AGENT_FAILURE = 5

      def pack_str(data: bytes) -> bytes:
          return struct.pack(">I", len(data)) + data

      def recv_exact(conn, n):
          buf = bytearray()
          while len(buf) < n:
              chunk = conn.recv(n - len(buf))
              if not chunk:
                  return None
              buf.extend(chunk)
          return bytes(buf)

      def recv_frame(conn):
          hdr = recv_exact(conn, 4)
          if not hdr:
              return None
          (length,) = struct.unpack(">I", hdr)
          if length < 1 or length > 1048576:
              return None
          return recv_exact(conn, length)

      def send_frame(conn, payload: bytes):
          conn.sendall(struct.pack(">I", len(payload)) + payload)

      def run_helper(args):
          if "--socket" not in args:
              sys.stderr.write("missing --socket\n")
              return 1
          idx = args.index("--socket")
          sock_path = args[idx + 1]
          with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
              conn.connect(sock_path)
              req = json.dumps({"op": "authorized_keys", "args": args[idx + 2 :]}).encode()
              send_frame(conn, req)
              reply = recv_frame(conn)
              if not reply:
                  return 1
              parsed = json.loads(reply.decode())
              if not parsed.get("ok"):
                  return 1
              for line in parsed.get("lines", []):
                  print(line)
              return 0

      if len(sys.argv) > 1 and sys.argv[1] in ("fetch-ssh-keys", "fetch-ssh-host-keys"):
          sys.exit(run_helper(sys.argv[2:]))

      def bind_socket(path, group_name=None, mode=0o600):
          try:
              os.unlink(path)
          except FileNotFoundError:
              pass
          sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
          sock.bind(path)
          if group_name:
              gid = grp.getgrnam(group_name).gr_gid
              os.chown(path, -1, gid)
          os.chmod(path, mode)
          sock.listen(16)
          return sock

      def serve_lookup(sock):
          while True:
              conn, _ = sock.accept()
              with conn:
                  req = recv_frame(conn)
                  if req is None:
                      continue
                  resp = json.dumps({
                      "ok": True,
                      "lines": ["no-agent-forwarding ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8= secrethub-test"],
                  }).encode()
                  send_frame(conn, resp)

      KEY_BLOB = pack_str(b"ssh-ed25519") + pack_str(bytes(range(32)))
      IDENTITIES_REPLY = (
          bytes([SSH_AGENT_IDENTITIES_ANSWER])
          + struct.pack(">I", 1)
          + pack_str(KEY_BLOB)
          + pack_str(b"secrethub-test")
      )

      def serve_signing(sock):
          while True:
              conn, _ = sock.accept()
              with conn:
                  while True:
                      req = recv_frame(conn)
                      if not req:
                          break
                      if req[0] == SSH_AGENTC_REQUEST_IDENTITIES:
                          send_frame(conn, IDENTITIES_REPLY)
                      else:
                          send_frame(conn, bytes([SSH_AGENT_FAILURE]))

      if os.environ.get("SECRET_HUB_AGENT_SSH_LOOKUP_ENABLED") == "true":
          lookup_sock = bind_socket(
              os.environ["SECRET_HUB_AGENT_SSH_LOOKUP_SOCKET_PATH"],
              os.environ.get("SECRET_HUB_AGENT_SSH_LOOKUP_SOCKET_GROUP"),
              0o660,
          )
          threading.Thread(target=serve_lookup, args=(lookup_sock,), daemon=True).start()

      if os.environ.get("SECRET_HUB_AGENT_SSH_SIGNING_ENABLED") == "true":
          signing_sock = bind_socket(
              os.environ["SECRET_HUB_AGENT_SSH_SIGNING_SOCKET_PATH"],
              os.environ.get("SECRET_HUB_AGENT_SSH_SIGNING_SOCKET_GROUP"),
              0o660,
          )
          threading.Thread(target=serve_signing, args=(signing_sock,), daemon=True).start()

      # Bind the private application socket last as the readiness marker.
      bind_socket(os.environ["SECRET_HUB_AGENT_SOCKET_PATH"], None, 0o600)

      threading.Event().wait()
    '';
  };

  commonNode = { pkgs, ... }: {
    imports = [ agentModule ];

    environment.etc."ssh-dummy-host-key".text = "test-only";
    environment.systemPackages = [ pkgs.openssh ];

    users.users.deploy = { isNormalUser = true; };
    users.users.outsider = { isNormalUser = true; };

    services.secrethub-agent = {
      enable = true;
      coreUrl = "https://core.example.test:4665";
      hostKeyPath = "/etc/ssh-dummy-host-key";
      package = stubAgent;
      ssh = {
        lookup.enable = true;
        signing.enable = true;
        sourceUsers = [ "deploy" ];
      };
    };
  };
in
pkgs.testers.runNixOSTest {
  name = "secrethub-ssh-sockets-systemd";

  nodes = {
    defaultLocations = commonNode;

    customLocations = { pkgs, ... }: {
      imports = [ commonNode ];

      services.secrethub-agent.ssh = {
        lookup = {
          socketPath = "/run/custom-ssh/lookup/lookup.sock";
          group = "custom-ssh-lookup";
        };
        signing = {
          socketPath = "/run/custom-ssh/signing/agent.sock";
          group = "custom-ssh-signing";
        };
      };
    };
  };

  testScript = ''
    def verify_node(node, lookup_dir, lookup_sock, lookup_group, signing_dir, signing_sock, signing_group):
        node.wait_for_unit("secrethub-agent.service")
        node.wait_for_file(lookup_sock)
        node.wait_for_file(signing_sock)
        node.wait_for_file("/run/secrethub-agent/agent.sock")

        # Shared SSH parents must have mode 0750 and their own configured group.
        node.succeed(f'test "$(stat -c "%a %G" {lookup_dir})" = "750 {lookup_group}"')
        node.succeed(f'test "$(stat -c "%a %G" {signing_dir})" = "750 {signing_group}"')
        node.succeed(f'test "$(stat -c "%a %G" {lookup_sock})" = "660 {lookup_group}"')
        node.succeed(f'test "$(stat -c "%a %G" {signing_sock})" = "660 {signing_group}"')

        # Private application socket and persistent Agent state remain 0700.
        node.succeed('test "$(stat -c %a /run/secrethub-agent)" = "700"')
        node.succeed('test "$(stat -c %a /run/secrethub-agent/agent.sock)" = "600"')
        node.succeed('test "$(stat -L -c %a /var/lib/secrethub-agent)" = "700"')
        node.succeed('test "$(stat -L -c %a /var/lib/secrethub-agent/client-auth)" = "700"')

        # Real source user can traverse and query signing + lookup sockets, not private state.
        node.succeed(f"su -s /bin/sh deploy -c 'test -x {signing_dir} && test -x {lookup_dir}'")
        listed = node.succeed(f"su -s /bin/sh deploy -c 'SSH_AUTH_SOCK={signing_sock} ssh-add -L'")
        assert "ssh-ed25519" in listed and "secrethub-test" in listed, listed
        node.fail("su -s /bin/sh deploy -c 'test -x /run/secrethub-agent'")
        node.fail("su -s /bin/sh deploy -c 'test -x /var/lib/secrethub-agent'")

        # sshd lookup helper account (nobody) can query lookup while remaining excluded from signing.
        node.succeed(f"su -s /bin/sh nobody -c 'test -x {lookup_dir}'")
        lookup_out = node.succeed("su -s /bin/sh nobody -c 'secrethub-fetch-ssh-keys deploy dummy-key'")
        assert "no-agent-forwarding ssh-ed25519" in lookup_out, lookup_out
        node.fail(f"su -s /bin/sh nobody -c 'test -x {signing_dir}'")
        node.fail(f"su -s /bin/sh nobody -c 'SSH_AUTH_SOCK={signing_sock} ssh-add -L'")
        node.fail("su -s /bin/sh nobody -c 'test -x /run/secrethub-agent'")

        # Unrelated local accounts remain excluded from all Agent directories.
        node.fail(f"su -s /bin/sh outsider -c 'test -x {lookup_dir}'")
        node.fail(f"su -s /bin/sh outsider -c 'test -x {signing_dir}'")
        node.fail("su -s /bin/sh outsider -c 'test -x /run/secrethub-agent'")

    start_all()

    with subtest("default SSH socket locations work after activation and restart"):
        verify_node(
            defaultLocations,
            "/run/secrethub-ssh",
            "/run/secrethub-ssh/lookup.sock",
            "secrethub-ssh-lookup",
            "/run/secrethub-ssh-signing",
            "/run/secrethub-ssh-signing/agent.sock",
            "secrethub-ssh-signing",
        )
        defaultLocations.succeed("systemctl restart secrethub-agent.service")
        verify_node(
            defaultLocations,
            "/run/secrethub-ssh",
            "/run/secrethub-ssh/lookup.sock",
            "secrethub-ssh-lookup",
            "/run/secrethub-ssh-signing",
            "/run/secrethub-ssh-signing/agent.sock",
            "secrethub-ssh-signing",
        )

    with subtest("configurable nested SSH socket locations work after activation and restart"):
        verify_node(
            customLocations,
            "/run/custom-ssh/lookup",
            "/run/custom-ssh/lookup/lookup.sock",
            "custom-ssh-lookup",
            "/run/custom-ssh/signing",
            "/run/custom-ssh/signing/agent.sock",
            "custom-ssh-signing",
        )
        customLocations.succeed("systemctl restart secrethub-agent.service")
        verify_node(
            customLocations,
            "/run/custom-ssh/lookup",
            "/run/custom-ssh/lookup/lookup.sock",
            "custom-ssh-lookup",
            "/run/custom-ssh/signing",
            "/run/custom-ssh/signing/agent.sock",
            "custom-ssh-signing",
        )
  '';
}
