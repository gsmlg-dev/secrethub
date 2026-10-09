{ nixpkgs, pkgs, agentModule }:
let
  inherit (pkgs) lib;
  evaluate = settings: nixpkgs.lib.nixosSystem {
    system = pkgs.stdenv.hostPlatform.system;
    modules = [
      agentModule
      {
        system.stateVersion = "25.11";
        services.secrethub-agent = settings;
      }
    ];
  };
  settings = {
    enable = true;
    coreUrl = "https://enroll.example.test";
  };
  enabled = (evaluate settings).config;
  service = enabled.systemd.services.secrethub-agent;
  legacy = (evaluate (settings // { agentId = "old-local-id"; })).config;
  privateCA = (evaluate (settings // {
    hostKeyPath = "/run/keys/ssh-host-key";
    enrollmentCaPath = "/run/keys/enrollment-ca.pem";
  })).config.systemd.services.secrethub-agent;
  agentFailures = config:
    lib.filter (item: !item.assertion && lib.hasPrefix "services.secrethub-agent." item.message) config.assertions;
  rejected = overrides:
    agentFailures (evaluate (settings // overrides)).config != [ ];
  checks = [
    (lib.assertMsg ((service.environment.SECRET_HUB_AGENT_CORE_URL or null) == settings.coreUrl)
      "The Agent service must pass the current HTTPS enrollment input")
    (lib.assertMsg (!(service.environment ? AGENT_ID) && !(service.environment ? CORE_URL))
      "Legacy environment variables must not override Core-issued identity")
    (lib.assertMsg (service.environment.RELEASE_DISTRIBUTION == "none")
      "Agent distribution must stay disabled")
    (lib.assertMsg (service.environment.RELEASE_TMP == "/run/secrethub-agent")
      "Release configuration must be writable outside the Nix store")
    (lib.assertMsg (service.environment.SECRET_HUB_AGENT_HOST_KEY_PATH == "%d/ssh-host-key")
      "The unprivileged Agent must read the systemd credential copy")
    (lib.assertMsg (service.serviceConfig.LoadCredential == [ "ssh-host-key:/etc/ssh/ssh_host_rsa_key" ])
      "The SSH private key must be loaded at runtime")
    (lib.assertMsg (service.serviceConfig.StateDirectoryMode == "0700")
      "Persistent Agent identity must be private")
    (lib.assertMsg (!(service.environment ? SECRET_HUB_AGENT_ENROLLMENT_CA_PATH))
      "Public enrollment HTTPS must use the normal trust store")
    (lib.assertMsg (privateCA.environment.SECRET_HUB_AGENT_ENROLLMENT_CA_PATH == "%d/enrollment-ca")
      "Private enrollment CA must reach the runtime configuration")
    (lib.assertMsg (privateCA.serviceConfig.LoadCredential == [
      "ssh-host-key:/run/keys/ssh-host-key"
      "enrollment-ca:/run/keys/enrollment-ca.pem"
    ]) "Custom credential sources must be preserved")
    (lib.assertMsg (legacy.systemd.services.secrethub-agent.environment == service.environment)
      "Deprecated agentId must not change runtime identity")
    (lib.assertMsg (!((evaluate { enable = false; }).config.systemd.services ? secrethub-agent))
      "A disabled Agent module must not require deployment inputs")
    (lib.assertMsg (rejected { coreUrl = "http://enroll.example.test"; })
      "Insecure enrollment must fail evaluation")
    (lib.assertMsg (rejected { hostKeyPath = "/nix/store/private-host-key"; })
      "SSH private keys must not come from the Nix store")
    (lib.assertMsg (agentFailures enabled == [ ])
      "The minimal supported Agent configuration must satisfy its assertions")
  ];
in
assert lib.all (result: result) checks;
pkgs.runCommand "secrethub-agent-module-check" {
  nativeBuildInputs = [ pkgs.openssh pkgs.openssl pkgs.python3 ];
  environmentFile = pkgs.writeText "agent-service-environment.json" (builtins.toJSON service.environment);
  preStartFile = pkgs.writeText "agent-pre-start" service.preStart;
  startFile = pkgs.writeText "agent-start" service.script;
  agentPackage = enabled.services.secrethub-agent.package;
} ''
  # Use the evaluated service environment and startup preparation, replacing only
  # systemd-managed directories with sandbox-owned temporary directories.
  export agentTestRoot="$TMPDIR/agent-test"
  mkdir -p "$agentTestRoot/credentials" "$agentTestRoot/state" "$agentTestRoot/run"
  chmod 700 "$agentTestRoot/state" "$agentTestRoot/run"
  ssh-keygen -q -t rsa -b 2048 -N "" -f "$agentTestRoot/credentials/ssh-host-key"
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj /CN=Enrollment-Test-CA \
    -keyout "$agentTestRoot/ca.key" -out "$agentTestRoot/credentials/enrollment-ca" 2>/dev/null

  python3 - <<'PY'
  import json
  import os
  import subprocess
  from pathlib import Path

  root = os.environ["agentTestRoot"]
  replacements = {
      "/var/lib/secrethub-agent": root + "/state",
      "/run/secrethub-agent": root + "/run",
      "%d": root + "/credentials",
  }

  def remap(value):
      for source, destination in replacements.items():
          value = value.replace(source, destination)
      return value

  env = {key: remap(value) for key, value in json.loads(Path(os.environ["environmentFile"]).read_text()).items()}
  env.update(CREDENTIALS_DIRECTORY=root + "/credentials", ERL_FLAGS="+S 2:2")
  preparation = remap(Path(os.environ["preStartFile"]).read_text())
  subprocess.run(["${pkgs.bash}/bin/bash", "-eu", "-c", preparation], env=env, check=True)
  start = remap(Path(os.environ["startFile"]).read_text())
  # Exercise the actual launcher and runtime config without starting enrollment.
  probe = "SecretHub.Agent.Preflight.run()"
  start = start.replace('/bin/secrethub_agent start', "/bin/secrethub_agent eval '" + probe + "'")
  assert " eval " in start
  for private_ca in (False, True):
      if private_ca:
          env["SECRET_HUB_AGENT_ENROLLMENT_CA_PATH"] = root + "/credentials/enrollment-ca"
      result = subprocess.run(["${pkgs.bash}/bin/bash", "-eu", "-c", start], env=env, text=True, capture_output=True)
      assert result.returncode == 0, result.stdout + result.stderr
      reports = [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]
      assert reports and reports[-1]["passed"], result.stdout
      print("Agent packaged preflight passed (private enrollment CA: %s)" % private_ca)
  PY
  touch "$out"
''
