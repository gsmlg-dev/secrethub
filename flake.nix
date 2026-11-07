{
  description = "SecretHub - Enterprise Machine-to-Machine Secrets Management";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/release-25.11";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachSystem [
      "x86_64-linux"
      "aarch64-linux"
      "x86_64-darwin"
      "aarch64-darwin"
    ]
      (system:
        let
          pkgs = import nixpkgs { inherit system; };
          lib = pkgs.lib;
          beamPackages = pkgs.beam.packages.erlang_28;

          version = builtins.head (builtins.match ".*version: \"([^\"]+)\".*" (builtins.readFile ./mix.exs));

          src = lib.cleanSourceWith {
            src = self;
            filter = path: type:
              let
                baseName = builtins.baseNameOf path;
                relPath = lib.removePrefix (toString self + "/") (toString path);
              in
              # Exclude build artifacts and dev-only files
              !(lib.hasPrefix "_build" relPath)
              && !(lib.hasPrefix "deps" relPath)
              && !(lib.hasPrefix ".devenv" relPath)
              && !(lib.hasPrefix ".direnv" relPath)
              && !(lib.hasPrefix ".trees" relPath)
              && !(lib.hasPrefix "node_modules" relPath)
              && !(lib.hasPrefix "result" relPath)
              && !(lib.hasPrefix "cover" relPath)
              && baseName != ".git"
              && baseName != ".elixir_ls";
          };

          # Shared Mix dependencies (FOD - fixed-output derivation)
          mixDeps = beamPackages.fetchMixDeps {
            pname = "secrethub-mix-deps";
            inherit version src;
            sha256 = "sha256-8TvNdQjWd3EqQVbsPzqsk4WANEK5YZsS+VslrvLQDO8=";
            mixEnv = "prod";
          };

          # Published checksum manifests pin every native compiler and MDEx artifact.
          nativeArtifacts = (builtins.fromJSON (builtins.readFile ./nix/native-artifacts.json)).${system};
          nativeCache = pkgs.linkFarm "secrethub-precompiled-nifs" (map (artifact: {
            inherit (artifact) name;
            path = pkgs.fetchurl {
              inherit (artifact) url sha256;
            };
          }) nativeArtifacts);
          prepareNifs = ''
            export RUSTLER_PRECOMPILED_GLOBAL_CACHE_PATH="${nativeCache}"
            export ZIGLER_PRECOMPILED_GLOBAL_CACHE_PATH="${nativeCache}"
            export ELIXIR_MAKE_CACHE_DIR="${nativeCache}"
            export LD_LIBRARY_PATH="${lib.makeLibraryPath (lib.optionals pkgs.stdenv.isLinux [ pkgs.stdenv.cc.cc.lib ])}"
          '';

          # Populate the Mix npm cache from lockfile integrity values. The
          # private Tailwind compiler runtime is pinned separately from app deps.
          npmCache = import ./nix/npm-cache.nix {
            inherit pkgs;
            lockfiles = [ ./package-lock.json ./nix/tailwind-runtime.json ];
          };

        in
        {
          packages = {
            # SecretHub Core: central service (core + web + shared)
            secrethub-core = beamPackages.mixRelease {
              pname = "secrethub-core";
              inherit version src;
              mixEnv = "prod";
              mixFodDeps = mixDeps;
              mixReleaseName = "secrethub_core";
              preConfigure = prepareNifs;

              nativeBuildInputs = lib.optionals pkgs.stdenv.isLinux [ pkgs.autoPatchelfHook ];
              buildInputs = lib.optionals pkgs.stdenv.isLinux [ pkgs.stdenv.cc.cc.lib ];
              SECRET_HUB_GIT_REF = self.rev or self.dirtyRev or "";
              SECRET_HUB_GIT_SHA = self.rev or self.dirtyRev or "";
              SOURCE_DATE_EPOCH = toString (self.lastModified or 0);

              postBuild = ''
                export NPM_EX_CACHE_DIR="$TMPDIR/npm-cache"
                export DUSKMOON_BUNDLER_JS_RUNTIME_DIR="$TMPDIR/bundler-js-runtimes"
                mkdir -p "$NPM_EX_CACHE_DIR"
                cp -r ${npmCache}/. "$NPM_EX_CACHE_DIR/"
                chmod -R u+w "$NPM_EX_CACHE_DIR"

                # fetchMixDeps strips Git metadata; bypass the metadata check
                # while using the already locked and compiled dependencies.
                mix do deps.loadpaths --no-deps-check, npm.ci
                elixir -pa "_build/prod/lib/*/ebin" nix/prepare-tailwind-runtime.exs ${./nix/tailwind-runtime.json}
                mix do deps.loadpaths --no-deps-check, compile --no-deps-check, duskmoon_bundler.build secrethub_web --tailwind
                cd apps/secrethub_web
                mix do deps.loadpaths --no-deps-check, phx.digest --no-compile
                cd ../..
              '';
            };

            # SecretHub Agent: local daemon (agent + shared)
            secrethub-agent = beamPackages.mixRelease {
              pname = "secrethub-agent";
              inherit version src;
              mixEnv = "prod";
              mixFodDeps = mixDeps;
              mixReleaseName = "secrethub_agent";
              preConfigure = prepareNifs;
            };

            # SecretHub CLI: escript command-line tool
            secrethub-cli = beamPackages.mixRelease {
              pname = "secrethub-cli";
              inherit version src;
              mixEnv = "prod";
              mixFodDeps = mixDeps;
              preConfigure = prepareNifs;

              # Build escript from the CLI app subdirectory
              postBuild = ''
                cd apps/secrethub_cli
                mix escript.build --no-deps-check
                cd ../..
              '';

              installPhase = ''
                runHook preInstall
                mkdir -p $out/bin
                cp apps/secrethub_cli/secrethub $out/bin/secrethub
                runHook postInstall
              '';
            };

            default = self.packages.${system}.secrethub-core;

            # Docker/OCI images
            docker-core = pkgs.dockerTools.buildImage {
              name = "secrethub-core";
              tag = version;
              copyToRoot = pkgs.buildEnv {
                name = "secrethub-core-root";
                paths = [
                  self.packages.${system}.secrethub-core
                  pkgs.cacert
                  pkgs.busybox
                ];
              };
              config = {
                Cmd = [ "/bin/secrethub_core" "start" ];
                Env = [
                  "PHX_SERVER=true"
                  "LANG=C.UTF-8"
                ];
                ExposedPorts."4664/tcp" = { };
              };
            };

            docker-agent = pkgs.dockerTools.buildImage {
              name = "secrethub-agent";
              tag = version;
              copyToRoot = pkgs.buildEnv {
                name = "secrethub-agent-root";
                paths = [
                  self.packages.${system}.secrethub-agent
                  pkgs.cacert
                  pkgs.busybox
                ];
              };
              config = {
                Cmd = [ "/bin/secrethub_agent" "start" ];
                Env = [ "LANG=C.UTF-8" ];
              };
            };
          };

          checks = lib.optionalAttrs pkgs.stdenv.isLinux {
            agent-module = import ./nix/tests/agent-module.nix {
              inherit nixpkgs pkgs;
              agentModule = self.nixosModules.agent;
            };
          };

          # Dev shell (standalone alternative to devenv)
          devShells.default = pkgs.mkShell {
            packages = [
              beamPackages.elixir_1_18
              beamPackages.erlang
              pkgs.postgresql_16
              pkgs.openssl
              pkgs.git
            ] ++ lib.optionals pkgs.stdenv.isLinux [
              pkgs.inotify-tools
            ] ++ lib.optionals pkgs.stdenv.isDarwin [
              pkgs.darwin.apple_sdk.frameworks.CoreFoundation
              pkgs.darwin.apple_sdk.frameworks.CoreServices
            ];
          };
        })
    // {
      # Overlay: adds secrethub packages to nixpkgs
      overlays.default = final: prev: {
        secrethub-core = self.packages.${prev.system}.secrethub-core;
        secrethub-agent = self.packages.${prev.system}.secrethub-agent;
        secrethub-cli = self.packages.${prev.system}.secrethub-cli;
      };

      # NixOS module for SecretHub Core service
      nixosModules.default = { config, lib, pkgs, ... }:
        let
          cfg = config.services.secrethub;
        in
        {
          options.services.secrethub = {
            enable = lib.mkEnableOption "SecretHub Core service";

            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.system}.secrethub-core;
              defaultText = lib.literalExpression "secrethub.packages.\${system}.secrethub-core";
              description = "SecretHub Core package to use.";
            };

            port = lib.mkOption {
              type = lib.types.port;
              default = 4664;
              description = "Port for the SecretHub web interface.";
            };

            host = lib.mkOption {
              type = lib.types.str;
              default = "localhost";
              description = "Hostname for the SecretHub web interface.";
            };

            databaseUrl = lib.mkOption {
              type = lib.types.str;
              description = "PostgreSQL connection URL.";
              example = "postgresql://secrethub:password@localhost/secrethub_prod";
            };

            secretKeyBaseFile = lib.mkOption {
              type = lib.types.path;
              description = "Path to file containing SECRET_KEY_BASE.";
            };

            nodeId = lib.mkOption {
              type = lib.types.str;
              description = "Stable deployment-owned identity unique to this Core replica.";
              example = "core-replica-a";
            };

            openFirewall = lib.mkOption {
              type = lib.types.bool;
              default = false;
              description = "Whether to open the firewall port.";
            };
          };

          config = lib.mkIf cfg.enable {
            networking.firewall.allowedTCPPorts = lib.mkIf cfg.openFirewall [ cfg.port ];

            systemd.services.secrethub = {
              description = "SecretHub Core Service";
              after = [ "network.target" "postgresql.service" ];
              wantedBy = [ "multi-user.target" ];

              environment = {
                PHX_SERVER = "true";
                PHX_HOST = cfg.host;
                PORT = toString cfg.port;
                DATABASE_URL = cfg.databaseUrl;
                SECRET_HUB_CLUSTER_NODE_ID = cfg.nodeId;
                RELEASE_COOKIE = "secrethub-prod";
                LANG = "C.UTF-8";
              };

              serviceConfig = {
                Type = "exec";
                Restart = "on-failure";
                RestartSec = 5;
                DynamicUser = true;
                StateDirectory = "secrethub";
                LoadCredential = "secret_key_base:${cfg.secretKeyBaseFile}";
              };

              script = ''
                export SECRET_KEY_BASE=$(cat ''${CREDENTIALS_DIRECTORY}/secret_key_base)
                exec ${cfg.package}/bin/secrethub_core start
              '';
            };
          };
        };

      # NixOS module for SecretHub Agent
      nixosModules.agent = { config, lib, pkgs, ... }:
        let
          cfg = config.services.secrethub-agent;
          sshEnabled = cfg.ssh.lookup.enable || cfg.ssh.signing.enable;
          lookupDir = builtins.dirOf cfg.ssh.lookup.socketPath;
          signingDir = builtins.dirOf cfg.ssh.signing.socketPath;
          socketDirectoryValid = path:
            builtins.match "/run/[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*" path != null && builtins.dirOf path != "/run"
            && !(lib.hasInfix "/../" path) && builtins.stringLength path <= 100
            && !(lib.hasPrefix "/run/secrethub-agent/" path);
          sshGroups = lib.optional cfg.ssh.lookup.enable cfg.ssh.lookup.group
            ++ lib.optional cfg.ssh.signing.enable cfg.ssh.signing.group;
          publicHelpers = pkgs.symlinkJoin {
            name = "secrethub-ssh-helpers";
            paths = [
              (pkgs.writeShellScriptBin "secrethub-fetch-ssh-keys" ''
                exec ${cfg.package}/bin/secrethub_agent fetch-ssh-keys --socket ${lib.escapeShellArg cfg.ssh.lookup.socketPath} "$@"
              '')
              (pkgs.writeShellScriptBin "secrethub-fetch-ssh-host-keys" ''
                exec ${cfg.package}/bin/secrethub_agent fetch-ssh-host-keys --socket ${lib.escapeShellArg cfg.ssh.lookup.socketPath} "$@"
              '')
            ];
          };
        in
        {
          options.services.secrethub-agent = {
            enable = lib.mkEnableOption "SecretHub Agent service";

            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.system}.secrethub-agent;
              defaultText = lib.literalExpression "secrethub.packages.\${system}.secrethub-agent";
              description = "SecretHub Agent package to use.";
            };

            coreUrl = lib.mkOption {
              type = lib.types.str;
              description = ''
                HTTPS URL of Core's Agent listener, shared by machine enrollment
                and runtime WSS. Core supplies runtime connection settings during enrollment.
              '';
              example = "https://core.example.com:4665";
            };

            hostKeyPath = lib.mkOption {
              type = lib.types.str;
              default = "/etc/ssh/ssh_host_rsa_key";
              description = ''
                Absolute runtime path to an existing RSA or ECDSA SSH private
                host key. systemd passes a private credential copy to the Agent.
                Use a quoted string; never put the private key in the Nix store.
                Ed25519 keys are not supported for enrollment.
              '';
            };

            enrollmentCaPath = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              example = "/etc/secrethub/enrollment-ca.pem";
              description = ''
                Optional absolute path to a PEM CA bundle for the enrollment
                HTTPS server. Null uses the normal CA trust store. The runtime
                mTLS CA chain is supplied separately by Core during enrollment.
              '';
            };

            ssh = {
              lookup = {
                enable = lib.mkEnableOption "public SSH key and known-host lookups";
                socketPath = lib.mkOption { type = lib.types.str; default = "/run/secrethub-ssh/lookup.sock"; };
                group = lib.mkOption { type = lib.types.str; default = "secrethub-ssh-lookup"; };
              };
              signing = {
                enable = lib.mkEnableOption "SSH agent signing";
                socketPath = lib.mkOption { type = lib.types.str; default = "/run/secrethub-ssh-signing/agent.sock"; };
                group = lib.mkOption { type = lib.types.str; default = "secrethub-ssh-signing"; };
              };
              sourceUsers = lib.mkOption {
                type = lib.types.listOf lib.types.str;
                default = [ ];
                description = "Existing Unix source accounts receiving enabled SSH socket groups. Core policy still authorizes each request.";
              };
            };

            agentId = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              description = "Deprecated and ignored; Core assigns the Agent identity during enrollment.";
            };
          };

          config = lib.mkIf cfg.enable {
            assertions = [
              {
                assertion = builtins.match "https://[^/?#@[:space:]]+(/[^?#[:space:]]*)?" cfg.coreUrl != null;
                message = "services.secrethub-agent.coreUrl must be an HTTPS enrollment URL without credentials, query or fragment.";
              }
              {
                assertion = lib.hasPrefix "/" cfg.hostKeyPath && !(lib.hasPrefix "/nix/store/" cfg.hostKeyPath);
                message = "services.secrethub-agent.hostKeyPath must be an absolute runtime path outside the Nix store.";
              }
              {
                assertion = cfg.enrollmentCaPath == null || lib.hasPrefix "/" cfg.enrollmentCaPath;
                message = "services.secrethub-agent.enrollmentCaPath must be an absolute path.";
              }
              {
                assertion = !cfg.ssh.lookup.enable || socketDirectoryValid cfg.ssh.lookup.socketPath;
                message = "services.secrethub-agent.ssh.lookup.socketPath must use a separate shared directory under /run and fit Linux socket limits.";
              }
              {
                assertion = !cfg.ssh.signing.enable || socketDirectoryValid cfg.ssh.signing.socketPath;
                message = "services.secrethub-agent.ssh.signing.socketPath must use a separate shared directory under /run and fit Linux socket limits.";
              }
              {
                assertion = !(cfg.ssh.lookup.enable && cfg.ssh.signing.enable) || (lookupDir != signingDir && cfg.ssh.lookup.group != cfg.ssh.signing.group);
                message = "services.secrethub-agent.ssh lookup and signing directories and groups must differ.";
              }
              {
                assertion = !(builtins.elem "nobody" cfg.ssh.sourceUsers);
                message = "services.secrethub-agent.ssh.sourceUsers must exclude the public helper account nobody.";
              }
              {
                assertion = lib.all (name: builtins.match "[a-zA-Z_][a-zA-Z0-9_-]{0,63}" name != null) sshGroups;
                message = "services.secrethub-agent.ssh groups must be valid static Unix group names.";
              }
            ];

            users.groups = lib.genAttrs sshGroups (_: { });
            users.users = lib.mkMerge [
              (lib.genAttrs cfg.ssh.sourceUsers (_: { extraGroups = sshGroups; }))
              (lib.mkIf cfg.ssh.lookup.enable { nobody.extraGroups = [ cfg.ssh.lookup.group ]; })
            ];
            environment.systemPackages = lib.optional cfg.ssh.lookup.enable publicHelpers;

            warnings = lib.optional (cfg.agentId != null)
              "services.secrethub-agent.agentId is ignored; remove it because Core assigns the Agent identity.";

            systemd.services.secrethub-agent = {
              description = "SecretHub Agent Service";
              after = [ "network-online.target" "sshd-keygen.service" ];
              wants = [ "network-online.target" ]
                ++ lib.optional config.services.openssh.enable "sshd-keygen.service";
              wantedBy = [ "multi-user.target" ];
              path = [ pkgs.getent pkgs.coreutils ];

              environment = {
                SECRET_HUB_AGENT_CORE_URL = cfg.coreUrl;
                SECRET_HUB_AGENT_HOST_KEY_PATH = "%d/ssh-host-key";
                SECRET_HUB_AGENT_STATE_DIR = "/var/lib/secrethub-agent";
                SECRET_HUB_AGENT_SOCKET_PATH = "/run/secrethub-agent/agent.sock";
                SECRET_HUB_CLIENT_AUTH_BUNDLE_DIR = "/var/lib/secrethub-agent/client-auth";
                RELEASE_DISTRIBUTION = "none";
                RELEASE_TMP = "/run/secrethub-agent";
                ERL_CRASH_DUMP = "/dev/null";
                LANG = "C.UTF-8";
                SECRET_HUB_AGENT_SSH_LOOKUP_ENABLED = lib.boolToString cfg.ssh.lookup.enable;
                SECRET_HUB_AGENT_SSH_SIGNING_ENABLED = lib.boolToString cfg.ssh.signing.enable;
              } // lib.optionalAttrs cfg.ssh.lookup.enable {
                SECRET_HUB_AGENT_SSH_LOOKUP_SOCKET_PATH = cfg.ssh.lookup.socketPath;
                SECRET_HUB_AGENT_SSH_LOOKUP_SOCKET_GROUP = cfg.ssh.lookup.group;
              } // lib.optionalAttrs cfg.ssh.signing.enable {
                SECRET_HUB_AGENT_SSH_SIGNING_SOCKET_PATH = cfg.ssh.signing.socketPath;
                SECRET_HUB_AGENT_SSH_SIGNING_SOCKET_GROUP = cfg.ssh.signing.group;
              } // lib.optionalAttrs (cfg.enrollmentCaPath != null) {
                SECRET_HUB_AGENT_ENROLLMENT_CA_PATH = "%d/enrollment-ca";
              };

              serviceConfig = {
                Type = "exec";
                Restart = "on-failure";
                RestartSec = 5;
                DynamicUser = true;
                StateDirectory = "secrethub-agent";
                StateDirectoryMode = "0700";
                SupplementaryGroups = sshGroups;
                RuntimeDirectory = if sshEnabled then [ "secrethub-agent" ]
                  ++ lib.optional cfg.ssh.lookup.enable (lib.removePrefix "/run/" lookupDir)
                  ++ lib.optional cfg.ssh.signing.enable (lib.removePrefix "/run/" signingDir)
                  else "secrethub-agent";
                RuntimeDirectoryMode = "0700";
                WorkingDirectory = "/var/lib/secrethub-agent";
                UMask = "0077";
                LoadCredential = [ "ssh-host-key:${cfg.hostKeyPath}" ]
                  ++ lib.optional (cfg.enrollmentCaPath != null) "enrollment-ca:${cfg.enrollmentCaPath}";
              };

              preStart = ''
                install -d -m 0700 "$SECRET_HUB_CLIENT_AUTH_BUNDLE_DIR"
              '' + lib.optionalString cfg.ssh.lookup.enable ''
                chgrp ${lib.escapeShellArg cfg.ssh.lookup.group} ${lib.escapeShellArg lookupDir}
                chmod 0750 ${lib.escapeShellArg lookupDir}
              '' + lib.optionalString cfg.ssh.signing.enable ''
                chgrp ${lib.escapeShellArg cfg.ssh.signing.group} ${lib.escapeShellArg signingDir}
                chmod 0750 ${lib.escapeShellArg signingDir}
              '';

              script = ''
                # mixRelease removes its build-time cookie. Distribution is off,
                # so a fresh process-local cookie needs no persistent secret.
                export RELEASE_COOKIE="$(head -c 32 /dev/urandom | base64)"
                exec ${cfg.package}/bin/secrethub_agent start
              '';
            };
          };
        };
    };
}
