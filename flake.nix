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
            sha256 = "sha256-bbCp6CshIbd5TfL6115grJJInu/z+PhukmEUSF8Qdyk=";
            mixEnv = "prod";
          };

          # RustlerPrecompiled supports an offline cache for the published MDEx
          # NIF. Hashes are from mdex_native 0.2.11's checksum manifest.
          mdexTarget = {
            x86_64-linux = {
              target = "x86_64-unknown-linux-gnu";
              sha256 = "92d39f336119bce948468a1dfc7f02052e38e16323408d1ac92c0ac7261423a8";
            };
            aarch64-linux = {
              target = "aarch64-unknown-linux-gnu";
              sha256 = "fad246782bcb277ce9d18aff2c2ad652c6fedcc00fdcce50cf2843e00d025b8e";
            };
            x86_64-darwin = {
              target = "x86_64-apple-darwin";
              sha256 = "ffad284452ccec7e0a94137386f2e910188d4024e8b2a3101c2603dd02a28106";
            };
            aarch64-darwin = {
              target = "aarch64-apple-darwin";
              sha256 = "be04155aec6c43d9a90d9e082c8d39983cf6ee497ce623e25bd41df4058c6a80";
            };
          }.${system};
          mdexArtifactName = "libmdex_native_nif-v0.2.11-nif-2.15-${mdexTarget.target}.so.tar.gz";
          mdexArtifact = pkgs.fetchurl {
            url = "https://github.com/leandrocp/mdex_native/releases/download/v0.2.11/${mdexArtifactName}";
            inherit (mdexTarget) sha256;
          };
          prepareNifs = ''
            export RUSTLER_PRECOMPILED_GLOBAL_CACHE_PATH="$TMPDIR/precompiled-nifs"
            mkdir -p "$RUSTLER_PRECOMPILED_GLOBAL_CACHE_PATH"
            cp ${mdexArtifact} "$RUSTLER_PRECOMPILED_GLOBAL_CACHE_PATH/${mdexArtifactName}"
          '';

          # Pre-fetched Bun/npm dependencies for asset pipeline
          bunDeps = pkgs.stdenvNoCC.mkDerivation {
            pname = "secrethub-bun-deps";
            inherit version;

            srcs = [ ];
            dontUnpack = true;

            nativeBuildInputs = [ pkgs.bun pkgs.cacert ];

            # FOD: network access allowed, output pinned by hash
            outputHashMode = "recursive";
            outputHashAlgo = "sha256";
            outputHash = "sha256-oCijd2KO4GUHnaEhrjcIIdrzdw2Hda3k9QkEu0GplP4=";
            impureEnvVars = lib.fetchers.proxyImpureEnvVars;

            # Prevent patchShebangs from embedding store paths in the output
            dontPatchShebangs = true;
            dontFixup = true;

            buildPhase = ''
              runHook preBuild

              # Reconstruct workspace structure
              mkdir -p apps/secrethub_web
              cp ${./package.json} package.json
              cp ${./bun.lock} bun.lock
              cp ${./bunfig.toml} bunfig.toml
              cp ${./apps/secrethub_web/package.json} apps/secrethub_web/package.json

              # Use the locked Mix package sources for Bun's file dependencies.
              for dep in phoenix phoenix_html phoenix_live_view phoenix_duskmoon; do
                mkdir -p deps
                cp -r ${mixDeps}/$dep deps/$dep
              done
              chmod -R u+w deps

              export BUN_INSTALL_CACHE_DIR="$TMPDIR/bun-cache"
              # Keep the shared FOD identical across the four supported systems.
              bun install --frozen-lockfile --ignore-scripts --os '*' --cpu '*'

              # Bun's generated command shims vary with install scheduling.
              # Asset tools use explicit package entry paths, so discard them.
              find node_modules apps/secrethub_web/node_modules \
                -type d \( -path 'node_modules/.bin' -o -path '*/node_modules/.bin' \) \
                -prune -exec rm -rf {} +

              runHook postBuild
            '';

            installPhase = ''
              runHook preInstall
              mkdir -p $out
              cp -r node_modules $out/node_modules 2>/dev/null || true
              if [ -d apps/secrethub_web/node_modules ]; then
                cp -r apps/secrethub_web/node_modules $out/web_node_modules
              fi
              runHook postInstall
            '';
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

              nativeBuildInputs = [ pkgs.bun ];

              MIX_BUN_PATH = "${pkgs.bun}/bin/bun";

              postBuild = ''
                # Install pre-fetched node_modules for asset pipeline
                if [ -d "${bunDeps}/node_modules" ]; then
                  cp -r ${bunDeps}/node_modules ./node_modules
                  chmod -R u+w ./node_modules
                fi
                if [ -d "${bunDeps}/web_node_modules" ]; then
                  cp -r ${bunDeps}/web_node_modules apps/secrethub_web/node_modules
                  chmod -R u+w apps/secrethub_web/node_modules
                fi

                # Link file: deps to actual mix deps
                for dep in phoenix phoenix_html phoenix_live_view phoenix_duskmoon; do
                  if [ -d "deps/$dep" ]; then
                    rm -rf "node_modules/$dep" 2>/dev/null || true
                    ln -sf "$(pwd)/deps/$dep" "node_modules/$dep"
                  fi
                done

                # Build assets using tools directly (avoids mix task overhead)
                mkdir -p apps/secrethub_web/priv/static/assets/css
                mkdir -p apps/secrethub_web/priv/static/assets/js

                cd apps/secrethub_web
                $MIX_BUN_PATH ./node_modules/@tailwindcss/cli/dist/index.mjs \
                  --input=assets/css/app.css \
                  --output=priv/static/assets/css/app.css \
                  --minify

                export NODE_PATH="$(pwd)/../../deps''${NODE_PATH:+:$NODE_PATH}"
                $MIX_BUN_PATH build assets/js/app.js \
                  --outdir=priv/static/assets/js \
                  --external "/fonts/*" --external "/images/*" \
                  --minify
                cd ../..

                # fetchMixDeps strips Git metadata. Load the pinned, compiled
                # dependencies explicitly before digest, without runtime config.
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
              pkgs.bun
              pkgs.tailwindcss_4
              pkgs.postgresql_16
              pkgs.openssl
              pkgs.git
            ] ++ lib.optionals pkgs.stdenv.isLinux [
              pkgs.inotify-tools
            ] ++ lib.optionals pkgs.stdenv.isDarwin [
              pkgs.darwin.apple_sdk.frameworks.CoreFoundation
              pkgs.darwin.apple_sdk.frameworks.CoreServices
            ];

            shellHook = ''
              export MIX_BUN_PATH="${pkgs.bun}/bin/bun"
              export MIX_TAILWIND_PATH="${pkgs.tailwindcss_4}/bin/tailwindcss"
            '';
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
                HTTPS URL of Core's machine enrollment API. Core supplies the
                separate mTLS WebSocket endpoint during enrollment.
              '';
              example = "https://enroll.secrethub.example.com";
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
            ];

            warnings = lib.optional (cfg.agentId != null)
              "services.secrethub-agent.agentId is ignored; remove it because Core assigns the Agent identity.";

            systemd.services.secrethub-agent = {
              description = "SecretHub Agent Service";
              after = [ "network-online.target" "sshd-keygen.service" ];
              wants = [ "network-online.target" ]
                ++ lib.optional config.services.openssh.enable "sshd-keygen.service";
              wantedBy = [ "multi-user.target" ];

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
                RuntimeDirectory = "secrethub-agent";
                RuntimeDirectoryMode = "0700";
                WorkingDirectory = "/var/lib/secrethub-agent";
                UMask = "0077";
                LoadCredential = [ "ssh-host-key:${cfg.hostKeyPath}" ]
                  ++ lib.optional (cfg.enrollmentCaPath != null) "enrollment-ca:${cfg.enrollmentCaPath}";
              };

              preStart = ''
                install -d -m 0700 "$SECRET_HUB_CLIENT_AUTH_BUNDLE_DIR"
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
