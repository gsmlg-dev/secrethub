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

          version = "1.0.0-rc4";

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
            sha256 = "sha256-HhdD0HTVlMLU81hKnelZ0/qvhOE+WjBt7yNTPfISuAg=";
            mixEnv = "prod";
          };

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
            outputHash = "sha256-zs6e9HqaAjQ0NXiZuAgF4ec4ObjM9y+bvZCPZ52ADsM=";
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

              # Create stub package.json for file: deps referenced in bun.lock
              for dep in phoenix phoenix_html phoenix_live_view phoenix_duskmoon; do
                mkdir -p deps/$dep
                echo '{"name":"'$dep'","version":"0.0.0"}' > deps/$dep/package.json
              done

              HOME=$TMPDIR bun install --frozen-lockfile || HOME=$TMPDIR bun install

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

              nativeBuildInputs = [ pkgs.bun pkgs.tailwindcss_4 ];

              MIX_BUN_PATH = "${pkgs.bun}/bin/bun";
              MIX_TAILWIND_PATH = "${pkgs.tailwindcss_4}/bin/tailwindcss";

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

                # Fix heroicons git dep lock check: fetchMixDeps strips .git metadata
                # which causes Mix to detect a lock mismatch. Re-init a stub .git dir.
                if [ -d "deps/heroicons" ] && [ ! -d "deps/heroicons/.git" ]; then
                  mkdir -p deps/heroicons/.git
                  echo "ref: refs/heads/main" > deps/heroicons/.git/HEAD
                fi

                # Build assets using tools directly (avoids mix task overhead)
                mkdir -p apps/secrethub_web/priv/static/assets/css
                mkdir -p apps/secrethub_web/priv/static/assets/js

                $MIX_TAILWIND_PATH \
                  --input=apps/secrethub_web/assets/css/app.css \
                  --output=apps/secrethub_web/priv/static/assets/css/app.css \
                  --minify

                cd apps/secrethub_web
                $MIX_BUN_PATH build assets/js/app.js \
                  --outdir=priv/static/assets/js \
                  --external "/fonts/*" --external "/images/*" \
                  --minify
                cd ../..

                # Generate digest - use mix run with --no-deps-check in web app context
                # Set dummy env vars required by runtime.exs (only digest runs, no DB connection)
                cd apps/secrethub_web
                DATABASE_URL="postgresql://x:x@localhost/x" \
                SECRET_KEY_BASE="dummy-secret-key-base-for-nix-build-only-not-used-at-runtime-min-64-chars" \
                mix run --no-deps-check --no-start -e '
                  Mix.Tasks.Phx.Digest.run([])
                '
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
            };

            # SecretHub CLI: escript command-line tool
            secrethub-cli = beamPackages.mixRelease {
              pname = "secrethub-cli";
              inherit version src;
              mixEnv = "prod";
              mixFodDeps = mixDeps;

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
              description = "URL of the SecretHub Core service.";
              example = "https://secrethub.example.com";
            };

            agentId = lib.mkOption {
              type = lib.types.str;
              description = "Agent identifier.";
            };
          };

          config = lib.mkIf cfg.enable {
            systemd.services.secrethub-agent = {
              description = "SecretHub Agent Service";
              after = [ "network.target" ];
              wantedBy = [ "multi-user.target" ];

              environment = {
                CORE_URL = cfg.coreUrl;
                AGENT_ID = cfg.agentId;
                LANG = "C.UTF-8";
              };

              serviceConfig = {
                Type = "exec";
                Restart = "on-failure";
                RestartSec = 5;
                DynamicUser = true;
                StateDirectory = "secrethub-agent";
                RuntimeDirectory = "secrethub-agent";
              };

              script = ''
                exec ${cfg.package}/bin/secrethub_agent start
              '';
            };
          };
        };
    };
}
