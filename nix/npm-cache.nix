{ pkgs, lockfiles }:

let
  inherit (pkgs) lib;
  records = lib.concatMap (lockfile:
    lib.mapAttrsToList (path: package: package // {
      name = lib.last (lib.splitString "node_modules/" path);
    } // lib.optionalAttrs (package ? tarball) {
      resolved = package.tarball;
    }) (builtins.fromJSON (builtins.readFile lockfile)).packages
  ) lockfiles;
  packages = builtins.attrValues (builtins.listToAttrs (map (package: {
    name = "${package.name}@${package.version}";
    value = package;
  }) (builtins.filter (package: package ? integrity && package ? resolved) records)));
  unpack = package:
    let
      archive = pkgs.fetchurl {
        name = "${lib.replaceStrings [ "/" "@" ] [ "-" "" ] package.name}-${package.version}.tgz";
        url = package.resolved;
        hash = package.integrity;
      };
      target = lib.escapeShellArg "cache/${package.name}/${package.version}";
    in ''
      mkdir -p "$out"/${target}
      tar -xzf ${archive} -C "$out"/${target} --strip-components=1
      printf '1\n' > "$out"/${target}/.npm-ex-cache-complete
    '';
in
pkgs.runCommand "secrethub-npm-cache" { } (lib.concatMapStrings unpack packages)
