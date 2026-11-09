#!/bin/sh
# Builds host keyring artifacts outside Nix for local verification:
#   OUT/libexec/secrethub-cli   escript
#   OUT/libexec/secrethub-exec  native launcher
#   OUT/bin/{secrethub,secrethub-exec,git-credential-secrethub,docker-credential-secrethub}
#
#   scripts/host-keyring/build-local.sh [OUT]   (default: _build/host-keyring)
set -eu

root=$(cd "$(dirname "$0")/../.." && pwd)
out=${1:-$root/_build/host-keyring}
case "$out" in /*) ;; *) out=$(pwd)/$out ;; esac

mkdir -p "$out/libexec"

(cd "$root/apps/secrethub_cli" && MIX_ENV="${MIX_ENV:-prod}" mix escript.build)
install -m 0755 "$root/apps/secrethub_cli/secrethub" "$out/libexec/secrethub-cli"
rm -f "$root/apps/secrethub_cli/secrethub"

make -C "$root/native/secrethub-exec" >/dev/null
install -m 0755 "$root/native/secrethub-exec/secrethub-exec" "$out/libexec/secrethub-exec"

"$root/scripts/host-keyring/install-wrappers.sh" \
  "$out/libexec/secrethub-cli" "$out/libexec/secrethub-exec" "$out/bin"

echo "$out/bin"
