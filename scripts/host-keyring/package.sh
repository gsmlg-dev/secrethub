#!/bin/sh
# Packages host keyring tools as a relocatable release archive:
#
#   scripts/host-keyring/package.sh VERSION TARGET [OUT_DIR]
#
# Produces OUT_DIR/secrethub-host-tools-VERSION-TARGET.tar.gz containing
#   libexec/secrethub-cli   the CLI escript (needs Erlang/OTP `escript` on PATH)
#   libexec/secrethub-exec  the native launcher (built and tested on this host)
#   install.sh              writes the secrethub, secrethub-exec, Git and Docker
#                           helper wrappers with absolute paths into a bin dir
set -eu

if [ "$#" -lt 2 ]; then
  echo "usage: $0 VERSION TARGET [OUT_DIR]" >&2
  exit 2
fi

version=$1
target=$2
root=$(cd "$(dirname "$0")/../.." && pwd)
out=${3:-$root/_build/host-keyring-dist}
case "$out" in /*) ;; *) out=$(pwd)/$out ;; esac

name="secrethub-host-tools-$version-$target"
stage="$out/$name"
rm -rf "$stage"
mkdir -p "$stage/libexec"

(cd "$root/apps/secrethub_cli" && MIX_ENV="${MIX_ENV:-prod}" mix escript.build)
install -m 0755 "$root/apps/secrethub_cli/secrethub" "$stage/libexec/secrethub-cli"
rm -f "$root/apps/secrethub_cli/secrethub"

make -C "$root/native/secrethub-exec" clean all test
install -m 0755 "$root/native/secrethub-exec/secrethub-exec" "$stage/libexec/secrethub-exec"
install -m 0755 "$root/scripts/host-keyring/install-wrappers.sh" "$stage/install-wrappers.sh"

cat > "$stage/install.sh" <<'EOF'
#!/bin/sh
# Installs wrappers for this extracted directory: ./install.sh [BIN_DIR]
# (default: ./bin). Keep this directory in place; wrappers reference it.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
exec "$here/install-wrappers.sh" "$here/libexec/secrethub-cli" "$here/libexec/secrethub-exec" "${1:-$here/bin}"
EOF
chmod 0755 "$stage/install.sh"

tar -C "$out" -czf "$out/$name.tar.gz" "$name"
rm -rf "$stage"
echo "$out/$name.tar.gz"
