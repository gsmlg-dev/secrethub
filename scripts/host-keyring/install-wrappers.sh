#!/bin/sh
# Writes the installed host keyring entry points into BIN_DIR.
#
#   install-wrappers.sh CLI_ESCRIPT EXEC_LAUNCHER BIN_DIR
#
# CLI_ESCRIPT is the built `secrethub` escript and EXEC_LAUNCHER the native
# `secrethub-exec` binary; both are referenced by absolute path. The wrappers
# preserve arguments and stdin exactly and only select the internal entry point.
# `secrethub exec` is routed to the native launcher so the target replaces the
# process (execve) instead of running beneath the BEAM.
set -eu

if [ "$#" -ne 3 ]; then
  echo "usage: $0 CLI_ESCRIPT EXEC_LAUNCHER BIN_DIR" >&2
  exit 2
fi

cli=$1
launcher=$2
bin=$3

case "$cli" in /*) ;; *) echo "CLI_ESCRIPT must be absolute" >&2; exit 2 ;; esac
case "$launcher" in /*) ;; *) echo "EXEC_LAUNCHER must be absolute" >&2; exit 2 ;; esac

mkdir -p "$bin"

# Minimal environments (systemd units, `env -i`) default the BEAM to latin1
# filename encoding; keep any caller-provided options.
erl_options='ERL_FLAGS="+fnu ${ERL_FLAGS-}"; export ERL_FLAGS'

write() {
  target="$bin/$1"
  tmp="$target.tmp.$$"
  cat > "$tmp"
  chmod 0755 "$tmp"
  mv -f "$tmp" "$target"
}

write secrethub <<EOF
#!/bin/sh
$erl_options
if [ "\${1-}" = exec ]; then
  shift
  SECRETHUB_CLI='$cli'
  export SECRETHUB_CLI
  exec '$launcher' "\$@"
fi
exec '$cli' "\$@"
EOF

write secrethub-exec <<EOF
#!/bin/sh
$erl_options
SECRETHUB_CLI='$cli'
export SECRETHUB_CLI
exec '$launcher' "\$@"
EOF

write git-credential-secrethub <<EOF
#!/bin/sh
$erl_options
exec '$cli' __git-credential "\$@"
EOF

write docker-credential-secrethub <<EOF
#!/bin/sh
$erl_options
exec '$cli' __docker-credential "\$@"
EOF
