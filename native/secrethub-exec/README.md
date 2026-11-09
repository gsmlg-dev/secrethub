# secrethub-exec

Native launcher behind `secrethub exec`. It puts resolved credentials into the
environment, then **replaces itself** with the target via `execvp` (same PID,
no shell). The target keeps stdin/stdout/stderr, the terminal, the cwd, its
exit status and its signals. Credential values and the constructed environment
are never printed.

Contract: `docs/subsystem/host-keyring.md` (sections "`secrethub exec`" and
"systemd services").

## Build

```sh
make                      # cc -O2 -std=c99 -Wall -Wextra -Werror
make test                 # runs test/run-tests.sh against the built binary
make install PREFIX=/usr DESTDIR=/tmp/pkg   # installs $(DESTDIR)$(PREFIX)/bin/secrethub-exec
```

Portable POSIX C (Linux, macOS), no third-party dependencies.

## Resolver mode

```sh
SECRETHUB_CLI=/path/to/secrethub \
  secrethub-exec --map MAP.json [--socket PATH] [--replace-env] -- TARGET [ARGS...]
```

- Runs `$SECRETHUB_CLI __exec-resolve --map MAP.json [--socket PATH]` with
  stdin from `/dev/null`, stdout to a private pipe and stderr inherited. On
  Linux the resolver gets `PR_SET_PDEATHSIG=SIGTERM`.
- Reads `NAME=VALUE\0` records (at most 1 MiB). `NAME` must match
  `[A-Za-z_][A-Za-z0-9_]*` (max 255 chars); `VALUE` is kept byte-exact and may
  be empty.
- Refuses to start the target (exit 1) if the resolver exits non-zero or is
  killed, output exceeds 1 MiB, a record is unterminated / lacks `=` / has an
  invalid name, a name is duplicated, or a name already exists in the
  inherited environment (unless `--replace-env`).
- SIGINT/SIGTERM/SIGHUP/SIGQUIT received while resolving are forwarded to the
  resolver. After the resolver is reaped, the launcher dies by that same signal
  and the target never starts. Signals that were ignored when the launcher
  started stay ignored and are not forwarded.

## systemd credentials-directory mode

```sh
secrethub-exec --credential NAME[=ENVVAR] [--credential ...] [--replace-env] -- TARGET [ARGS...]
```

- Requires an absolute `$CREDENTIALS_DIRECTORY`. Never runs the resolver.
- `NAME` matches `[A-Za-z0-9_.-]{1,255}` and is not `.` or `..`.
- Each `$CREDENTIALS_DIRECTORY/NAME` must be a regular file (symlinks are
  refused), non-empty and at most 1 MiB. An empty credential means the
  `LoadCredential=` provider failed, so the target does not start.
- With `=ENVVAR`, the exact file bytes (trailing newline included) are exported
  as `ENVVAR`. Content containing NUL, a duplicate `ENVVAR` or an inherited
  `ENVVAR` (without `--replace-env`) is refused. Without `=ENVVAR` the file is
  only validated.

## Exit codes

| Code | Meaning |
|------|---------|
| target's | the target ran (the launcher was replaced by it) |
| 1 | credential resolution or validation failed; target not started |
| 2 | usage error (one-line message on stderr) |
| 126 | target found but not executable (`EACCES`) |
| 127 | target could not be executed |
| 128+N | killed by forwarded signal N during resolution |
