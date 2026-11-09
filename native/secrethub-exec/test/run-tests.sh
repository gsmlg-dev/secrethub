#!/bin/sh
# Integration tests for the built secrethub-exec binary.
# Usage: sh test/run-tests.sh ./secrethub-exec
set -u

BIN=${1:-./secrethub-exec}
case $BIN in /*) ;; *) BIN=$(pwd)/$BIN ;; esac
[ -x "$BIN" ] || { echo "binary not found: $BIN" >&2; exit 2; }

T=$(mktemp -d "${TMPDIR:-/tmp}/secrethub-exec-test.XXXXXX")
trap 'rm -rf "$T"' EXIT
export T

PASS=0
FAIL=0

ok() { PASS=$((PASS + 1)); echo "ok   - $1"; }
not_ok() { FAIL=$((FAIL + 1)); echo "FAIL - $1${2:+ ($2)}"; }

# check NAME EXPECTED ACTUAL
check() {
  if [ "$2" = "$3" ]; then ok "$1"; else not_ok "$1" "expected [$2] got [$3]"; fi
}

# resolver NAME BODY -> creates executable fake resolver script, prints its path
resolver() {
  f="$T/$1"
  printf '#!/bin/sh\n%s\n' "$2" > "$f"
  chmod +x "$f"
  echo "$f"
}

reset() { rm -f "$T/started" "$T/out" "$T/err" "$T/args" "$T/ppid" "$T/marker" "$T/rpid"; }

started() { [ -e "$T/started" ]; }

MARK_TARGET="touch \"\$T/started\""

# Run launcher in resolver mode; stdout -> $T/out, stderr -> $T/err; sets RC.
run_a() {
  "$BIN" "$@" > "$T/out" 2> "$T/err"
  RC=$?
}

# ---------------------------------------------------------------- Mode A

reset
SECRETHUB_CLI=$(resolver ok.sh 'echo "$*" > "$T/args"; printf "A=hello world\0B=line1\nline2\n\0C=\0"')
export SECRETHUB_CLI
unset A B C 2>/dev/null
run_a --map /m.json --socket /s.sock -- sh -c 'printf "[%s][%s][%s][%s]" "$A" "$B" "$C" "${C+set}"'
check "A: exit 0 on success" 0 "$RC"
# the trailing 'x' keeps command substitution from trimming newlines
check "A: exact values incl. spaces, newlines, empty" "[hello world][line1
line2
][][set]x" "$(cat "$T/out"; printf x)"
check "A: resolver argv" "__exec-resolve --map /m.json --socket /s.sock" "$(cat "$T/args")"

reset
run_a --map m -- printf '[%s]' 'a b' -- '*' '$HOME' ''
check "A: exact target argv, '--' and globs untouched" "[a b][--][*][\$HOME][]" "$(cat "$T/out")"

reset
OUT=$(echo "from-stdin" | "$BIN" --map m -- cat)
check "A: stdin passes through" "from-stdin" "$OUT"

reset
"$BIN" --map m -- sh -c 'exit 7' 2>/dev/null
check "A: target exit status propagated" 7 "$?"

reset
SECRETHUB_CLI=$(resolver ppid.sh 'echo "$PPID" > "$T/ppid"')
run_a --map m -- sh -c 'echo $$'
check "A: launcher replaced by target (same PID)" "$(cat "$T/ppid")" "$(cat "$T/out")"

reset
run_a --map m -- /nonexistent/target
check "A: missing target exits 127" 127 "$RC"

reset
printf '#!/bin/sh\n' > "$T/noexec"; chmod 0644 "$T/noexec"
run_a --map m -- "$T/noexec"
check "A: non-executable target exits 126" 126 "$RC"

reset
SECRETHUB_CLI=$(resolver fail.sh 'printf "A=1\0"; echo "resolver diag" >&2; exit 3')
run_a --map m -- sh -c "$MARK_TARGET"
check "A: resolver failure exits 1" 1 "$RC"
if started; then not_ok "A: resolver failure does not start target"; else ok "A: resolver failure does not start target"; fi
if grep -q "resolver diag" "$T/err"; then ok "A: resolver stderr inherited"; else not_ok "A: resolver stderr inherited"; fi

reset
SECRETHUB_CLI=$(resolver killed.sh 'kill -KILL $$')
run_a --map m -- sh -c "$MARK_TARGET"
check "A: resolver killed by signal exits 1" 1 "$RC"

malformed() {
  reset
  SECRETHUB_CLI=$(resolver "bad-$1.sh" "$2")
  run_a --map m -- sh -c "$MARK_TARGET"
  if [ "$RC" -eq 1 ] && ! started; then ok "A: rejects $1"; else not_ok "A: rejects $1" "rc=$RC"; fi
}
unset A B 2>/dev/null
malformed "missing trailing NUL" 'printf "A=1\0B=2"'
malformed "record without =" 'printf "ABC\0"'
malformed "name starting with digit" 'printf "1A=x\0"'
malformed "empty name" 'printf "=x\0"'
malformed "name with dash" 'printf "A-B=x\0"'
malformed "duplicate name" 'printf "A=1\0A=2\0"'
N255=$(printf '%255s' '' | tr ' ' N)
malformed "name longer than 255" "printf '${N255}N=x\\0'"
malformed "output over 1 MiB" 'head -c 1048577 /dev/zero | tr "\0" "a"'

reset
SECRETHUB_CLI=$(resolver long.sh "printf '${N255}=ok\\0'")
run_a --map m -- sh -c 'echo started'
check "A: accepts 255-char name" "0 started" "$RC $(cat "$T/out")"

reset
SECRETHUB_CLI=$(resolver none.sh 'exit 0')
run_a --map m -- sh -c 'echo none'
check "A: zero records is fine" "0 none" "$RC $(cat "$T/out")"

reset
SECRETHUB_CLI=$(resolver coll.sh 'printf "EXISTING=new\0"')
EXISTING=orig run_a --map m -- sh -c "$MARK_TARGET"
if [ "$RC" -eq 1 ] && ! started; then ok "A: refuses inherited env collision"; else not_ok "A: refuses inherited env collision" "rc=$RC"; fi
reset
EXISTING=orig "$BIN" --map m --replace-env -- sh -c 'printf %s "$EXISTING"' > "$T/out"
check "A: --replace-env replaces inherited var" "new" "$(cat "$T/out")"
if grep -q "new" "$T/err" 2>/dev/null; then not_ok "A: value not printed on stderr"; else ok "A: value not printed on stderr"; fi

reset
(unset SECRETHUB_CLI; "$BIN" --map m -- true 2>/dev/null); check "A: missing SECRETHUB_CLI exits 2" 2 "$?"
(SECRETHUB_CLI= "$BIN" --map m -- true 2>/dev/null); check "A: empty SECRETHUB_CLI exits 2" 2 "$?"

# Signal during resolution
signal_test() {
  sig=$1; expect=$2
  reset
  SECRETHUB_CLI=$(resolver sig.sh '
echo $$ > "$T/rpid.tmp"; mv "$T/rpid.tmp" "$T/rpid"
trap "echo got > \"\$T/marker\"; kill \$sp 2>/dev/null; exit 3" TERM INT HUP QUIT
sleep 30 & sp=$!
wait $sp')
  # Background jobs of a non-interactive shell start with SIGINT/SIGQUIT
  # ignored; restore defaults so those signals reach the launcher.
  $RESET_SIGNALS "$BIN" --map m -- sh -c "$MARK_TARGET" 2>/dev/null &
  lpid=$!
  n=0
  while [ ! -s "$T/rpid" ] && [ $n -lt 100 ]; do sleep 0.05 2>/dev/null || sleep 1; n=$((n + 1)); done
  rpid=$(cat "$T/rpid" 2>/dev/null)
  kill -"$sig" "$lpid"
  wait "$lpid"
  rc=$?
  check "A: SIG$sig -> launcher dies by same signal" "$expect" "$rc"
  check "A: SIG$sig forwarded to resolver" "got" "$(cat "$T/marker" 2>/dev/null)"
  if [ -n "$rpid" ] && kill -0 "$rpid" 2>/dev/null; then
    not_ok "A: SIG$sig no orphan resolver"; kill -KILL "$rpid" 2>/dev/null
  else ok "A: SIG$sig no orphan resolver"; fi
  if started; then not_ok "A: SIG$sig target not started"; else ok "A: SIG$sig target not started"; fi
}
RESET_SIGNALS=
if env --default-signal=INT,QUIT true 2>/dev/null; then
  RESET_SIGNALS="env --default-signal=INT,QUIT"
fi
signal_test TERM 143
signal_test HUP 129
if [ -n "$RESET_SIGNALS" ]; then
  signal_test INT 130
  signal_test QUIT 131
else
  echo "# skip: SIGINT/SIGQUIT forwarding needs env --default-signal"
fi

# ---------------------------------------------------------------- Mode B

CD="$T/creds"
mkdir -p "$CD"
printf 'secret value\n' > "$CD/db.password"
printf 'line1\nline2' > "$CD/multi"
printf 'tls' > "$CD/tls_key"
: > "$CD/empty"
printf 'a\000b' > "$CD/nul"
ln -s "$CD/tls_key" "$CD/link"
mkdir "$CD/subdir"
unset SECRETHUB_CLI DB_PASSWORD MULTI 2>/dev/null

run_b() {
  CREDENTIALS_DIRECTORY=$CD "$BIN" "$@" > "$T/out" 2> "$T/err"
  RC=$?
}

reset
run_b --credential db.password=DB_PASSWORD --credential multi=MULTI --credential tls_key -- \
  sh -c 'printf "[%s][%s]x" "$DB_PASSWORD" "$MULTI"; [ -z "${tls_key+set}" ] && printf N'
check "B: exports exact bytes (trailing newline kept)" "[secret value
][line1
line2]xN" "$(cat "$T/out")"
check "B: exit 0" 0 "$RC"

reset
run_b --credential tls_key -- sh -c 'printf %s "$CREDENTIALS_DIRECTORY"'
check "B: validate-only credential" "0 $CD" "$RC $(cat "$T/out")"

reset
run_b --credential db.password=DB_PASSWORD -- sh -c 'exit 9'
check "B: target exit status propagated" 9 "$RC"

refuse_b() {
  label=$1; shift
  reset
  run_b "$@" -- sh -c "$MARK_TARGET"
  if [ "$RC" -eq 1 ] && ! started; then ok "B: refuses $label"; else not_ok "B: refuses $label" "rc=$RC"; fi
}
refuse_b "missing file" --credential missing
refuse_b "empty file" --credential empty
refuse_b "empty file (exported)" --credential empty=EMPTY
refuse_b "NUL content for env" --credential nul=NULVAR
refuse_b "symlink" --credential link
refuse_b "directory" --credential subdir
refuse_b "duplicate ENVVAR" --credential tls_key=X --credential multi=X
head -c 1048577 /dev/zero | tr '\0' 'a' > "$CD/big"
refuse_b "file over 1 MiB" --credential big

reset
run_b --credential nul -- sh -c 'echo fine'
check "B: NUL content allowed for validate-only" "0 fine" "$RC $(cat "$T/out")"

reset
MULTI=orig run_b --credential multi=MULTI -- sh -c "$MARK_TARGET"
if [ "$RC" -eq 1 ] && ! started; then ok "B: refuses inherited env collision"; else not_ok "B: refuses inherited env collision" "rc=$RC"; fi
reset
MULTI=orig run_b --replace-env --credential multi=MULTI -- sh -c 'printf %s "$MULTI"'
check "B: --replace-env replaces inherited var" "line1
line2" "$(cat "$T/out")"

reset
run_b --credential missing -- true
if grep -q "missing" "$T/err"; then ok "B: error names the credential"; else not_ok "B: error names the credential"; fi
run_b --credential db.password=X --credential missing -- true
if grep -q "secret value" "$T/err"; then not_ok "B: value never printed"; else ok "B: value never printed"; fi

reset
(unset CREDENTIALS_DIRECTORY; "$BIN" --credential tls_key -- sh -c "$MARK_TARGET" 2>/dev/null)
rc=$?
if [ "$rc" -eq 1 ] && ! started; then ok "B: missing CREDENTIALS_DIRECTORY refused"; else not_ok "B: missing CREDENTIALS_DIRECTORY refused" "rc=$rc"; fi
(CREDENTIALS_DIRECTORY=relative/dir "$BIN" --credential tls_key -- true 2>/dev/null)
check "B: relative CREDENTIALS_DIRECTORY refused" 1 "$?"

for bad in .. . ../creds/tls_key sub/x '' 'a b' 'x=1BAD' 'x='; do
  reset
  run_b --credential "$bad" -- sh -c "$MARK_TARGET"
  if [ "$RC" -eq 2 ] && ! started; then ok "B: invalid spec '$bad' refused"; else not_ok "B: invalid spec '$bad' refused" "rc=$RC"; fi
done

reset
SECRETHUB_CLI=$(resolver never.sh 'touch "$T/marker"; printf "A=1\0"')
CREDENTIALS_DIRECTORY=$CD SECRETHUB_CLI=$SECRETHUB_CLI "$BIN" --credential tls_key -- true
if [ -e "$T/marker" ]; then not_ok "B: never runs resolver"; else ok "B: never runs resolver"; fi
unset SECRETHUB_CLI

# ---------------------------------------------------------------- usage

usage_case() {
  label=$1; shift
  SECRETHUB_CLI=/bin/true CREDENTIALS_DIRECTORY=$CD "$BIN" "$@" > /dev/null 2> "$T/err"
  rc=$?
  lines=$(wc -l < "$T/err" | tr -d ' ')
  check "usage: $label exits 2 with one-line message" "2 1" "$rc $lines"
}
usage_case "no arguments"
usage_case "no --" --map m true
usage_case "no target" --map m --
usage_case "unknown option" --bogus --map m -- true
usage_case "missing option value" --map -- true
usage_case "neither --map nor --credential" -- true
usage_case "--replace-env only" --replace-env -- true
usage_case "--map with --credential" --map m --credential tls_key -- true
usage_case "--socket with --credential" --socket s --credential tls_key -- true
usage_case "--socket without --map" --socket s -- true
usage_case "--map twice" --map a --map b -- true

echo "# passed: $PASS, failed: $FAIL"
[ "$FAIL" -eq 0 ]
