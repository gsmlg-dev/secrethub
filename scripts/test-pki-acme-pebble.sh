#!/usr/bin/env bash
set -euo pipefail
# Local-only ACME qualification; no public CA, real DNS provider or production keys.
project_root=$(cd "$(dirname "$0")/.." && pwd)
qualification_dir=$(mktemp -d /tmp/secrethub-pebble.XXXXXX)
pebble_pid=''
dns_pid=''
authoritative_dns_pid=''
cleanup() {
  if [[ -n "$pebble_pid" ]]; then kill "$pebble_pid" 2>/dev/null || true; wait "$pebble_pid" 2>/dev/null || true; fi
  if [[ -n "$authoritative_dns_pid" ]]; then kill "$authoritative_dns_pid" 2>/dev/null || true; wait "$authoritative_dns_pid" 2>/dev/null || true; fi
  if [[ -n "$dns_pid" ]]; then kill "$dns_pid" 2>/dev/null || true; wait "$dns_pid" 2>/dev/null || true; fi
  rm -rf "$qualification_dir"
}
trap cleanup EXIT INT TERM
export SECRETHUB_PEBBLE_DIRECTORY=https://localhost:24000/dir
export SECRETHUB_PEBBLE_MANAGEMENT=https://localhost:25000
export SECRETHUB_PEBBLE_DNS_API=http://127.0.0.1:28055
export SECRETHUB_PEBBLE_DNS_PORT=28054
export SECRETHUB_PEBBLE_TLS_CERT="$qualification_dir/tls.pem"
pebble_tools=${SECRETHUB_PEBBLE_TOOLS:-$qualification_dir/tools}
if [[ ! -x "$pebble_tools/pebble" || ! -x "$pebble_tools/pebble-challtestsrv" ]]; then
  GOBIN="$pebble_tools" go install github.com/letsencrypt/pebble/v2/cmd/pebble@v2.10.1
  GOBIN="$pebble_tools" go install github.com/letsencrypt/pebble/v2/cmd/pebble-challtestsrv@v2.10.1
fi
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=SecretHub Pebble test TLS root' \
  -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout "$qualification_dir/root.key" -out "$SECRETHUB_PEBBLE_TLS_CERT" 2>"$qualification_dir/openssl.log"
openssl req -new -newkey rsa:2048 -nodes -subj /CN=localhost \
  -keyout "$qualification_dir/tls.key" -out "$qualification_dir/tls.csr" 2>>"$qualification_dir/openssl.log"
cat > "$qualification_dir/server.ext" <<'EXT'
subjectAltName=DNS:localhost,IP:127.0.0.1
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EXT
openssl x509 -req -in "$qualification_dir/tls.csr" -CA "$SECRETHUB_PEBBLE_TLS_CERT" \
  -CAkey "$qualification_dir/root.key" -CAcreateserial -days 1 -extfile "$qualification_dir/server.ext" \
  -out "$qualification_dir/server.pem" 2>>"$qualification_dir/openssl.log"
cat > "$qualification_dir/pebble.json" <<JSON
{"pebble":{"listenAddress":"127.0.0.1:24000","managementListenAddress":"127.0.0.1:25000","certificate":"$qualification_dir/server.pem","privateKey":"$qualification_dir/tls.key","httpPort":25002,"tlsPort":25001,"externalAccountBindingRequired":false,"retryAfter":{"authz":1,"order":1},"keyAlgorithm":"ecdsa","profiles":{"default":{"description":"isolated 6-day qualification","validityPeriod":518400}}}}
JSON
"$pebble_tools/pebble-challtestsrv" -dnsserver 127.0.0.1:28053 -management 127.0.0.1:28055 -http01 '' -https01 '' -tlsalpn01 '' -doh '' >"$qualification_dir/dns.log" 2>&1 &
dns_pid=$!
python3 "$project_root/scripts/pki_acme_authoritative_dns.py" --listen-port 28054 --upstream-port 28053 >"$qualification_dir/authoritative-dns.log" 2>&1 &
authoritative_dns_pid=$!
PEBBLE_VA_NOSLEEP=1 PEBBLE_WFE_NONCEREJECT=10 PEBBLE_AUTHZREUSE=0 \
  "$pebble_tools/pebble" -config "$qualification_dir/pebble.json" -dnsserver 127.0.0.1:28054 >"$qualification_dir/pebble.log" 2>&1 &
pebble_pid=$!
for attempt in $(seq 1 100); do
  if curl --silent --fail --max-time 1 --cacert "$SECRETHUB_PEBBLE_TLS_CERT" "$SECRETHUB_PEBBLE_DIRECTORY" >/dev/null; then break; fi
  if ! kill -0 "$pebble_pid" 2>/dev/null || ! kill -0 "$dns_pid" 2>/dev/null || ! kill -0 "$authoritative_dns_pid" 2>/dev/null; then
    cat "$qualification_dir/pebble.log" "$qualification_dir/dns.log" "$qualification_dir/authoritative-dns.log"
    exit 1
  fi
  sleep 0.1
done
cd "$project_root"
MIX_ENV=test mix run --no-start "${SECRETHUB_PEBBLE_RUN_SCRIPT:-scripts/test-pki-acme-protocol.exs}"
