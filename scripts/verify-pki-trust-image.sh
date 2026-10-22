#!/usr/bin/env bash
# Inspect immutable published bytes without starting Core, Vault, or PostgreSQL.
set -euo pipefail

image="${1:?Usage: verify-pki-trust-image.sh IMAGE@sha256:DIGEST TAG COMMIT}"
tag="${2:?Release tag is required}"
revision="${3:?Release commit is required}"
if [[ ! "$image" =~ ^ghcr.io/[^/]+/[^/]+/(core|core-standalone)@sha256:[0-9a-f]{64}$ ]] ||
   [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] ||
   [[ ! "$revision" =~ ^[0-9a-f]{40}$ ]]; then
  echo "Expected an immutable Core GHCR reference, release tag, and full commit SHA" >&2
  exit 1
fi
repository="${image#ghcr.io/}"
repository="${repository%/*}"
probe="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/verify-pki-trust-release.exs"
qualification_dir="$(mktemp -d)"
container="secrethub-trust-qualification-$(openssl rand -hex 8)"
cleanup() {
  timeout --kill-after=10s 30s docker rm --force "$container" >/dev/null 2>&1 || true
  rm -rf "$qualification_dir"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

timeout --kill-after=10s 900s docker pull --platform linux/amd64 "$image"
timeout --kill-after=10s 30s docker image inspect "$image" > "$qualification_dir/image.json"
python3 - "$qualification_dir/image.json" "$tag" "$revision" "$repository" <<'PY'
import json, sys
with open(sys.argv[1]) as file:
    image, = json.load(file)
assert image["Architecture"] == "amd64" and image["Os"] == "linux", "Unexpected image platform"
labels = image["Config"]["Labels"]
for key, value in {
    "org.opencontainers.image.version": sys.argv[2],
    "org.opencontainers.image.revision": sys.argv[3],
    "org.opencontainers.image.source": "https://github.com/" + sys.argv[4],
}.items():
    assert labels.get(key) == value, "Image label mismatch: " + key
PY

# Qualification-only keys satisfy runtime configuration before eval; no service starts.
export SECRET_KEY_BASE="$(openssl rand -base64 64 | tr -d '\n')"
export AUDIT_HMAC_KEY="$(openssl rand -base64 32)"
args=(run --rm --name "$container" --platform linux/amd64 --network=none --read-only
  --cap-drop=ALL --security-opt=no-new-privileges --no-healthcheck
  --tmpfs /app/tmp:rw,noexec,nosuid,size=32m,mode=1777
  --mount "type=bind,src=$probe,dst=/qualification/probe.exs,readonly"
  --entrypoint /app/bin/secrethub_core
  --env SECRET_KEY_BASE --env AUDIT_HMAC_KEY
  --env SECRETHUB_ROLE=core --env HUMAN_ENABLED=false --env RELEASE_DISTRIBUTION=none
  --env 'ERL_FLAGS=+S 4:4' --env RELEASE_TMP=/app/tmp --env TMPDIR=/app/tmp
  --env PHX_SERVER=false --env DATABASE_URL=postgresql://offline:offline@127.0.0.1:1/offline
  --env AUDIT_HMAC_KEY_ID=offline-trust-qualification
  --env SECRET_HUB_CLUSTER_NODE_ID=offline-trust-qualification
  --env SECRET_HUB_MANAGEMENT_ORIGIN=https://localhost
  --env SECRET_HUB_AGENT_ENDPOINT_SERVER=false --env SECRET_HUB_ADMIN_ENDPOINT_SERVER=false)
if [[ "$image" == */core-standalone@* ]]; then
  # Override the declared data volume as well as the database-starting entrypoint.
  args+=(--tmpfs /data:ro,noexec,nosuid,size=1m)
fi
timeout --kill-after=10s 180s docker "${args[@]}" "$image" eval 'Code.eval_file("/qualification/probe.exs")' \
  > "$qualification_dir/probe.log"
cat "$qualification_dir/probe.log"
python3 - "$qualification_dir/probe.log" "${tag#v}" <<'PY'
import json, sys
with open(sys.argv[1]) as file:
    results = [json.loads(line) for line in file if line.startswith("{")]
assert len(results) == 1, "Missing unique trust qualification result"
result, = results
assert result["result"] == "PASS", "Trust qualification failed"
assert result["services_started"] is False, "Qualification started services"
assert result["release"] == sys.argv[2], "Packaged release version mismatch"
PY
