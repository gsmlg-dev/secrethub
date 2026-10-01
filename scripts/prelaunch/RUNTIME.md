# Isolated Agent lifecycle artifact checks

`runtime_acceptance.py` checks G11 against explicitly owned Core and Agent
containers. Both releases must already run outside the source checkout with the
selected immutable image IDs. Complete initial pending enrollment and operator
approval through the established workflow before invoking it. It does not
initialize a Vault or create another Agent identity.

Start with the private Core acceptance configuration and add:

```json
{
  "isolated_fixture": true,
  "agent_container": "secrethub-prelaunch-<unique-fixture>",
  "agent_image_id": "sha256:<exact-image-id>",
  "agent_hostname": "<that-container-hostname>"
}
```

The Agent state must live in a persistent bind mount. Use a real fixture host
key at the production host-key path with private service-UID access; do not use
development key generation. Core's configured runtime mTLS listener must use
the enrolled authority and remain separate from the protected management path.
Use `provisional: true` until source and both images are frozen.

```sh
python3 -B scripts/prelaunch/runtime_acceptance.py \
  --config /private/fixture/config.json \
  --shares-file /private/fixture/recovery-shares.private.json \
  --output /private/fixture/new-runtime-result-directory
```

The helper checks UID1002, finalized enrollment and real Core heartbeats. It
records certificate/private-key/CA digests and authorization floor, restarts
Agent and Core, requires a heartbeat later than each restart's completion,
manually unseals Core with independently held shares, and confirms the same
identity. Shares travel through stdin for separate release checks or protected
HTTP for serving unseal; they never become runtime configuration or arguments.

Damaged-state rejection uses a separate retained volume containing a copy of
the trusted state. Only the copied identity JSON is malformed. Redacted
preflight checks must show identity is the sole failing check, and normal
startup must reject it. The live identity remains untouched. Enrollment IDs are
queried independently of Agent association, so a new pending enrollment cannot
be hidden by a missing association. The baseline is taken before either restart
and checked after each restart and after the damaged-state check.

`runtime-report.json` contains metadata only and always has `complete: false`.
It qualifies G11's selected lifecycle scenario, not static reads, PKI delivery,
restore or the full launch plan. Raw diagnostics and recovery files must never
be exported with acceptance evidence. Retained damaged fixture volumes are
diagnostic copies, not an instruction to delete real identity or trust state.

`Dockerfile.consumer` packages the independent Python/OpenSSL static consumer
as UID1002, matching the owner-only Agent socket. Its pinned runtime and
immutable built image ID must be recorded in static-consumer acceptance. A
successful container build or `--help` does not establish authorized delivery.
