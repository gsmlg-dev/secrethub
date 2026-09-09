# Client Auth PKI: Receipt Outbox Recovery Guide

This guide documents the recovery procedure for SecretHub Agent installations affected by the receipt outbox identity issue in early versions of PR #8.

---

## 1. Issue Overview

In affected agent versions, `TrustBundleManager` was started without the enrolled `agent_id`, resulting in newly enqueued receipts having `"agent_id": nil`. On subsequent outbox reads or agent restarts, `AtomicStore.read_outbox/1` rejected the malformed entries with:

```elixir
{:corrupted_outbox, {:missing_receipt_field, "agent_id", sequence}}
```

This placed `TrustBundleManager` into `recovery_mode: :quarantined`, which blocked ordinary CRL and trust bundle updates.

---

## 2. Automatic Recovery

The fixed version handles recovery automatically upon startup:

1. **Identity Source of Truth**: On startup or upon completion of enrollment, `TrustBundleManager` resolves the verified enrolled Agent identity from `IdentityStore.load(state_dir)` and `RuntimeBootstrapper`.
2. **Atomic Pre-Repair Backup**: When `TrustBundleManager.bind_identity/2` is invoked, `AtomicStore.repair_outbox_metadata/2` is executed. Before modifying the outbox, it backs up the original file to:
   ```
   <state_dir>/pki/client-auth/observation_sequence.json.pre_repair_bak
   ```
3. **Safe In-Place Repair**:
   - Backfills missing or empty `agent_id` with the local enrolled identity.
   - Backfills missing timestamps with the original enqueue timestamp.
   - **Preserves all observation sequences, the persistent high-water counter, CA pins, and CRL watermarks without reset.**
   - Strictly refuses to overwrite any existing non-empty `agent_id` that differs from the verified enrolled identity.
4. **Automatic Unquarantine**: Once the repaired outbox passes strict schema validation, `TrustBundleManager` automatically clears the quarantine (`recovery_mode: :none`), restores active status, and resumes draining the outbox to Core.

---

## 3. Manual Verification & Recovery Procedure

If an operator wants to inspect or manually trigger recovery for an affected agent:

### Step 1: Inspect Current Outbox State
```bash
# Default path:
cat ~/.local/state/secrethub/agent/pki/client-auth/observation_sequence.json | jq .
```

Look for any entries under `"outbox"` where `"agent_id"` is `null` or `""`:
```json
{
  "observation_sequence": 1,
  "outbox": [
    {
      "sequence": 1,
      "receipt": {
        "agent_id": null,
        "observation_sequence": 1,
        "status": "applied"
      }
    }
  ]
}
```

### Step 2: Confirm Verified Identity in IdentityStore
Verify that local identity material exists and contains the enrolled `agent_id`:
```bash
cat ~/.local/state/secrethub/agent/identity.json | jq .agent_id
```

### Step 3: Trigger Repair in IEx Shell (Optional)
If running inside an interactive shell (`iex -S mix` or `bin/secrethub_agent remote_console`):
```elixir
# Check current manager status:
SecretHub.Agent.PKI.TrustBundleManager.status()

# Manually trigger binding & repair with verified enrolled identity:
SecretHub.Agent.PKI.TrustBundleManager.bind_identity("agent-your-enrolled-id")

# Verify recovery mode is cleared:
SecretHub.Agent.PKI.TrustBundleManager.status()
# => %{recovery_mode: :none, status: "applied", ...}
```

### Step 4: Verify Backup
Verify that the pre-repair backup was preserved:
```bash
ls -l ~/.local/state/secrethub/agent/pki/client-auth/observation_sequence.json.pre_repair_bak
```

---

## 4. Conflicting Identity Resolution

If `observation_sequence.json` contains a non-empty `agent_id` that disagrees with the enrolled `IdentityStore` (`{:conflicting_outbox_identity, existing_id, target_id}`):
- Automatic repair halts and retains the quarantine to prevent emitting falsified receipts under a different identity.
- The operator must verify whether the agent host was re-enrolled with a new identity before old receipts were acknowledged.
- In that scenario, compare the client certificate serial in `agent-cert.pem` against Core records. After audit review, remove or archive `observation_sequence.json` to begin clean receipt tracking under the new identity.
