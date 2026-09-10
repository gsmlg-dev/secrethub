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
2. **Immutable Pre-Repair Backup & Resumption Safety**: When `TrustBundleManager.bind_identity/2` is invoked, `AtomicStore.repair_outbox_metadata/3` is executed. Before modifying the active outbox, it durably creates an immutable, content-addressed backup file:
   ```
   <state_dir>/pki/client-auth/observation_sequence.json.bak-<content_sha256>
   ```
   - Backups are created exclusively (`:exclusive` flag) to guarantee existing files are never overwritten.
   - Symlinks and directories occupying the backup path are strictly rejected without being followed.
   - Backup file contents and directory entries are synchronized (`fsync`) to disk before active state is modified.
   - **Resumption & Replay Safety**: If a prior repair attempt was interrupted after backup creation (e.g. system crash or I/O error during active outbox replacement), retrying repair (even after a process restart) safely validates and reuses the existing byte-identical content-addressed backup file. Mismatching or truncated backups remain an error.
3. **Safe In-Place Repair**:
   - Backfills missing or empty `agent_id` with the local enrolled identity.
   - Backfills missing timestamps with the original enqueue timestamp.
   - **Preserves all observation sequences, the persistent high-water counter, CA pins, and CRL watermarks without reset.**
   - Strictly refuses to overwrite any existing non-empty `agent_id` that differs from the verified enrolled identity.
4. **Scoped Unquarantine & Trust Isolation**: Once the repaired outbox passes strict schema validation, `TrustBundleManager` clears only the outbox-related restriction (`outbox_restriction: nil`).
   - If no trust-level restriction is active, the quarantine is lifted (`recovery_mode: :none`), active status is restored, and outbox draining resumes.
   - If the manager is under an independent trust quarantine (e.g. corrupt watermark or conflicting bundle evidence), trust quarantine **remains strictly enforced** (`recovery_mode: :quarantined`, `status: "recovery_required"`).
5. **Authorized Trust Recovery Transitions**: When an operator authorizes recovery (`process_bundle/3` with `force: true`):
   - Upon durable commitment of validated trust material to disk, the resolved `trust_recovery_restriction` is cleared.
   - Any independently unresolved outbox restriction is preserved.
   - Manager `recovery_mode` and `status` are derived consistently: if all restrictions are resolved, `recovery_mode` transitions to `:none` and `status` to `"applied"`, allowing subsequent updates without `force: true`. Rebinding identity does not re-quarantine the manager.

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
# Returns :ok on complete success, or {:error, {:repair_failed, reason}} if outbox repair fails.
case SecretHub.Agent.PKI.TrustBundleManager.bind_identity("agent-your-enrolled-id") do
  :ok ->
    IO.puts("Identity bound and outbox repaired successfully.")

  {:error, {:repair_failed, reason}} ->
    IO.puts("Identity bound, but outbox repair failed: #{inspect(reason)}")

  {:error, {:identity_mismatch, current, proposed}} ->
    IO.puts("Identity mismatch: manager already bound to #{current}")
end

# Verify manager status:
SecretHub.Agent.PKI.TrustBundleManager.status()
```

### Step 4: Verify Backup
Verify that the pre-repair backup was preserved:
```bash
ls -l ~/.local/state/secrethub/agent/pki/client-auth/observation_sequence.json.bak-*
```

---

## 4. Conflicting Identity Resolution

If `observation_sequence.json` contains a non-empty `agent_id` that disagrees with the enrolled `IdentityStore` (`{:conflicting_outbox_identity, existing_id, target_id}`):
- Automatic repair halts and retains the quarantine to prevent emitting falsified receipts under a different identity.
- The operator must verify whether the agent host was re-enrolled with a new identity before old receipts were acknowledged.
- In that scenario, compare the client certificate serial in `agent-cert.pem` against Core records. After audit review, remove or archive `observation_sequence.json` to begin clean receipt tracking under the new identity.

---

## 5. Partial-Failure & Backup Guarantees

If backup creation fails for any reason (e.g. backup path occupied by an unexpected directory, existing backup file collision, symlink detected, or disk I/O error):
1. **Zero State Mutation**: Active outbox bytes, observation sequences, watermarks, and CA pins are never modified.
2. **Error Propagation**: `repair_outbox_metadata/3` returns `{:error, {:backup_failed, reason}}`.
3. **Caller Visibility**: `TrustBundleManager.bind_identity/2` returns `{:error, {:repair_failed, {:backup_failed, reason}}}` rather than reporting unqualified success.
4. **Evidence Preservation**: Prior forensic evidence is never overwritten. All historical backup files remain immutable.
