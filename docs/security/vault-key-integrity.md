# Vault key integrity and legacy recovery

## Persisted formats

Before this change, `vault_config` held an ID, `encrypted_master_key`, threshold,
total count, and timestamps. The stored blob used the shared AES-256-GCM layout
(version 1, 12-byte nonce, 16-byte tag, 32-byte ciphertext), but its random KDK
was discarded. The shares contained the data key itself. This stored blob cannot
validate a recovered legacy key. The old unique index on ID did not enforce a
singleton. Historical share wire versions 1–3 used arithmetic modulo 251;
coordinate 251 is zero and cannot participate in trusted recovery. Such a share
exposes the complete old data key, including v3 adjustment metadata. Recovery
rejects it even if otherwise well formed. A set containing that coordinate or
other disclosed old material requires an explicit compromise assessment: new
shares do not revoke old shares or cure historical ciphertext exposure. This
compatibility procedure preserves the old data key; rotating that key and
reencrypting old data is a separate operator-authorized procedure.

Existing secret and secret-version `encrypted_data` blobs use AES-256-GCM with
associated data `SecretHub-v1` and provide trusted verification evidence for
legacy recovery. Certificate `private_key_encrypted` blobs use the same layout
but historical PKI code also used a known development encryption key. Their
encryption-key provenance is unverified, so they are excluded even when the
private key matches its certificate. A certificate-only legacy Vault remains
blocked until independently trusted Vault ciphertext is available. The
migration never rewrites these blobs, IDs, or old Vault rows. It adds nullable
format/generation columns and a unique constant-expression index. Multiple old
Vault rows or invalid parameters cause migration failure, requiring operator
investigation; no row is selected, deleted, or reset automatically. Schema
downgrade refuses while any new envelope/generation metadata exists. Bare legacy
rows can be downgraded and upgraded without rewriting their key material.

## New Vault envelope

Initialization creates independent random 32-byte wrapping and data keys and a
random raw 16-byte generation. Only the wrapping key enters v4 Shamir shares via
`split/4`. The data key is encrypted with the wrapping key using AES-256-GCM.
`encrypted_master_key` contains exactly 61 bytes: version 1, random 12-byte nonce,
16-byte authentication tag, and 32-byte ciphertext. The durable columns are
`envelope_version=1`, `share_version=4`, and `share_set_id` (16 raw bytes).

Authenticated associated data is the exact concatenation of ASCII
`SecretHub-Vault`, envelope version byte 1, share version byte 4, a big-endian
unsigned 16-bit byte length for the canonical Vault UUID text, that text, the
16-byte generation, the threshold byte, and the total-share-count byte.
Changing any binding makes authentication fail. Share metadata is checked
against the durable row before collection; interpolation alone never unseals.
Malformed, duplicate, inconsistent, mixed-generation, or unauthenticated shares
clear partial progress and leave the Vault sealed, allowing a fresh correct
attempt. Errors contain no shares, reconstructed keys, or database diagnostics.

Creation uses a transaction and the database singleton invariant. Shares are
returned only after commit; failed or interrupted persistence returns no usable
share set. An interruption after commit but before the operator receives shares
can leave a committed, sealed Vault without available shares. This is an
operational recovery condition, never permission for automatic reinitialization.

## Availability and process behavior

The process starts `loading`; a successful read of no rows establishes
`not_initialized`. Connection failures, missing migrations, malformed rows, and
multiple rows establish `unavailable`, never an empty Vault. Initialization and
key access fail closed there. Retried successful reads recover to an empty or
sealed state, with no new ID or keys generated automatically. Once an identity
is known, missing or changed durable configuration remains unavailable; it is
never interpreted as permission to initialize. Key access and unseal recheck
the durable configuration and discard the active key on database failure.
Startup reads run in a supervised task with a bounded timeout, keeping loading
status responsive; timed-out tasks are cancelled. A durable legacy
row is sealed with `recovery_required=true`. The public status reports only
state, initialization/seal flags, progress, parameters, and recovery requirement.

Restart always requires manual unseal. `seal/0` remains an intentional no-op,
including after successful unseal. Stop Core to remove its active in-memory key;
this does not erase previously delivered Agent or application material. An
incident response must separately stop consumers, address caches, and revoke or
rotate issued credentials. The BEAM does not promise explicit zeroization of
immutable binaries; status and normal Inspect output redact key material.

## Controlled legacy recovery

Use the explicit local operator API
`SecretHub.Core.Vault.SealState.recover_legacy(encoded_shares, total, threshold)`.
It is available only for a sealed durable legacy row. Ordinary unseal and the v4
share decoder continue rejecting legacy shares. Do not put shares into a shell
command, command history, ordinary configuration, logs, or an image. Supply them
through a protected operator session from securely held material.

The quarantined recovery decoder accepts only canonical, bounded historical
wire versions 1–3 with exact 32-byte values, matching durable parameters, matching
version/mask, unique nonzero modulo-251 coordinates (1–250), field values below
251, and for v3 an exact binary 32-byte mask containing only 0 or 1. It requires
the durable threshold. Historical v1/v2 cannot recover byte values that the old
algorithm irreversibly reduced; authentication failure blocks recovery.

Within one transaction, recovery locks and rechecks the original Vault row,
authenticates the reconstructed old data key against preexisting persisted
ciphertext, and then replaces the legacy envelope and sharing parameters with
fresh wrapping material. It preserves the Vault ID, initialization time, and old
data key, so old secret and PKI ciphertext remains usable. Recovery returns new
v4 shares only after commit and leaves the Vault sealed for explicit unseal.
Concurrent recovery cannot overwrite an already recovered generation.

**Blocking condition:** no reliable preexisting authenticated ciphertext, wrong
legacy shares, unrecoverable historical values, or missing required schema means
recovery cannot establish ownership of the old key. Do not create a verifier from
that reconstruction, reset the database, or generate a replacement data key.
Restore verified backup/evidence and securely held shares, or have the operator
explicitly decide how disposable staging data should be recreated. Unknown or
production data is never treated as disposable.
