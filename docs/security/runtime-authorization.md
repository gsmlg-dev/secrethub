# Static runtime authorization and cutover

Application reads derive Agent identity from the authenticated Core-Agent socket,
and derive application identity from the canonical certificate association.
Claims never select an Agent. A durable `typed_runtime_authorization` marker is
required before the typed runtime read path can release any value.

Reads acquire the global epoch, Agent subject, and application subject locks in
that order, then hold entity/certificate/path/current-secret locks through the
transaction. Both typed policy gates must independently allow the canonical dot
path. Explicit deny and malformed applicable conditions fail closed. The Vault
must verify its durable configuration even for exact-revision `not_modified`.
Allow and deny audit appends are required; no secret value enters their metadata.

Mutation statement triggers acquire the global epoch exclusively before entity
DML and bump typed subject versions atomically. Contexts that first lock rows
explicitly acquire the epoch before those rows. This conservative implementation
serializes authorization writers. Direct SQL DML is covered; callers must not
first lock entity rows in an ad hoc transaction before invoking these contexts.
Per-path revisions remain after deletion and advance on recreation and mutation.

`UpgradeGates.activate_app_certificate_v2/1` is the cutover operation. It reruns
canonical and typed preflights under the epoch lock, requires capable fresh
Agents, and requires exact acknowledged snapshots for stale or retired Agents.
It durably raises the minimum UDS authentication version to 2. The database rejects
lowering or deleting that floor, and every runtime read rechecks it under the
shared epoch lock. The post-transaction broadcast is advisory: missing notification
cannot authorize a v1 request after cutover. Agents persist their maximum observed
floor before acknowledgment and must reject a restored Core with an older floor.

The compatibility release retains legacy columns and existing many-app Agent
assignments. A future separately reviewed contract release may remove legacy
authorization only after every deployed node advertises canonical capability and
all preflights have been rerun with zero findings. No destructive contract
migration or production cutover is part of this change.

The focused runtime test fixture uses disposable PostgreSQL databases and real
pool connections. Shared SQL Sandbox transactions cannot validate the separate
Vault process's durable reads or concurrent PostgreSQL locking. The test role
therefore needs permission to create its isolated databases; cleanup drops only
those generated fixtures.
