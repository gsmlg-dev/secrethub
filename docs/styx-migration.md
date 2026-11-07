# Background-job migration to Styx

Core and Human use separate repositories and named Styx instances:
`SecretHub.Core.Styx` and `SecretHub.Human.Styx`. Migrate both databases before
starting an enabled Human application. Fresh databases install Styx schema v1
through the existing historical queue migrations.

Existing databases apply `20261107000001_replace_oban_with_styx.exs` in each
repository. The transition accepts Oban PostgreSQL schema v14, used by Oban
2.24.2. It renames `oban_jobs`, `oban_peers` and `oban_job_state` to their Styx
equivalents. It preserves every queued job, state (including suspended jobs),
payload, retry history, timestamp, peer row and the owned ID sequence. Existing
index and sequence names retain their physical Oban names; their identities,
ownership and sequence values remain intact. Worker module names are unchanged,
so persisted jobs resolve to the same application workers.

The migration records Styx schema version 1 and creates `styx_wrap_id(bigint)`.
Oban v14 has no database notification trigger; Styx publishes notifications
through its own PostgreSQL notifier on `<schema>.styx_*` channels. Existing
peer names are retained as historical data; the new configured instances use
their Styx names. Simultaneous `oban_jobs` and `styx_jobs` tables are rejected
without merging or discarding either queue.

Before an operator applies this migration:

1. Back up both databases and stop all Core and Human job producers and workers.
2. Apply the normal Core and Human release migrations with the new release.
3. Start the new release and verify the configured queues and pending work.

Do not run old Oban workers alongside Styx workers. Their table names and
notification channels differ. Update external telemetry consumers from
`[:oban, ...]` to `[:styx, ...]` when adopting the release.

Rolling back the transition renames migrated storage back to Oban, restores
the v14 table comment, and removes the transition's `styx_wrap_id` function.
Jobs added by Styx remain in the restored queue. Stop all producers and workers
before rollback, roll back the transition in both repositories, then use the
previous Oban release. A fresh Styx database is unchanged by rolling back only
the transition. Fully rolling back the historical queue installation drops
queue storage, as a normal full schema rollback does.

The regression suite uses isolated schemas and covers both repository migration
paths, all eight legacy states, peers, ID sequence identity and continuity,
fresh installation, upgrade, rollback, full rollback/reapplication, dual-storage
rejection and execution of migrated/new jobs after a Styx instance restart.
These checks do not authorize migration or restart of a live/shared service.
