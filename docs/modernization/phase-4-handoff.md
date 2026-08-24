# Phase 4 state and context handoff

Phase 4 is the persistence and context boundary for Synapse Beta. A genuinely
new workspace is created directly in State Store v2 after runtime/filesystem
readiness succeeds. Existing JSON-v1 workspaces are never migrated
automatically: inventory, migration, verification, and activation remain
separate operator steps with no deadline.

Protocol profile selection is independent of workspace store selection.
`legacy`, `modern-compact`, and `modern-direct` are MCP projections; JSON-v1 and
SQLite-v2 are workspace persistence engines. The frozen legacy launcher reads
an activated v2 workspace, and selecting it never switches state back to JSON.

## Acceptance gate

Run the closed, offline gate from the repository root:

```bash
bin/run-phase4-acceptance
```

The runner uses only fictional `.example` targets, sends no target traffic,
creates private temporary roots, injects migration and transaction failures,
and commits only sanitized aggregate evidence to
`docs/modernization/evidence/phase-4/acceptance-results.json`. It covers fresh
v2 bootstrap/restart, deterministic v1 migration twice, interruption/resume,
activation and v2-only writes, multi-process concurrency tests, online backup,
bundle export/import, legacy stdio over v2, context budgets/deltas/omissions,
rollback refusal, and secret hygiene.

The runner's exact JSON-RPC transport smoke is explicitly not an objective
agent benchmark. The live Codex workflow benchmark remains the separate
command below and is run only when the real client is available:

```bash
bin/run-phase3-agent-benchmark --run --repetitions 3
```

MCP Inspector is an independent discovery client when locally available. The
generic MCP conformance verdict remains honestly `partial_fail`; repository
transport/security tests and Inspector discovery do not convert unresolved
generic-suite failures into a universal conformance pass.

## Store adoption

| Workspace condition | Selected store | Operator action |
| --- | --- | --- |
| New ID with no legacy files | SQLite-v2 | None after readiness; creation is transactional |
| Existing JSON-v1 files, no v2 selector | JSON-v1 | Explicit migration and activation when desired |
| Verified migration, not activated | JSON-v1 | Review verification, then `bin/state activate` |
| Activated or bundle-imported workspace | SQLite-v2 | Use both protocol profiles normally |
| V2 advanced beyond activation | SQLite-v2 | Export/forward recovery; state rollback is refused |

Fresh bootstrap commits workspace, scope, initial targets, revision, change
records, and audit in one SQLite transaction, then atomically installs the
store selector. If the process stops between those steps, retrying the same
creation resumes the database and installs the selector without a duplicate
revision.

## Migration and rollback

Stop MCP processes that can write the workspace, then run:

```bash
bin/state inventory <workspace>
bin/state migrate <workspace> --dry-run
bin/state migrate <workspace> --apply
bin/state verify <workspace>
bin/state status <workspace>
bin/state activate <workspace>
```

Keep the pre-cutover snapshot and JSON-v1 source. Migration never activates
implicitly. A state-engine rollback is safe only before the first v2-only
revision:

```bash
bin/state rollback <workspace>
```

`rollback_v2_data_loss_risk` is a required refusal, not a recoverable retry.
Export current v2 truth and perform a reviewed forward recovery. Changing the
MCP protocol profile is always available independently and does not cross this
state rollback boundary.

## Backup and recovery

Prefer a canonical bundle for portable, complete state plus artifact recovery:

```bash
bin/state export <workspace> --output /private/path/workspace-bundle
bin/state import /private/path/workspace-bundle
```

Import requires an empty destination with the same workspace identity,
verifies schema/content/artifact hashes before selection, and activates the
imported SQLite-v2 workspace only after semantic equivalence succeeds. Never
edit `bundle.json`, rebind a bundle to another workspace ID, or use it to move
credential bodies; those remain outside state exports.

For a fast database-only recovery point while writers remain online:

```bash
bin/state checkpoint <workspace>
bin/state backup <workspace> --output /private/path/state-backup.sqlite3
```

The backup API creates a consistent SQLite image and refuses overwrite. It
does not copy the workspace artifact namespace or external credential store,
so retain those separately. Never copy the live `state.sqlite3`, WAL, or SHM
files as a backup. In-place restoration is deliberately not automated: stop
all writers, preserve the failed workspace for forensics, verify the backup
and artifact inventory, and use a reviewed forward recovery or canonical
bundle import rather than overwriting live state ad hoc.

## Troubleshooting

- `sqlite_runtime_too_old`: install the reviewed `state-v2` extra or select a
  runtime whose linked SQLite meets the documented floor; do not lower it.
- `network_filesystem_unsupported` / `filesystem_unsupported`: move the local
  workspace to a supported filesystem. WAL workspaces are not placed on known
  remote/unsupported mounts.
- `migration_source_changed`: stop writers and repeat inventory/dry-run against
  the current JSON-v1 bytes.
- `migration_verification_failed`: inspect blocking orphans and verification
  counts. Do not activate or delete the pre-cutover snapshot.
- `state_busy_retryable`: retry the bounded operation after contention clears.
- `state_commit_unknown`: reconcile current revision, dispatch, task, and audit
  truth before deciding whether another operation is safe.
- `rollback_v2_data_loss_risk`: retain v2 as authoritative and use export plus
  forward recovery.
- A missing selector on an interrupted fresh bootstrap is recovered by retrying
  the same workspace creation. Do not create a selector by hand.

The JSON-v1 adapter, pre-cutover snapshots, legacy protocol fixtures, and
frozen launcher remain supported rollback/compatibility assets. Phase 4 sets
no automatic migration deadline and makes no cross-client or universal-agent
performance claim.

## Closure markers

```text
PHASE_4_ENTRY_PASS
PHASE_4A_PASS
PHASE_4B_PASS
PHASE_4C_PASS
PHASE_4D_PASS
PHASE_4_PASS
```
