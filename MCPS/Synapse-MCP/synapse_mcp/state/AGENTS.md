# State Store Instructions

- SQLite-v2 is authoritative only for an activated workspace. Existing
  selector-less JSON-v1 workspaces remain compatibility/migration inputs; never
  auto-migrate or dual-write.
- Keep one per-workspace database and artifact store. Raw SQL stays in this
  package; callers use repository contracts and transaction boundaries.
- Domain mutation, workspace revision/change log, evidence/result references,
  and audit must commit atomically. Use optimistic concurrency with actionable
  stale-version diagnostics and bounded retry only before an unambiguous commit.
- Credential bodies, bearer/cookie values, raw opaque handles, encryption keys,
  and request-state keys remain outside workspace SQLite and canonical bundles.
- Migrations are ordered, hashed, restartable, and verified. Update schema
  inventory, in-place upgrade, bundle export/import, backup, and recovery tests
  with every migration.
- Install content-addressed artifacts before metadata references. Reject path
  traversal, symbolic-link escape, hash mismatch, collision, and broad or
  non-local storage roots.
- Work-item lease expiry makes a claim reclaimable; it never cancels, replays,
  or declares linked active/unknown execution safe. Preserve handoff and event
  history across restart.
- Use isolated fictional workspace roots in tests. Exercise multiprocess races,
  crash boundaries, WAL/backup behavior, bundle recovery, and JSON-v1 refusal
  for v2-only mutations.
