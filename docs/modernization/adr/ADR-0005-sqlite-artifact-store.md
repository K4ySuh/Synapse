# ADR-0005: SQLite and a content-addressed artifact store

- Status: Accepted
- Date: 2026-08-24
- Owners: Synapse architectural lead
- Applies from: Phase 4
- Supersedes: File-backed operational state after migration acceptance

## Context

Current operational state is distributed across workspace JSON files, JSONL
event logs, credential metadata, job records, evidence files, fingerprints, and
generated reports below the local runtime root. Workspace and evidence modules
perform direct path construction, locking, serialization, and updates. Large
artifacts already belong in files, while relationships and lifecycle state are
spread across multiple documents.

Later phases need transactional revisions, authority/task/evidence linkage, and
restartable migration. Introducing a database before the typed application and
authority boundaries exist would entrench current module coupling instead of
removing it.

## Decision

Replace fragmented JSON/JSONL operational state with one SQLite database and
one artifact namespace per workspace, reached only through application-facing
repository interfaces. The fixed workspace layout is:

```text
DATA/workspaces/<workspaceId>/state-v2/state.sqlite3
DATA/workspaces/<workspaceId>/state-v2/artifacts/sha256/<prefix>/<digest>
```

SQLite operates in WAL mode with foreign keys enabled on every connection,
`synchronous=FULL` by default, a bounded busy timeout, and short explicit
transactions. WAL/multi-connection use requires the actual linked SQLite
runtime to be 3.51.3 or later. The standard `sqlite3` binding is selected when
it meets that floor; otherwise the maintained APSW version pinned in the
`state-v2` extra provides SQLite 3.53.4 across the supported Python 3.10–3.13
matrix. Readiness reports both `sqlite3.sqlite_version` and the selected
binding/runtime instead of inferring SQLite capability from the Python version.

State Store v2 supports local filesystems only and fails readiness on known
network or unsupported filesystem types. It is not a graph database or vector
store. Graphs and embeddings remain non-authoritative derived projections.

Credential bodies and request-state encryption keys stay in their existing
confined stores. SQLite may hold only opaque credential/key references and the
minimum non-secret metadata needed for authority, dispatch, evidence, and
audit linkage.

## Invariants

- Migration is deterministic, versioned, restartable, idempotent, dry-runnable, and explicit about unresolved or orphaned records.
- No indefinite dual-write; an explicit workspace store version identifies the authoritative engine.
- Existing evidence and finding IDs are preserved where technically possible; any mapping is explicit and exportable.
- JSON import and export remain supported; a pre-migration snapshot is retained until acceptance.
- Embeddings and graph projections are derived indexes, never sources of truth.
- One database and artifact namespace belong to exactly one workspace; no
  cross-workspace content deduplication or database reference is permitted.
- Existing workspaces remain JSON v1 until deterministic migration verifies and
  atomically activates the v2 selector. An absent selector means JSON v1.
- JSON v1 receives no writes after activation. It remains an immutable
  pre-cutover snapshot rather than a dual-written peer.
- Artifact bytes are bounded, streamed, hashed, fsynced, and atomically
  installed before database metadata commits. A directory is a bounded,
  canonical sorted manifest of individual SHA-256 blobs.
- Symlinks, traversal, non-regular files, hash/collision mismatch, missing
  blobs, and cross-workspace access fail closed.
- Raw credential secrets, bearer values, cookies, request-state keys, and raw
  opaque handles never enter SQLite, exports, migration evidence, or artifact
  metadata.
- Protocol profile selection is independent of store selection. Legacy MCP
  must operate over whichever repository the workspace selector chooses.

## Alternatives considered

### Keep JSON and JSONL as the permanent authoritative store

- Benefits: Fully inspectable files, no database dependency, and minimal
  migration.
- Costs: Cross-entity transactions, revision queries, relationship integrity,
  and restartable state changes remain difficult.
- Reason rejected/deferred: The future authority, task, and context models need
  transactional operational truth.

### Store every artifact body in SQLite

- Benefits: One backup unit and transaction boundary.
- Costs: Large responses, screenshots, scanner output, bundles, and reports
  bloat the database and weaken content reuse.
- Reason rejected/deferred: Large immutable content belongs in an artifact
  store referenced by hash.

### Adopt a graph or vector database

- Benefits: Native relationship traversal or semantic retrieval.
- Costs: Adds operational complexity and risks making derived projections the
  source of truth.
- Reason rejected/deferred: Relational integrity is sufficient for authoritative
  state; graph and embedding views remain derived.

### Indefinitely dual-write file and database stores

- Benefits: Continuous compatibility and easy comparison.
- Costs: Conflicting truth requires reconciliation and makes failures
  ambiguous.
- Reason rejected/deferred: Store authority must be explicit and singular.

## Consequences

- Positive: Transactions, foreign keys, revisions, and indexed relationships
  become available behind application repositories.
- Negative: Migration, backup, repair, and store-version operations require new
  tooling and tests.
- Operational: Large artifacts remain inspectable immutable files, addressed by
  content hash inside one workspace namespace. Backup uses SQLite's online
  backup API plus a verified artifact manifest; a live database is never copied
  as an ordinary file.
- Security: Store boundaries and partitions must preserve engagement isolation
  and evidence provenance.
- Compatibility: JSON import/export and a retained pre-migration snapshot
  preserve rollback and interoperability.

## Migration and rollback

ADR-0002 and ADR-0003 are stable. Define versioned repository interfaces and a
dry-run migration that inventories every source record, artifact, unresolved
reference, and ID mapping. Under the workspace lock, create an immutable
pre-cutover snapshot and canonical manifest, import deterministically, verify
counts, relations, authority totals, and hashes, then atomically switch the
workspace selector. Never dual-write.

Protocol rollback selects the legacy MCP surface while retaining the selected
workspace repository; it never implies JSON v1. State-engine rollback selects
the retained JSON snapshot and is safe only before the first v2-only mutation.
After v2 advances, rollback must refuse with a typed data-loss reason unless a
separately designed and verified reverse migration exists. Forward export and
migration are the recovery path after that boundary.

## Verification

- Run migration twice and verify identical results without duplicate records.
- Interrupt and resume at each migration stage.
- Compare entity, evidence, finding, action, credential-reference, and artifact
  counts plus content hashes.
- Exercise foreign keys, WAL recovery, export/import, dry-run, orphan reporting,
  and store-version selection.
- Prove rollback from the retained snapshot before accepting the new store.
- Print Python, `sqlite3.sqlite_version`, fallback binding/runtime, selected
  binding, and filesystem type in readiness and CI evidence. Reject SQLite
  below 3.51.3 rather than weakening the floor.
- Verify unsupported/network filesystems fail before WAL activation, secrets
  are absent, and both legacy and modern transports use the selected store.
