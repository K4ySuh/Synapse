# ADR-0005: SQLite and a content-addressed artifact store

- Status: Proposed
- Date: 2026-07-28
- Owners: Synapse architectural lead
- Applies from: Phase 4 or later after application and authority boundaries stabilize
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

Replace fragmented JSON/JSONL operational state with SQLite (WAL, foreign keys) reached only through application-facing repository interfaces, plus an immutable content-addressed artifact store for large files. Not a graph database, not a vector store. Introduced only after the application and authority boundaries are stable.

## Invariants

- Migration is deterministic, versioned, restartable, idempotent, dry-runnable, and explicit about unresolved or orphaned records.
- No indefinite dual-write; an explicit workspace store version identifies the authoritative engine.
- Existing evidence and finding IDs are preserved where technically possible; any mapping is explicit and exportable.
- JSON import and export remain supported; a pre-migration snapshot is retained until acceptance.
- Embeddings and graph projections are derived indexes, never sources of truth.
- **Unresolved and deliberately deferred:** one database per engagement versus one strictly partitioned local database.

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
  content hash.
- Security: Store boundaries and partitions must preserve engagement isolation
  and evidence provenance.
- Compatibility: JSON import/export and a retained pre-migration snapshot
  preserve rollback and interoperability.

## Migration and rollback

Wait until ADR-0002 and ADR-0003 boundaries are stable. Define versioned
repository interfaces and a dry-run migration that inventories every source
record, artifact, unresolved reference, and ID mapping. Create a pre-migration
snapshot, import deterministically, verify counts and hashes, then switch the
explicit workspace store version. Do not dual-write indefinitely. Rollback
selects the retained file store and snapshot before new database-only writes are
accepted. The database partitioning choice remains a separate decision.

## Verification

- Run migration twice and verify identical results without duplicate records.
- Interrupt and resume at each migration stage.
- Compare entity, evidence, finding, action, credential-reference, and artifact
  counts plus content hashes.
- Exercise foreign keys, WAL recovery, export/import, dry-run, orphan reporting,
  and store-version selection.
- Prove rollback from the retained snapshot before accepting the new store.
