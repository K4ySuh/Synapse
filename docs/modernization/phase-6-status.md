# Phase 6 status

Phase 6 Beta is complete. Tasks 6A–6D are implemented at reviewed Beta commit
`5a33b238020ff987ecf38dd3afcacca81d13de1a`. Task 6R0 records the revised
completion contract; 6R1 corrects new SQLite-v2 ingestion, and 6R2 makes
authority/lifecycle persistence incremental, and 6R3 publishes versioned
consumer contributions. 6R4 publishes canonical modern guidance. Task
6R5 bounds context recovery and preserves synchronous observations across
failure finalization. Task 6R6 proves a passive saved-data integration seam.
Task 6R7 completes current-suite integration, a bounded direct-client exercise,
and the operator handoff at `48dee7f`. The passing client claim is limited to
the exact configuration in the [exercise record](phase-6-client-exercise.md).
See the [roadmap](README.md#phase-6-beta-completion-roadmap) and
[checkpoint ledger](phase-6-checkpoints.md).

- The default is one Codex agent using `modern-compact`. Provider-specific
  skills stay outside the Synapse application.
- Work items, authority grants, dispatches, and execution runs remain in
  canonical SQLite-v2 workspace state. JSON-v1 compatibility and explicit
  migration remain unchanged.
- The Action Registry is the single policy, execution, outcome, and evidence
  route. A dispatch is bound to its signed execution plan and durable run.
- 6D observes Synapse-owned synchronous HTTP hops, planned local-output writes
  and exact retention deletions, and command preflight/process lifecycle at
  the synchronous child-process seam. It enforces the plan at those owned
  boundaries and records bounded, redacted observations on the durable run.
  Child-process internals, provider-only HTTP, browser activity, background
  worker internals, and other uninstrumented effects are outside that coverage.
  Missing or uncertain effects require reconciliation and are not
  automatically replayed. Comprehensive observer/provider coverage is
  deferred.
- Existing 6C lifecycle runs, receipt/job binding, and date-relative test
  fixtures are retained. Commit `f503e87` repaired the fixture clock, and the
  renamed lifecycle test passed 22/22 at `5a33b23`; these are historical
  reviewed results, not fresh 6R0 test runs.
- Pre-fix SQLite-v2 workspaces may retain historical over-linking. The affected
  path and manual review limit are documented in [Operations](../Operations.md#workspace-context);
  no historical links are removed automatically. SQLite-v2 authority mutations
  now use indexed current-record reads and change-only writes. With 8 versus
  256 retained mock runs on one local interpreter, the persistent path used the
  same SQL statement counts per operation and measured 15.22 versus 15.40 ms
  median. These figures are a local diagnostic, not a client or service-level
  guarantee. Versioned ingestion is documented in the
  [contribution contract](../Contribution-Contract.md). The modern server now
  exposes the same package-owned operating prompt as legacy plus a read-only,
  digested catalog of the three default Codex skills and their references.
  Local skill installation remains supported; hosted resources do not activate
  client skills. Context recovery now selects at most bounded repository pages
  from one SQLite snapshot and protects relevant unresolved run, dispatch,
  work/job, outcome, coverage, and validation facts. Captured synchronous
  observations survive executor/output/finalization failures when storage can
  commit; uncertain execution remains unknown and is never automatically
  replayed. The OpenAPI/Swagger/Postman pilot now keeps its existing action and
  legacy alias over a deterministic core parser/ingestion seam. Hosted web
  guidance points to live Registry and contribution schemas, and the saved-data
  integration convention classifies future adapter migration without starting
  a catalog rewrite. A fictional temporary-workspace scenario proves saved
  import, strict contribution receipt, evidence-linked context recovery, and
  report projection. The 6R7 current core/modern/distribution checks pass, and
  one provisioned Codex/Daybreak client recovered that fictional state across
  restarts, committed one idempotent contribution receipt under narrow
  authority, and rendered a context-backed report. This is not a claim for
  untested clients or models.
  Counterfactual evaluation is deferred.

The applicable developer checks are focused service tests for the changed
boundary. Completed-phase acceptance and benchmark runners were retired; they
are not prerequisites for Beta completion. Current operator instructions are in
[Operations](../Operations.md). Durable decisions are in
[ADR-0013](adr/ADR-0013-observed-effect-execution-lifecycle.md).
