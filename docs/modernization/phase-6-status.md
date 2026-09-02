# Phase 6 implementation status

Phase 6 is in progress. This status is intentionally checkpointed in small,
resumable task slices; it is not a Phase 6 acceptance or closure claim.

## Task 6A.1 — durable work-execution attempts

Status: implemented on 2026-08-31; focused gates passed.

Delivered:

- SQLite-v2 migration `0004` adds durable work-execution attempts bound before
  dispatch to the work item, originating claim, trusted principal/session,
  action, replay class, and hashed idempotency identity;
- the facade replaces claim-dependent pre/post links with bind, start, and
  lease-independent finalization transitions around the unchanged Action
  Registry path;
- planned, started, approval-pending, and unknown attempts are classified as
  reconciliation-required and block automatic duplicate dispatch;
- linked action results expose the current work-item version and opaque
  execution reference, including the `execution_unknown` result-link failure;
- supervised operation records retain the attempt identity for exact resume;
- state bundles and context snapshots preserve attempt identity and state.

Focused verification:

```text
8 Phase 6A work-execution reliability tests passed
17 Phase 5C work-item compatibility tests passed
66 retained Phase 5 tests passed
25 Phase 3B facade tests passed
48 Phase 4 state/migration/runtime/context tests passed
9 Phase 5F operational acceptance tests passed
```

Compatibility result: action IDs, Registry routing, effects, authority
evaluation, dispatch truth, output contracts, the eleven compact operations,
legacy behavior, and JSON-v1 remain unchanged. Migration `0004` is additive
for activated SQLite-v2 workspaces. The complete Task 6A gate has not run yet.

## Task 6A.2–6A.6 — operational errata and performance baseline

Status: implemented and independently reviewed on 2026-09-01; Task 6A passed
after a review-discovered performance-method correction.

Delivered:

- SQLite-v2 migration `0005` gives existing and new work items the explicit
  compatible `success_required` dependency default, adds
  `terminal_required`, and stores structured blocker details;
- terminally impossible success-required work becomes blocked atomically, while
  terminal-required convergence/reporting work becomes available only after
  every dependency reaches a terminal state;
- `work.resolve_blocked` provides CAS-protected cancel or replan resolution and
  never invents successful completion;
- default work lists are bounded summaries with filter-bound opaque keyset
  cursors; inspect and `detail=true` provide full records, and list/inspect
  calculate effective claim expiry without a recovery mutation;
- `tasks.control(operation="work.contract")` returns the application-owned
  discriminated payload schemas and examples without selecting a workspace or
  adding a twelfth compact operation;
- Phase 5 documentation now records the exact official-host allowlist defect
  and distinguishes the historical Phase 5E 5,941-byte prompt from the shipped
  Phase 5F 6,289-byte prompt without rewriting historical acceptance evidence;
- `bin/run-phase6-performance` records three batched repetitions and a
  versioned pre-instrumentation environment/method fingerprint, exposes
  absolute ceilings, and checks the unchanged 20% matching-method relative p95
  bound. Failed single-run v1 and unbatched v2 evidence remain historical.

Exact verification:

```text
19 Phase 6A reliability/work-contract/performance-method tests passed
66 retained Phase 5 tests passed
767 full core tests passed
16 official-SDK modern adapter tests passed
2 custom-adapter template tests passed
Phase 5 operational acceptance passed all 8 verdict groups and 3 repetitions
Phase 6A v3 performance comparison passed all relative p95 bounds
174-action inventory current; 168 retained output contracts current
174 actions have one owner across 6 capability packs
modern-compact remains 11 operations and 23,336 application bytes
8 Codex skills and 2 shared references validate
222 Python files compile; shell syntax, secret-pattern, and diff hygiene pass
```

The Phase 5 distribution sub-gate used its documented build-interpreter
override because this host splits offline `pip` from the system
`setuptools`/`wheel` packages. Task 6B closure added the missing explicit,
build-scoped `SYNAPSE_BUILD_PYTHONPATH` support and reran both archive installs
plus standard 174-action and core-only 42-action startup. The historical Phase
5 acceptance artifact was not regenerated.

Compatibility result: the Action Registry remains the one execution path;
standard/core action counts stay 174/42; compact stays at eleven operations;
modern-direct, frozen legacy, JSON-v1, Phase 4 migration, and Phase 5 work-item
callers remain compatible. Migration `0005` is additive only for explicitly
activated SQLite-v2 workspaces.

Residuals and boundary:

- the accepted v3 capture misses standard cold-start p50 and core-only p50/p95
  absolute ceilings. Those failures remain visible while matching future runs
  enforce the accepted 20% relative p95 ceiling;
- the Registry timing is a pre-instrumentation control, not an observed-effect
  or effect-validation claim;
- retained generic MCP conformance is still `partial_fail`; Inspector and live
  Codex diagnostics remain optional and were not rerun for Task 6A;
- Task 6A does not change the Phase 5 multi-agent Codex default. That integration
  change belongs to Task 6B, and Phase 6 is not closed before Task 6J.

The completed independent review and corrective evidence are in
[the Task 6A adversarial-review brief](phase-6a-adversarial-review.md). Task 6B
follows below.

## Task 6B — single-agent Codex default and compatibility profile

Status: implemented on 2026-09-01; focused and full compatibility gates passed.

Delivered:

- ADR-0012 establishes one Codex agent as the default operational unit over
  the unchanged multi-consumer Synapse core;
- the default profile contains exactly `operate-synapse`,
  `synapse-web-pentesting`, and `synapse-cve-intelligence`, with Web Pentesting
  absorbing bootstrap/perimeter/application/authentication/access-control and
  bounded validation methodology, and CVE Intelligence covering precise
  component correlation, authoritative/public-PoC intelligence, applicability,
  and bounded validation planning;
- the Phase 5 coordinator and specialist skills remain installable under the
  explicit `multi-agent-compat` profile, while `synapse-developing` is a
  separate development profile;
- the root instructions and package-owned operational prompt now require
  workspace-truth recovery, direct simple work, no default sub-agent spawning,
  on-demand methodology selection, and multi-consumer terminology;
- the skill validator and `synapse-codex-assets` expose profile-aware checks and
  selection; wheel/sdist metadata contains identical default, compatibility,
  development, and five config-profile assets;
- the historical Phase 5 live runner requires explicit compatibility selection,
  and `bin/run-phase6b-codex-diagnostic` provides an optional one-agent
  Terra/medium diagnostic for direct work, sequential skill use, recovery,
  non-replay, and report convergence.

Focused verification:

```text
8 Phase 6B single-agent/default-profile tests passed
8 Phase 5D compatibility skill tests passed
7 Phase 5E instruction/distribution tests passed
9 Phase 5F operational acceptance tests passed
5 modernization documentation tests passed
12 authored skill trees passed skill-creator validation
778 full core tests passed
16 official-SDK modern adapter tests passed
Phase 5 offline acceptance passed: 66 tests, 3 repetitions, no external traffic
Phase 6B wheel/sdist distribution passed: 174/42 standard/core actions
Action inventory/output contracts/pack ownership current: 174/168/174
Compact surface unchanged at 11 operations; compatibility profiles validated
```

Compatibility result: no Action Registry action ID/order, output contract,
effect, Authority Engine, workspace/state migration, evidence, job, compact,
direct, legacy, JSON-v1, or provider-neutral application behavior changed.
The full core and modern gates require loopback socket binding and were run
outside the default sandbox; the sandbox-only attempt's socket errors were
environment restrictions, not product failures. The optional live model run
was not consumed; its preflight passed and acceptance remains offline.

Closure correction on 2026-09-01:

- repository, modernization-index, changelog, and local version-log wording was
  reconciled with the committed Task 6B state;
- the offline distribution runner now supports an explicit build-only Python
  package path when `pip` and `setuptools`/`wheel` live in separate local
  environments, without leaking that path into installed runtime checks;
- the timeout-recovery workflow benchmark now scopes every job inventory read
  to its fixture workspace, so a late worker from another isolated fixture
  cannot be misclassified as duplicate execution; duplicate records inside the
  benchmark workspace still fail with bounded job diagnostics;
- no live Phase 6B trace directory existed, consistent with the recorded
  preflight-only optional diagnostic.

Closure verification:

```text
8 Phase 6B tests and 8 Phase 5E distribution/instruction tests passed
67 retained Phase 5 tests passed
779 full core tests passed
16 official-SDK modern adapter tests passed
2 custom-adapter template tests passed
Phase 5 operational acceptance passed all 8 verdict groups and 3 repetitions
Phase 6B wheel/sdist distribution passed: 174/42 standard/core actions
Action inventory/output contracts/pack ownership current: 174/168/174
Compact surface current: 11 operations / 23,336 application bytes
225 Python files compile; shell syntax and diff hygiene pass
```

Task 6B is complete. Task 6C follows below; Phase 6 remains open through Task
6J.

## Task 6C — versioned execution lifecycle and durable run state

Status: implemented on 2026-09-02; focused and compatibility gates passed.

Delivered:

- ADR-0013 maps execution intent, authorization, dispatch, observation, and
  validation onto the existing `ExecutionPlan` v1, Action Registry, Authority
  Engine, work-attempt, background-job, and SQLite-v2 paths and rejects a
  parallel executor, authority service, or lifecycle store;
- immutable protocol-independent contracts seal execution intent,
  authorization binding, run identity/state, observation provenance/trust and
  coverage, normalized effects, discrepancies, and validation verdicts;
- ordered migration `0006_execution_lifecycle.sql` adds exactly one run per
  dispatch plus append-only observations and validations to the workspace
  database, with repository, migration inventory, backup, and canonical bundle
  support;
- the Authority reservation transaction creates the run before effecting
  dispatch and binds exact plan/authorization fingerprints, opaque
  session/idempotency references, grant revision, and optional work attempt;
- synchronous Registry execution, exact supervised resume, and background
  creation/status/finalization carry the same run identity, while restart can
  reconstruct every lifecycle boundary without consulting a work lease;
- the injectable no-op observer records `not_instrumented` coverage and an
  explicit `unobservable` verdict. Only runtime-observed/runtime-enforced
  telemetry can determine effect truth; mismatched validation fingerprints are
  rejected atomically, and unsafe or failed validation becomes
  `execution_unknown` without replay;
- existing `ExecutionPlan` v1/job fixtures and JSON-v1 authority serialization
  remain compatible. JSON-v1 refuses lifecycle repository selection and gains
  no lifecycle files or dual-write behavior.

Exact verification:

```text
19 Phase 6C lifecycle/migration/concurrency/data-hygiene tests passed
147 authority/state/work/background compatibility tests passed
58 Phase 4 migration/runtime/context tests and acceptance passed
67 retained Phase 5 tests and all 8 acceptance verdict groups passed across 3 repetitions
16 official-SDK modern adapter tests passed
2 custom-adapter template tests passed
798 full core tests passed
Action inventory/output contracts/pack ownership current: 174/168/174
Compact surface remains 11 operations / 23,336 application bytes
Phase 6A v3 performance comparison passed the matching 20% relative p95 gate
229 Python files compile; shell syntax and diff hygiene pass
```

The Phase 5 distribution sub-gate used the documented build-only
`SYNAPSE_BUILD_PYTHON` and `SYNAPSE_BUILD_PYTHONPATH` overrides for this host's
split offline build prerequisites; both wheel and sdist installs and 174/42
standard/core startup passed. The first invocation omitted the explicit build
interpreter and failed before building; no product or fixture change was made
to obtain the pass.

Compatibility result: the Registry remains the only executor path and the
Authority Engine remains the only grant/effect decision path. Action
IDs/order/effects and generated contracts remain 174/168/174; compact remains
eleven operations; modern-direct, the frozen legacy projection, persisted plan
v1, existing SQLite-v2 dispatches, and JSON-v1 behavior remain compatible.
Migration `0006` is additive and does not invent lifecycle truth for historical
dispatches.

Residuals and boundary:

- Task 6C establishes lifecycle identity and durable truth but deliberately
  provides no owned HTTP, local-output, or child-process observation coverage;
  normal baseline verdicts are explicit `unobservable`, not proof that effects
  were observed;
- the performance replay retains the accepted absolute cold-start misses while
  passing every matching-environment relative p95 comparison; Registry control
  p95 changed from 0.038 ms to 0.039 ms;
- generic MCP conformance remains the retained `partial_fail` classification;
  Inspector and live Codex diagnostics remain optional and were not rerun;
- Task 6C requires an adversarial checkpoint focused on lifecycle-state
  completeness and duplicate dispatch before Task 6D begins. Phase 6 remains
  open through Task 6J.
