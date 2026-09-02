# ADR-0013: Observed-effect execution lifecycle over the canonical dispatch path

- Status: Accepted
- Date: 2026-09-02
- Owners: Synapse architectural lead
- Applies from: Phase 6C
- Supersedes: None; extends ADR-0002, ADR-0003, ADR-0005, and ADR-0011

## Context

The Action Registry already produces one sealed `ExecutionPlan`, the Authority
Engine binds an allow decision to its fingerprints and reserves one dispatch,
executors receive that same plan, and background jobs seal continuation data.
Those boundaries prove intent and pre-dispatch authorization, but they do not
yet provide one durable identity for the complete attempt or distinguish
runtime-observed effects from provider, consumer, or model narration.

Adding a parallel lifecycle executor, authority service, or state database would
split the strongest existing guarantees. Replacing the persisted plan format
would also break frozen job and continuation records without improving the
identity already sealed by `ExecutionPlan` v1.

## Decision

Phase 6 uses this lifecycle:

```text
ExecutionIntent
    -> ExecutionAuthorization
    -> ProviderDispatch / ExecutionRun
    -> NormalizedEffectObservation
    -> EffectValidation
    -> outcome commit or execution_unknown
```

`ExecutionPlan` v1 remains the execution and job compatibility carrier. A
versioned `ExecutionIntent` lifecycle contract wraps the complete sealed plan,
its plan fingerprint, and its stable authorization fingerprint. Existing v1
plans continue to deserialize and verify byte-for-byte; a future plan v2 must
retain an explicit v1 reader.

For an activated SQLite-v2 workspace, the existing locked authority transaction
creates one `ExecutionRun` with the dispatch reservation before the executor is
entered. The run binds workspace, action, correlation, opaque idempotency
identity, exact intent and authorization fingerprints, grant revision, trusted
authority-session reference, optional work execution attempt, and continuation
job identity. A unique dispatch foreign key makes duplicate run creation a
database error in addition to the existing idempotency reservation checks.

Migration `0006_execution_lifecycle.sql` adds `execution_runs`, append-only
`execution_observations`, and append-only `effect_validations` to the same
per-workspace database. The authority repository advances both dispatch and run
truth in one workspace transaction. Bundle export/import, online backup,
migration verification, workspace revisions, change log, and audit continue to
use the existing state system. There is no lifecycle database or dual-write.

Run states are reconstructable as `authorized`, `dispatch_started`,
`observing`, `validation_pending`, `outcome_committed`, `execution_unknown`, or
`not_dispatched`. Finalization is bound to the run and dispatch identity, not a
work-item lease. Supervised retry creates a run only after exact step-up
authorization. Background creation stores the originating run in both the job
and dispatch continuation binding; status/finalization reuses that run rather
than reserving a second one.

The Registry policy evaluator owns an injectable `ExecutionObserver` seam.
Task 6C ships a no-op coverage-aware observer which records
`not_instrumented` and validates as `unobservable`; it does not manufacture
runtime observations. Later phases may inject owned HTTP, output, command,
browser, provider, and job observers without bypassing Registry dispatch.

Only `runtime_observed` and `runtime_enforced` observations may determine
effect-validation truth. `provider_reported`, `consumer_reported`,
`model_reported`, and `legacy_unknown` records are supporting context. A trusted
outside-envelope, incomplete, or indeterminate verdict forces dispatch and run
truth to `unknown` and prevents normal Registry outcome commitment.

JSON-v1 remains a compatibility and migration input. It retains its existing
authority/dispatch behavior and refuses lifecycle repository selection; Phase
6 does not add JSON lifecycle files or dual-write.

## Invariants

- The Action Registry remains the only action execution entry.
- `ExecutionPlan` and the Authority Engine remain the only intent and grant
  evaluation path.
- One authority reservation has at most one execution run.
- Intent, authorization, dispatch, observation, validation, and outcome
  fingerprints must agree before state advances.
- Narrated execution cannot mark a run observed, within-envelope, or complete.
- Work claims coordinate responsibility but cannot authorize, cancel, orphan,
  or replay an already-dispatched run.
- Observations and validations are append-only; corrections add reconciliation
  truth rather than rewriting prior evidence.
- Secrets and raw opaque identities remain outside lifecycle state.

## Consequences

- Restart recovery can distinguish pre-dispatch authorization, possible
  effects, observation/validation gaps, committed outcomes, and unknown work.
- Phase 6D and 6E can add effect-boundary coverage through one observer seam and
  the existing repository contracts.
- Task 6C adds control-plane writes and storage for modern SQLite-v2 dispatches;
  accepted Phase 6A performance evidence remains the pre-instrumentation
  baseline for later comparison.
- Imported or retained legacy dispatches do not gain invented observations or
  lifecycle proof.

## Alternatives considered

### Replace ExecutionPlan with an unrelated intent type

Rejected. It would fork Registry/job compatibility and duplicate already sealed
authorization material.

### Store lifecycle records in a separate event database

Rejected. Atomic authority, dispatch, workspace revision, audit, bundle, and
recovery guarantees would be split across stores.

### Trust provider or model result summaries as observations

Rejected. Those sources can omit, misunderstand, or narrate effects that the
runtime did not observe.

### Add lifecycle files to JSON-v1

Rejected. JSON-v1 is a compatibility/migration input and must not gain new
Phase 6 truth or dual-write behavior.

## Verification

- `MCPS/Synapse-MCP/tests/test_phase6c_execution_lifecycle.py`
- retained authority, Registry, facade, background-job, Phase 4 state/migration,
  Phase 5 work/acceptance, full core, modern, inventory, output-contract, and
  capability-pack gates

## Migration and rollback

Migration `0006` is ordered, hashed, and additive for SQLite-v2 workspaces.
Canonical bundles include its three tables. Rollback follows the existing
State Store boundary: an activated workspace with post-migration writes is not
downgraded by deleting tables or switching to JSON-v1. Protocol rollback to the
frozen legacy projection does not erase lifecycle truth.
