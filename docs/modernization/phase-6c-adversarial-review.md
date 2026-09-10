# Phase 6C adversarial-review brief

## Checkpoint disposition

Task 6C's lifecycle-state and duplicate-dispatch checkpoint passed on
2026-09-10 after three review findings were corrected. This closes the Task 6C
checkpoint and permits Task 6D to begin; it is not a Phase 6 closure claim.

## Claims reviewed

1. One exact server-held authorization receipt advances one dispatch and its
   run; altered workspace, action, plan, grant revision, session, profile, or
   run bindings fail before lifecycle state changes.
2. One idempotency reservation creates at most one run under thread and process
   contention, and authorized, dispatched, or unknown work is not replayed.
3. Every run boundary is reconstructable after restart without consulting a
   work claim, including authorized, dispatch-started, observing,
   validation-pending, committed, unknown, and not-dispatched states.
4. Work-claim expiry cannot orphan finalization, and supervised resume creates
   a run only after the exact step-up is consumed.
5. Background continuation binding validates workspace, parent plan, effects,
   handler, receipt, dispatch, and run truth before mutating the durable job.
6. Provider, consumer, model, and legacy narration cannot establish effect
   truth; only runtime-observed or runtime-enforced observations participate in
   validation.
7. Observation and validation fingerprints, sequence identities, immutable
   rows, bundles, migration, and JSON-v1 refusal preserve the reviewed state
   boundary.

## Findings and corrections

### Exact receipt binding was incomplete

The pre-dispatch hook accepted the dispatch ID from an `AuthorizationReceipt`
without comparing the rest of the receipt with durable dispatch truth.
Lifecycle repository methods checked workspace, run, and grant revision but did
not consistently bind the origin action, plan, authority session, and profile.
An altered in-process receipt could therefore advance dispatch or lifecycle
state.

The repository now validates the complete persisted receipt binding before an
origin dispatch starts and before run observations or validations advance.
Continuation receipts retain their intentional child-action/plan distinction
while remaining bound to the same workspace, grant revision, session, profile,
dispatch, and run.

### Rejected background bindings could mutate unrelated jobs

`bind_background_job` wrote the execution-run ID into the job record before it
validated workspace, parent plan, and durable receipt truth. A rejected
cross-workspace or forged-run bind could leave the job poisoned even though no
authority continuation was committed.

Background binding now performs non-mutating job checks first, validates the
receipt against the locked authority transaction, and only then applies the
idempotent job/run binding. Negative tests prove rejected cross-workspace and
forged-run bindings leave the job's execution-run field empty.

### The focused gate expired with wall-clock time

The Phase 6C fixture froze grants around 2026-09-02 while three paths used the
real repository clock. On 2026-09-10 those tests failed with `grant_expired`
before reaching their lifecycle assertions. The fixture now captures the test
process's current UTC time once, preserving stable intra-test sequencing while
remaining valid on future dates.

## Verification

```text
22 Phase 6C lifecycle/adversarial tests passed
49 complete Phase 6 tests passed
60 authority-focused tests passed
27 background-focused tests passed
28 migration-focused tests passed
801 full core tests passed
16 official-SDK modern adapter tests passed
2 custom-adapter template tests passed
67 retained Phase 5 tests and all 8 acceptance verdict groups passed across 3 repetitions
Action inventory/output contracts/pack ownership current: 174/168/174
Compact surface current: 11 operations / 23,336 application bytes
3 default Codex operating skills and 2 shared references validate
```

The Phase 5 distribution gate used the documented build-only
`SYNAPSE_BUILD_PYTHON` and `SYNAPSE_BUILD_PYTHONPATH` overrides for this host's
split offline build prerequisites. Wheel and sdist installation plus 174-action
standard and 42-action core-only startup passed.

The Phase 6A performance check ran on a non-matching environment fingerprint,
so no relative comparison was accepted. Its absolute results remained visible:
the core-only cold-start p50 was 693.878 ms against the proposed 500 ms ceiling;
the other four fixtures passed their absolute ceilings, including 0.031 ms
Registry control p95. This retained baseline limitation is not hidden or
reclassified by the Task 6C checkpoint.

## Compatibility and residual boundary

- The Action Registry, Authority Engine, action identities/effects, eleven
  compact operations, modern-direct, frozen legacy, and JSON-v1 behavior are
  unchanged.
- No owned HTTP, local-output, child-process, browser, or provider observation
  coverage is claimed. Those effect boundaries begin in Tasks 6D and 6E.
- Generic MCP conformance remains the retained `partial_fail` classification;
  MCP Inspector and live Codex diagnostics were not rerun and remain optional.
- The checkpoint used fictional local workspaces and disabled external target
  traffic. It created no engagement or credential data.

## Verdict

`pass after corrective action`: receipt identity, background binding order,
state reconstruction, validation trust, concurrency, migration, and
compatibility survived the checkpoint after the three corrections above. Task
6D may begin. Phase 6 remains open through Task 6J.
