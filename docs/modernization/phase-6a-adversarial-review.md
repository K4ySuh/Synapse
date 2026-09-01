# Phase 6A adversarial-review brief

## Checkpoint disposition

Task 6A implementation and its prescribed local gates are complete. The
independent checkpoint passed on 2026-09-01 after one review-discovered defect
was corrected. This verdict closes Task 6A only; it does not close Phase 6.

## Claims to challenge

1. A work-linked action is bound before dispatch, and result or unknown
   finalization remains possible after the originating claim expires.
2. No planned, started, approval-pending, active, or outcome-unknown bound
   execution can be replayed automatically after crash, recovery, replan, or a
   competing claim.
3. `success_required` cannot leave downstream work permanently planned after a
   dependency fails or is cancelled. `terminal_required` cannot become
   available before every dependency is terminal.
4. Blocked resolution is a typed optimistic mutation. It can cancel or replan,
   cannot fake completion, and propagates cancellation to direct dependents in
   the same workspace revision.
5. Expired claims do not appear active or satisfy worker filters at read time,
   but a read does not mutate canonical recovery state.
6. Work-list cursors neither duplicate nor skip the original 250-item traversal
   and cannot be reused with changed filters or detail mode. Summary pages stay
   bounded and full claims/references/attempts require explicit detail.
7. A fresh facade client can discover work schemas without a workspace, while
   discovery grants neither scope nor execution authority and adds no compact
   top-level operation.
8. Every mutation and linked execution gives the caller the current work-item
   version needed for the next CAS step.
9. Migration `0005` upgrades a 0001–0004 workspace to explicit compatible
   dependency semantics without dual-write, synthetic provenance, or JSON-v1
   activation.
10. Phase 5 historical evidence remains historical: the official-host test and
    current prompt measurements are corrected only as post-closure errata.
11. The performance runner measures what it names, performs no provider or
    external target I/O, records a sufficient environment fingerprint, exposes
    absolute failures, and accepts a matching baseline only within 20% p95.

## Evidence available to the reviewer

```text
bin/test --core                                      767 passed
bin/test-modern                                      16 passed
bin/test --template                                  2 passed
Phase 6A unittest discovery                          16 passed
Phase 5 unittest discovery                           66 passed
bin/run-phase5-acceptance                            pass, 3 repetitions
bin/run-phase6-performance --check                   pass (corrected v3 method)
bin/generate-action-inventory --check                174 current
bin/generate-action-output-contracts --check         168 current
bin/generate-capability-pack-ownership --check       174 / 6 current
bin/measure-phase3-surfaces --check                  11 / 23,336 bytes
bin/validate-codex-skills --check                    8 / 2 current
```

The Phase 5 distribution gate required its documented build-interpreter
override on this host because offline build prerequisites are split between the
project and system Python environments. The gate itself was unchanged and
passed wheel/sdist installation plus standard/core startup. No live model,
external target, credential, or provider traffic was used.

## Compatibility boundary

- one canonical Action Registry, policy decision, execution, outcome, and
  evidence path;
- 174 standard actions, 42 core-only actions, six standard packs, and eleven
  compact operations;
- retained modern-direct, frozen legacy, and explicit JSON-v1 migration;
- no planner, agent loop, sub-agent scheduler, parallel state store, or
  provider-specific core behavior;
- no observed-effect, complete containment, or complete Phase 6 claim.

## Adversarial finding and correction

The original single-run performance gate failed twice from the unchanged
review tree on the same recorded environment. Warm p95 variance exceeded 20%
even though the warm absolute ceilings passed, so claim 11 did not initially
survive review. Median-of-three v2 still amplified scheduler jitter for the
sub-millisecond Registry and short work-list fixtures.

The corrected v3 method preserves the v1/v2 evidence, runs three complete
repetitions, batches warm operations while reporting per-operation latency,
records each repetition, expands the environment fingerprint, and binds
relative comparison to a versioned fixture. Three focused evaluator tests and
an immediate exact baseline replay passed. No application behavior or accepted
20% relative-p95 rule changed.

## Known residuals

- The accepted v3 capture misses standard cold-start p50 and core-only p50/p95
  absolute ceilings. The exact replay continued to expose the core-only p50
  miss while passing every matching-method relative p95 comparison.
- The `registryControlOverhead` fixture ends at output validation. It is the
  pre-instrumentation control for later Phase 6 comparison, not the future
  intent/observation/effect-validation measurement.
- Generic MCP conformance retains its Phase 3 `partial_fail` classification.
  MCP Inspector and live Codex behavior remain optional diagnostics outside
  Task 6A acceptance.
- Work-operation discovery exposes current v1 application schemas. The broader
  immutable Registry `CapabilityContract` belongs to Task 6F.

## Verdict

`pass after corrective action`: claims 1–10 passed code and evidence review;
claim 11 failed with the reproducible unchanged-tree counterexample above and
passed after the v3 correction. No unrecorded compatibility or safety gap
remains at the Task 6A boundary. This is not a Phase 6 closure verdict.
