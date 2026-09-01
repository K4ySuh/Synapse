# Phase 6A adversarial-review brief

## Checkpoint disposition

Task 6A implementation and its prescribed local gates are complete. This brief
defines the first Phase 6 independent checkpoint; it is not an adversarial pass
marker and does not close Phase 6. Review commit `fix(phase6): close operational
work and recovery errata` before Task 6B changes Codex integration defaults.

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
bin/run-phase6-performance --check                   pass
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

## Known residuals

- Core-only cold-start baseline p50 is 792.572 ms against the proposed 500 ms
  ceiling; p95 is 875.567 ms against 900 ms. The baseline and check output keep
  the absolute miss visible and use a 20% matching-environment p95 ceiling.
- The `registryControlOverhead` fixture ends at output validation. It is the
  pre-instrumentation control for later Phase 6 comparison, not the future
  intent/observation/effect-validation measurement.
- Generic MCP conformance retains its Phase 3 `partial_fail` classification.
  MCP Inspector and live Codex behavior remain optional diagnostics outside
  Task 6A acceptance.
- Work-operation discovery exposes current v1 application schemas. The broader
  immutable Registry `CapabilityContract` belongs to Task 6F.

## Requested verdict

Return `pass` only if the eleven claims survive code and evidence review without
an unrecorded compatibility or safety gap. Otherwise return `fail` with the
smallest reproducible counterexample, affected invariant, and required follow-up
task. Do not issue a Phase 6 closure verdict at this checkpoint.
