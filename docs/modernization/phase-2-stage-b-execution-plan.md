# Phase 2 Stage B Execution Plan

Status: complete
Owner: local implementation agent
Started: 2026-08-09
Baseline: `Beta` at `873b56baa18e4a6c85f11a9fedfea217ab93700b`
Final adversarial closure: 2026-08-19, based on audited implementation
`937c7707a1f96bbf2f8b70b620fd5b6700020ced`; closure implementation
`0b17118693038436a85e388f8a99bd749e370832`

This is the durable execution plan for
`CODEX-TASK-SYNAPSE-PHASE-2-STAGE-B-AUTHORITY-INTEGRATION.md`. The operator
brief is input only and is not part of the implementation diff.

## Gate sequence

| Gate | Invariant | State |
|---|---|---|
| 0 | Clean baseline, complete path maps, fresh supported installs, frozen compatibility measurements | complete |
| 1 | Target credentials are resolved per outgoing origin; proxy credentials remain provider-confined | complete |
| 2 | One validated replay/effect coverage lattice is used everywhere | complete |
| 3 | Every job transition/finalization is revision-safe and exactly once | complete |
| 4 | Trusted runtime inputs and continuations are exact and server-authenticated | complete |
| 5 | Phase 2 limits have one explicit, accurately named budget meaning | complete |
| 6 | Authority, budgets, decisions, dispatches, and continuations persist atomically | complete |
| 7 | Registry policy is typed; authority profiles dispatch without caller confirmation; legacy is unchanged | complete |
| 8 | Trusted local operators can manage authority without model-executable self-granting tools | complete |
| 9 | All six migrated actions pass a real Registry authority walkthrough | complete |
| 10 | Guidance, ADRs, handoff, ledger, and product docs match demonstrated behavior | complete |

## Final adversarial closure addendum

The 2026-08-19 closure gate found three defects after the original Stage B
integration: official-SDK resume regenerated request identity, correlation was
part of approval identity and allowed an unknown-dispatch retry bypass, and a
background observer could recreate `returncode.txt` after finalization. The
correction added these completed gates without rewriting the published Stage B
history:

| Gate | Invariant | State |
|---|---|---|
| 11 | The official SDK token resumes through `ctx.request_state`; trusted state restores the original correlation/idempotency identity and dispatches once | complete |
| 12 | Canonical authorization identity excludes correlation/deadline metadata; idempotency conflicts and unresolved retries fail closed | complete |
| 13 | Process observation is pure; watchdog/polling finalization cannot recreate a cleaned runtime sidecar | complete |
| 14 | Focused, modern, contract, stress, legacy, CLI, compile/diff, and two consecutive full-suite gates pass; formal documents agree | complete |

The original task requested one commit per Stage B task, but published tasks
2–7 landed together in `937c770`. That historical deviation is recorded rather
than hidden by rewriting commits. The closure correction is the separate,
reviewable implementation commit `0b17118693038436a85e388f8a99bd749e370832`.

## Working decisions

- Preserve `legacy` as a profile-isolated compatibility path; authority-aware
  behavior is server-owned context, never action input.
- Continue an authorized cross-host crawl anonymously when the selected target
  credential does not cover the destination, and return a typed, secret-free
  credential-coverage observation. An explicitly multi-origin credential may
  be resolved again for each covered destination.
- Keep proxy credential scopes separate from assessment-target scopes and bind
  them to the exact provider origin.
- Use dispatch budgets for Phase 2. Network volume remains visible and bounded
  by action-specific plan inputs such as crawler `maxPages`, delays, redirect
  limits, and concurrency; Phase 2 will not mislabel one dispatch as one HTTP
  request.
- Use the existing workspace lock and crash-atomic JSON primitives; no database
  or transport-wide migration belongs in this stage.

## Verification discipline

For each gate: retain a failing reproduction, implement through the real
runtime seam, add adversarial tests, run focused tests, inspect the diff for
bypasses and secrets, then run the broader gate suite. Before the final verdict,
repeat supported installs and every validation command from the task in fresh
environments and compare frozen contract artifacts with the Gate 0 manifest.
