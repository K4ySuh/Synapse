# Phase 5 operational handoff

Phase 5 closes the capability-pack, shared operational-work, Codex methodology,
instruction/distribution, and operational-acceptance boundary. Synapse remains
the provider-neutral control plane; provider-specific configuration and
methodology remain package integration data outside application, policy, state,
and executor behavior.

## Acceptance

The canonical closure gate is fully offline:

```bash
bin/run-phase5-acceptance
```

It writes sanitized evidence to `docs/modernization/evidence/phase-5/`. Its
eight verdicts cover capability packs, real multi-process work state,
authority/execution linkage, compact/context budgets, direct and coordinated
operational workflows, installed cold start, and legacy rollback. The exact
method and thresholds are documented in
[phase-5-benchmark-method.md](phase-5-benchmark-method.md).

All fixtures are fictional and local. External target traffic is process-
blocked and no credential values or third-party providers are used. A Phase 5
pass proves the provider-neutral application/state contracts under concurrent
independent processes; it does not claim that one subscription can economically
simulate multiple model agents or that every MCP client is conformant.

`bin/run-phase5-codex-benchmark --run` remains an explicit, one-repetition live
Codex diagnostic for operators who need it. Its coordinator and specialists
default to Luna/low with bounded retained tool output; multiple repetitions or
a non-default profile require `--allow-high-usage`. It is not an acceptance
dependency.

## Operating boundary

Use direct compact operations for simple inspection, bounded context, one small
action, job polling, or reporting. Decompose only independent or dependency-
ordered objectives that benefit from real concurrent ownership. Multiple
operators, accounts, or clients coordinate through durable Synapse work items;
one operator is never required to spawn multiple agents.

Durable work items carry objective, scope/context bounds, completion contract,
claims, references, gaps, and next work; they never carry execution authority.
Clients recover from SQLite-v2 workspace truth. After a lost worker or expired
claim, inspect linked operation/job state before new execution. Active or
outcome-unknown state is never automatically replayed. Reporting waits for
dependencies and renders workspace evidence rather than chat transcripts.

## Compatibility and rollback

The standard modern runtime still assembles six built-in packs and 174 action
IDs in canonical order. Core-only starts with 42 actions without importing
unselected implementations. `modern-compact` remains the Codex default with
eleven operations; `modern-direct` and the frozen 174-tool legacy launcher
remain available.

Protocol rollback is independent of workspace state: select the legacy profile
or launcher without changing SQLite-v2 truth. JSON-v1 remains the explicit
compatibility and migration source for existing workspaces. Do not attempt a
state-engine rollback after v2-only revisions; retain v2 as authoritative and
use verified bundle export/import or reviewed forward recovery. Keep the pre-
cutover JSON-v1 snapshot until the workspace-specific retention decision.

For installed rollback/configuration profiles:

```bash
synapse-codex-assets --config legacy
synapse-codex-assets --config modern-direct
```

## Residuals

- Generic MCP conformance remains the retained Phase 3 `partial_fail`; it was
  not rerun or promoted by this gate.
- MCP Inspector and live model/client diagnostics remain optional.
- Repository-local modern readiness still requires operator-owned private
  identity bindings, request-state keyring, and state paths. Distribution and
  acceptance gates self-provision isolated equivalents.

Post-closure Phase 6A audit identified one exact core documentation-host
allowlist failure and one stale final prompt measurement. The allowlist now
recognizes the official documentation host already cited by the benchmark
method. The Phase 5E checkpoint remains 5,941 bytes/78.5%; the Phase 5F shipped
prompt is correctly recorded as 6,289 bytes/77.2%. These are explicit errata,
not retroactive changes to the captured Phase 5 acceptance evidence.

The deferred complete-phase adversarial review passed on 2026-08-30. It found
no open Phase 5 contract, authority, state, evidence, packaging, or rollback
inconsistency beyond the explicit residuals above. The review used the offline
closure gate and repository compatibility suites; it did not consume or claim
a live model/client result.

## Closure marker

```text
PHASE_5_PASS
```
