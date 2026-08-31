# Synapse Modernization

This directory records the reviewed baseline and durable architecture decisions
for the staged Synapse modernization. The reviewed product baseline is commit
`099ba1aec4873b3ac08ffbecd82a45c06753880f`; Phase 0 measurements and
compatibility evidence build on that immutable reference.

## Baseline

- [Reproducible baseline](baseline.md)
- [Phase 0 handoff](phase-0-handoff.md)

## Phase 1

- [Stage A design checkpoint](phase-1-stage-a.md) — approved; the Phase 0
  program gate is PASS
- [Stage B task brief](phase-1-stage-b-tasks.md) — the ordered Codex
  implementation spec for the Action Registry and six-action slice
- [Stage B review brief](phase-1-stage-b-review-brief.md) — the independent
  adversarial-review gate
- [Stage B handoff](phase-1-stage-b-handoff.md) — Action Registry and the
  six-action vertical slice landed; gate PASS (2026-08-07)
- [Contract-change ledger](contract-changes.md)
- [Action migration pattern](action-migration-pattern.md) — contributor guide
  preserved as the Phase 1 historical pattern

## Phase 2

Phase 2 is complete. Its temporary design, execution, status, inventory, and
handoff documents were removed after closure; the original local workbench plan
is retained outside this tracked directory. Durable decisions remain in
[ADR-0003](adr/ADR-0003-durable-authority-grants.md),
[ADR-0009](adr/ADR-0009-registry-v2-correction-gate.md), the implementation,
tests, and the shared [changelog](../../CHANGELOG.md).

## Phase 3

- [Execution plan](phase-3-plan.md) — strict Session A–D sequence
- [Running status](phase-3-status.md) — exact Session 3A–3D gate evidence and
  Codex-only closure amendment
- [Benchmark method](phase-3-benchmark-method.md) — frozen corpus, metrics, and
  tolerances
- [Interoperability handoff](phase-3-handoff.md) — adopted Codex default,
  reproducible gate, residuals, and rollback
- [Machine-readable Phase 3 evidence](evidence/phase-3/) — client matrix,
  objective-agent and exact transport/safety results, payload/read results,
  conformance, and security gates
- [Canonical action migration guide](action-migration-guide.md) — current
  bounded pack-batch and manifest procedure

## Phase 4

- [State and context handoff](phase-4-handoff.md) — v2 default for new
  workspaces, explicit existing-workspace migration, recovery procedures, and
  the reproducible offline acceptance gate
- [Machine-readable Phase 4 evidence](evidence/phase-4/) — sanitized
  migration/recovery/context, environment, transport, Inspector, and test
  measurements

## Phase 5

- [Implementation status](phase-5-status.md) — ordered 5A–5F progress and
  focused gate evidence
- [Codex distribution and instruction architecture](phase-5-distribution.md) —
  scoped repository policy, packaged operational prompt, installed skills, and
  standard/core/direct configuration
- [Operational benchmark method](phase-5-benchmark-method.md) — fictional
  provider-neutral deterministic corpus, bounded Luna/low optional live client
  diagnostic, thresholds, evidence hygiene, and retained baselines
- [Phase 5 handoff](phase-5-handoff.md) — acceptance, operating boundary,
  compatibility, residuals, and rollback closure
- [Machine-readable Phase 5 evidence](evidence/phase-5/) — sanitized
  provider-neutral aggregate acceptance results
- [Capability-pack ownership map](capability-pack-ownership.json) — checked
  single-owner assignment for all 174 built-in actions
- [ADR-0010](adr/ADR-0010-capability-pack-lifecycle.md) — deterministic,
  frozen, high-level capability-pack assembly over the one Action Registry

## Phase 6

- [Implementation status](phase-6-status.md) — resumable Task 6A slices and
  exact focused verification; no Phase 6 closure claim

## Architecture decisions

| ADR | Decision | Status |
| --- | --- | --- |
| [ADR-0001](adr/ADR-0001-generic-agents-operational-plane.md) | Generic agents as cognitive plane, Synapse as operational plane | Accepted |
| [ADR-0002](adr/ADR-0002-typed-core-action-registry.md) | Typed application core and Action Registry | Accepted |
| [ADR-0003](adr/ADR-0003-durable-authority-grants.md) | Durable Authority Grants | Accepted |
| [ADR-0004](adr/ADR-0004-mcp-compatibility-profiles.md) | Legacy and modern MCP compatibility profiles | Accepted |
| [ADR-0005](adr/ADR-0005-sqlite-artifact-store.md) | SQLite and a content-addressed artifact store | Accepted |
| [ADR-0006](adr/ADR-0006-context-revisions-budget-behaviour.md) | Context revisions and budget behaviour | Accepted |
| [ADR-0007](adr/ADR-0007-application-outcome-model-and-error-boundary.md) | Application outcome model and the protocol error boundary | Proposed |
| [ADR-0008](adr/ADR-0008-action-identity-and-packs.md) | Action identity and pack scheme | Proposed |
| [ADR-0009](adr/ADR-0009-registry-v2-correction-gate.md) | Registry v2 correction gate | Accepted |
| [ADR-0010](adr/ADR-0010-capability-pack-lifecycle.md) | Deterministic high-level capability-pack lifecycle | Accepted |
| [ADR-0011](adr/ADR-0011-operational-work-items-and-claim-leases.md) | Durable operational work items and claim leases | Accepted |

## Cross-cutting pattern

`confirm=true` and `maxTokens` are the same defect in two subsystems:
caller-supplied values that the server accepts, validates, echoes, and does not
enforce. ADR-0003 fixes the authority case in Phase 2; ADR-0006 fixes the budget
case in Phase 4. Recording it once prevents them from being treated as
unrelated coincidences.

The modern profile evaluates server-held grants through the Registry. It uses
protocol `input_required` when negotiated and a typed opaque operation handle
plus `tasks.control` on compatible older revisions. `confirm=true` remains
legacy-only authority.
