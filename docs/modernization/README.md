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
  proven by the six-action vertical slice

## Phase 2

- [Phase 1.1 truth-gate handoff](phase-1.1-handoff.md) — continuation-safe jobs,
  truthful crawler effects/output, and one execution envelope for targets,
  redirects, proxies, and partial/whole-scope selection
- [Correction-gate handoff](correction-gate-handoff.md) — Registry v2,
  credential concurrency, official-SDK spike, and local functional vertical;
  foundations are ready for a revised Phase 2
- [Input-schema keyword inventory](input-schema-keyword-inventory.md)
- [Capability-gap inventory](capability-gap-inventory.md)
- [Stage A Authority Engine design checkpoint](phase-2-stage-a.md) — the
  original draft is corrected by ADR-0009; Stage B must use effective
  multidimensional effects and configurable grant dimensions
- Crash-atomic scope and credential storage prerequisite — integrated before
  the Phase 1 Action Registry merge and covered by the combined Beta gate

## Architecture decisions

| ADR | Decision | Status |
| --- | --- | --- |
| [ADR-0001](adr/ADR-0001-generic-agents-operational-plane.md) | Generic agents as cognitive plane, Synapse as operational plane | Accepted |
| [ADR-0002](adr/ADR-0002-typed-core-action-registry.md) | Typed application core and Action Registry | Accepted |
| [ADR-0003](adr/ADR-0003-durable-authority-grants.md) | Durable Authority Grants | Proposed |
| [ADR-0004](adr/ADR-0004-mcp-compatibility-profiles.md) | Legacy and modern MCP compatibility profiles | Proposed |
| [ADR-0005](adr/ADR-0005-sqlite-artifact-store.md) | SQLite and a content-addressed artifact store | Proposed |
| [ADR-0006](adr/ADR-0006-context-revisions-budget-behaviour.md) | Context revisions and budget behaviour | Proposed |
| [ADR-0007](adr/ADR-0007-application-outcome-model-and-error-boundary.md) | Application outcome model and the protocol error boundary | Proposed |
| [ADR-0008](adr/ADR-0008-action-identity-and-packs.md) | Action identity and pack scheme | Proposed |
| [ADR-0009](adr/ADR-0009-registry-v2-correction-gate.md) | Registry v2 correction gate | Accepted |

## Cross-cutting pattern

`confirm=true` and `maxTokens` are the same defect in two subsystems:
caller-supplied values that the server accepts, validates, echoes, and does not
enforce. ADR-0003 fixes the authority case in Phase 2; ADR-0006 fixes the budget
case in Phase 4. Recording it once prevents them from being treated as
unrelated coincidences.

The modern spike confirms that protocol `input_required` can represent the
active no-dispatch state, but it intentionally implements neither durable
grants nor resume flows. `confirm=true` remains legacy-only authority.
