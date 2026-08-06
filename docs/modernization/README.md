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
  program gate is PASS and Stage B is cleared
- [Contract-change ledger](contract-changes.md)

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

## Cross-cutting pattern

`confirm=true` and `maxTokens` are the same defect in two subsystems:
caller-supplied values that the server accepts, validates, echoes, and does not
enforce. ADR-0003 fixes the authority case in Phase 2; ADR-0006 fixes the budget
case in Phase 4. Recording it once prevents them from being treated as
unrelated coincidences.
