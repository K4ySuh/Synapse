# Synapse Modernization

This directory keeps durable decisions and current migration guidance. Closed
phase handoffs, acceptance runners, and benchmark artifacts are not active
development instructions.

- [Action migration guide](action-migration-guide.md)
- [Contract-change ledger](contract-changes.md)
- [Capability-pack ownership map](capability-pack-ownership.json)
- [Current Phase 6 status](phase-6-status.md)
- [Operations and recovery](../Operations.md)

The frozen baseline and Stage A checkpoint remain only because inventory and
compatibility checks reference them. Service-level regression tests remain in
the test suite even when their original filenames mention a completed phase.

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
| [ADR-0012](adr/ADR-0012-single-agent-codex-default.md) | Single-agent Codex default over a multi-consumer core | Accepted |
| [ADR-0013](adr/ADR-0013-observed-effect-execution-lifecycle.md) | Observed-effect execution lifecycle over the canonical dispatch path | Accepted |

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
