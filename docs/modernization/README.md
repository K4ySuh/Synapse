# Synapse Modernization

This directory keeps durable decisions and current migration guidance. Closed
phase handoffs, acceptance runners, and benchmark artifacts are not active
development instructions.

- [Action migration guide](action-migration-guide.md)
- [Contract-change ledger](contract-changes.md)
- [Saved-data integration convention](../Integration-Convention.md)
- [Capability-pack ownership map](capability-pack-ownership.json)
- [Current Phase 6 status](phase-6-status.md)
- [Phase 6 checkpoint ledger](phase-6-checkpoints.md)
- [Operations and recovery](../Operations.md)

The frozen baseline and Stage A checkpoint remain only because inventory and
compatibility checks reference them. Service-level regression tests remain in
the test suite even when their original filenames mention a completed phase.

## Phase 6 Beta completion roadmap

Tasks 6A–6D are implemented. The remaining work follows the serial 6R0–6R7
sequence; [status](phase-6-status.md) records the current boundary and the
[checkpoint ledger](phase-6-checkpoints.md) records resumable progress.
Completed-phase acceptance and benchmark runners remain retired.

| Task | Deliverable | Depends on | Checkpoints |
| --- | --- | --- | --- |
| 6R0 | Rebaseline the completion contract and retain the completed clock repair | Reviewed Beta | 6R0.1–6R0.2 |
| 6R1 | Correct evidence ownership and transactional entity merging | 6R0 | 6R1.1–6R1.3 |
| 6R2 | Make authority and lifecycle persistence incremental | 6R0 | 6R2.1–6R2.3 |
| 6R3 | Publish a versioned contribution contract on existing ingestion | 6R1 | 6R3.1–6R3.3 |
| 6R4 | Deliver canonical prompt and selected skills through modern MCP | 6R0; 6R3 for final references | 6R4.1–6R4.3 |
| 6R5 | Bound recovery/context and preserve failure-path observations | 6R2 | 6R5.1–6R5.3 |
| 6R6 | Prove one passive integration pilot and migration convention | 6R3, 6R4 | 6R6.1–6R6.2 |
| 6R7 | Run final integration, compatibility, and Beta handoff checks | 6R1–6R6 | 6R7.1–6R7.3 |

The revised disposition of earlier Phase 6 tasks is:

| Earlier task | Revised disposition |
| --- | --- |
| 6A reliability/performance | Preserve its improvements; 6R1/6R2 address confirmed defects. Retired benchmark runners stay retired. |
| 6B single-agent default | Preserve; 6R4 completes modern guidance and client model preference documentation. |
| 6C lifecycle contracts/storage | Preserve receipt, job, and clock corrections; 6R5 completes bounded recovery. |
| 6D synchronous observation | Preserve implemented owned-boundary coverage; 6R5 reviews failure-path telemetry. |
| 6E background/browser/provider observation | Retain run/job linkage; defer comprehensive observer and provider coverage. |
| 6F capability/work contracts | Reuse Registry and work contracts; 6R3 prioritizes the contribution contract. |
| 6G MCP compatibility | Verify the actual supported client at 6R7; avoid a speculative SDK rewrite. |
| 6H provenance/taint/invalidation | Repair precise evidence attribution in 6R1; defer generalized taint/invalidation. |
| 6I telemetry/counterfactual evaluation | Keep bounded practical measurements; defer counterfactual evaluation. |
| 6J final acceptance | Use current service checks and a bounded 6R7 client exercise; do not restore historical gates. |

Daybreak is a preferred operator-selected model for the eventual direct-client
exercise, not a Synapse core requirement or evidence that a Codex host/protocol
combination is supported. That compatibility claim requires an actual recorded
client check at 6R7.

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
