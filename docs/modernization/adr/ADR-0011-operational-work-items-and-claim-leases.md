# ADR-0011: Operational work items and claim leases

- Status: Accepted
- Date: 2026-08-27
- Owners: Synapse architectural lead
- Applies from: Phase 5C
- Supersedes: None

## Context

Background jobs describe execution owned by a worker process. Opaque operation
handles describe an authority-gated request awaiting supervised continuation.
Neither represents an application-level objective that several agents can
claim, update, hand off, recover, and converge into one workspace.

Phase 5 needs that coordination state without adding an internal planner,
scheduler, secondary authority path, chat transcript store, or provider-specific
core behavior. A lost agent must not make an active or outcome-unknown execution
safe to repeat.

## Decision

Add protocol-independent work-item contracts and services under
`synapse_mcp.app.work_items`, backed only by the selected workspace's SQLite-v2
repository. Migration `0003_operational_work_items.sql` adds work items,
dependencies, claims, references, and append-only work-item events. Every
mutation commits with the workspace revision, change log, and audit event.
Canonical state bundles include all five tables.

A work item is distinct from a job. It records a bounded objective, optional
parent and dependencies, lifecycle status, role and capability-pack hints,
target/context selectors, completion contract, progress/result/blocker/handoff
summaries, unresolved gaps, workspace revisions, references, and optimistic
version. It does not store chain of thought or chat history.

Claims are separate rows so an exclusive item has exactly one active claimant
while an explicitly non-exclusive analysis item can retain several. Claim uses
one SQLite `BEGIN IMMEDIATE` transaction plus an expected work-item version.
Claim rows bind hashed trusted principal, authority-session, and optional
agent-run identity together with a non-authoritative worker label. Heartbeat
renews only a matching active claim. Every mutation requires the current
version and claim ID.

Lease expiry makes work reclaimable. Recovery expires stale claims, preserves
linked action/authority/dispatch/job/evidence/artifact/domain truth, records
whether reconciliation is required, and always publishes
`automaticReplay=false`. It never cancels, resumes, or re-dispatches linked
execution. A stale claimant cannot mutate terminal, blocked, handed-off, or
reclaimed work.

Dependency completion changes a downstream item from `planned` to `available`
once, in the same committed workspace revision as the final prerequisite.
Blocked and failed dependency states remain visible rather than being silently
converted into completion.

Modern compact keeps exactly eleven operations. `tasks.control` retains its
job `list`, `inspect`, `cancel`, and operation-handle `resume` behavior and adds
`work.*` discriminators with concise common linkage fields plus a typed
application-validated payload. `context.query` accepts work-item/claimant
filters and prioritizes the selected objective, parent/dependencies, delta,
execution reconciliation state, references, handoffs, gaps, and completion
contract inside the existing deterministic envelope budget.

An action may carry a separate `workItem`/`claimId` linkage object. The facade
validates the active claim, records the canonical effects and replay safety,
then uses the unchanged Registry, scope, authority, dispatch, and output path.
The linkage metadata is copied into `ExecutionContext` for attribution only;
it is not part of `AuthorizationIntent`, pack selection, effects, or grant
evaluation. Final action/decision/dispatch/job/result references are merged
back into the work item. An uncertain post-execution link returns
`execution_unknown` and requires reconciliation.

Existing JSON-v1 workspaces remain readable and otherwise compatible, but new
work-item operations return `work_items_require_sqlite_v2`; Synapse does not
create a parallel JSON coordination board or migrate an existing workspace
implicitly.

## Invariants

- Work-item, claim, dependency, reference, and handoff truth lives in the
  canonical SQLite-v2 workspace store.
- Coordination identity grants no scope, authority, pack access, credentials,
  or execution effects.
- Exclusive claim races have one winner; stale writes return current version
  and workspace revision.
- Lease expiry and client/process loss never replay linked execution.
- Active or unknown state-changing execution remains reconciliation-required.
- Jobs and operation handles retain their existing lifecycle and control path.
- Simple single-agent operations do not require work-item decomposition.
- The compact surface remains eleven operations and frozen legacy/direct action
  identity remains unchanged.

## Consequences

- Coordinators and specialists can share bounded objectives through durable
  workspace truth and resume after chat or process loss.
- Work-item inspection may show a newer linked job/dispatch state than the
  stored reference snapshot because those canonical tables remain authoritative.
- Coordination is available only after SQLite-v2 activation; this preserves the
  single-store rule and JSON-v1 rollback boundary.
- Work-item operations add no agent loop. Clients decide whether and how to
  decompose work.

## Alternatives considered

### Reuse background jobs

Jobs describe process execution and finalization. Using them as objectives
would conflate lease expiry with process ownership and encourage unsafe replay.

### Store a shared JSON task board

That would place claim truth outside the canonical revision/audit transaction
and make process races dependent on filesystem locking rather than State Store
CAS semantics.

### Let worker labels select grants or packs

Labels are caller-supplied coordination metadata. Giving them security meaning
would turn assignment into an authority bypass.

### Add a twelfth compact tool or an internal scheduler

Neither is needed. The existing task-control seam and external agent behavior
cover creation, claims, handoff, and recovery without expanding the top-level
surface or adding autonomous planning.

## Verification

- `MCPS/Synapse-MCP/tests/test_phase5c_work_items.py`
- Phase 3B compact facade gates
- Phase 4 migration, runtime, bundle, and context gates
- `bin/test --core`, `bin/test`, and `bin/test-modern`

The compact projection omits non-validating JSON Schema title, default, and
description annotations while preserving runtime defaults and validation. This
keeps the eleven-operation application and official-SDK wire surfaces within
the existing 24,834-byte ceiling.

## Migration and rollback

Opening an existing two-migration SQLite-v2 workspace applies migration `0003`
in place without changing its current workspace revision. Bundle import/export
preserves work-item rows and links. Protocol rollback remains separate from
state-engine rollback; any post-activation v2 write, including a work-item
write, keeps the existing rollback refusal boundary.
