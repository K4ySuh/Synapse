# ADR-0003: Durable Authority Grants

- Status: Accepted
- Date: 2026-07-28
- Owners: Synapse architectural lead
- Applies from: Phase 2 after acceptance and prerequisite completion
- Supersedes: Caller-asserted confirmation in the modern application path

## Context

The legacy surface exposes a `confirm` input property on 47 tools. The server
accepts caller-provided `confirm=true` as the execution gate for active,
credential, third-party, and destructive-local operations. The wire taxonomy
already distinguishes approval-required outcomes (`-32001`, 10 uses) from scope
denials (`-32002`, 8 uses), so scope and execution authority are observably
separate even though approval itself is caller asserted.

The P0-3 timeout-recovery workflow records that an uncertain client result must
not create a second job. Credential operations use IDs, but current redaction of
long values retains their first four and last four characters; the committed
legacy credential fixture records `CANA...b2c3`. A tracked Phase 0 integrity
prerequisite must land before Phase 2 persists authority state.

## Decision

Replace caller-asserted `confirm=true` in the new application path with durable,
server-evaluated Authority Grants bound to canonical action IDs and
request-effective multidimensional effects. Grants carry scope digest, allowed
actions and methods, traffic destinations, local write domains, local/remote
state-change permissions, credential/provider restrictions, configurable
dispatch-total, dispatch-rate-window, and active-dispatch budgets, expiry, and
revocation. `confirm=true` remains
accepted only behind the explicitly selected legacy profile and is marked
distinctly in audit records.

One budget unit authorizes one canonical action dispatch. These counters are not
HTTP-request, provider-request, redirect-hop, or page counters. Action-specific
network volume remains an explicit input (for example crawler page and redirect
limits) sealed by the execution-plan fingerprint. A missing budget limit means
unbounded for that dimension; there are no hidden defaults or product ceilings.
The operator may explicitly enlarge a grant within authorized scope. Any future
network-request budget requires shared HTTP/provider instrumentation rather than
relabeling dispatch counters. A grant cannot create a capability that the
adapter or repository policy does not currently expose; those are tracked
capability gaps, not silently encoded permanent grant denials.

Phase 1.1 supplies the comparison operand: a sealed `AuthorizationIntent` with
`TargetEnvelope`, provider route, local-output envelope, methods, credential
references, effective effects, input/plan fingerprints, and continuation
lineage. A grant must compare the explicit target selection as well as
`scopeDigest`: exact delegation never expands merely because the target belongs
to workspace scope, while `entireWorkspaceScope=true` is covered only by an
explicitly broad human grant.

Polling/finalization of already dispatched background work is a continuation of
that dispatch, not a new authority request. The creation-time plan records the
originating action, workspace, scope digest/snapshot, target/effect envelope,
provider, correlation, job/finalizer identity, and bound local paths. Phase 2
re-evaluates expiry/revocation
before new active dispatch or an explicit resume; it must not rewrite the truth
of work already dispatched or demand approval for each observational poll.

## Invariants

- Model-supplied data can never expand scope, authority, risk ceiling, credential access, third-party access, or budgets.
- The evaluated effect set is the request-effective `ActionEffects`, with the
  descriptor maximum used conservatively when resolution is uncertain.
- Supported modes are `observe`, `supervised`, and `full_delegated`; each
  dimension, including methods, dispatch totals, dispatch-rate windows, and
  active dispatches, is operator-configured.
- **Scope authorization and execution authorization remain separate decisions, and this separation already exists observably in the shipped wire protocol: `-32002` denotes scope denial (8 uses, all scope-related) and `-32001` denotes authorization/approval required (10 uses). Phase 2 reason codes must map onto this taxonomy or record an explicit decision to supersede it. Collapsing both into one generic denial is a regression in observable safety semantics even if every test passes.**
- Approval-required is a normal resumable outcome, not a protocol error.
- A state-changing dispatch in `dispatched` or `unknown` is never automatically replayed. The P0-3 workflow-06 benchmark is the standing regression guard.
- Credentials are referenced by ID and resolved at dispatch; secret values never enter descriptors, audit summaries, or agent-facing results.
- Grant coverage compares exact/whole-scope remote targets, redirect expansion,
  provider/proxy infrastructure, and exact local outputs as separate dimensions.
- Continuations cannot widen targets/effects and finalization is single-
  application; polling a covered dispatched job does not consume a second
  action approval or dispatch budget.
- **Prerequisite:** the Phase 0 integrity prerequisite must land before authority state is persisted.

## Alternatives considered

### Keep `confirm=true` as the modern authority mechanism

- Benefits: Preserves the current call shape and avoids new persisted state.
- Costs: Lets caller-controlled data assert its own authority and cannot express
  expiry, revocation, budgets, or bounded delegation.
- Reason rejected/deferred: It validates intent syntax but does not enforce
  server-held authority.

### Use process-local or one-shot approval flags

- Benefits: Smaller implementation and no durable grant repository.
- Costs: Cannot support restart recovery, revocation history, or reliable audit
  linkage.
- Reason rejected/deferred: Authority must survive and explain task recovery.

### Merge scope and execution approval into one decision

- Benefits: One policy result and fewer concepts for clients.
- Costs: Erases the existing safety distinction and makes denial remediation
  ambiguous.
- Reason rejected/deferred: It would regress observable semantics and weaken
  policy reasoning.

## Consequences

- Positive: Authority becomes server evaluated, bounded, expiring, revocable,
  and auditable.
- Negative: Phase 2 adds durable policy state, resumable approval outcomes, and
  migration complexity.
- Operational: Legacy callers may explicitly select the legacy profile while
  modern callers handle approval-required as resumable state.
- Security: Caller input can request but cannot expand authority; credentials
  remain references resolved only at dispatch.
- Compatibility: Legacy `confirm=true` behavior remains available and is
  distinguishable in audit records.

## Migration and rollback

Do not persist grants until the stated prerequisite is complete. Introduce grant
evaluation beside the legacy profile, bind decisions to canonical actions and
scope state, and migrate selected actions only after denial/recovery tests pass.
Rollback selects the legacy profile and stops new grant dispatches while
retaining grant and audit records for explanation. Dispatches in `dispatched` or
`unknown` remain non-replayable through migration and rollback.

## Verification

- Test that model-supplied fields cannot expand any grant dimension.
- Preserve the `-32001`/`-32002` distinction or record an explicit superseding
  decision.
- Exercise expiry, revocation, scope digest changes, risk ceilings, credential
  restrictions, effective effects, methods, dispatch totals,
  dispatch-rate-window limits, active-dispatch limits, and third-party routes
  before dispatch.
- Keep the P0-3 workflow-06 duplicate-dispatch benchmark green.
- Verify that descriptors, audit summaries, and agent-facing results contain
  credential IDs rather than secret values.
- Require completion of the tracked prerequisite at the Phase 2 gate.
