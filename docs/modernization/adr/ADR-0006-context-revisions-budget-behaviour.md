# ADR-0006: Context revisions and budget behaviour

- Status: Proposed
- Date: 2026-07-28
- Owners: Synapse architectural lead
- Applies from: Phase 4 after acceptance
- Supersedes: Fixed `workspace.prepare_target_context` view in the modern application path

## Context

`workspace.prepare_target_context` currently returns a fixed dictionary selected
from workspace entities. It accepts and echoes `maxTokens`, whose schema minimum
is 100, but does not use the value to bound the serialized response. P0-3 proved
this on a populated workspace created from sitemap JSON with `hosts[].urls[]`,
containing 2 endpoints and 1 parameter.

Across budgets 100, 400, 1,500, 6,000, and 20,000, the response remains
4,024–4,026 characters (about 1,006 tokens using characters divided by four).
No truncation, omission, or gap field appears. The current view also has no
transactional revision cursor for deterministic deltas.

## Decision

Replace the fixed `prepare_target_context` view with a revision-aware, budgeted `context.query` service returning typed sections, and make the token budget an enforced contract with explicit machine-readable omission records.

## Invariants

- **Baseline (measured at `fc15cff`): `maxTokens` is accepted, schema-validated at a minimum of 100, echoed back, and not enforced — response size is invariant across a 200× budget range and no truncation, omission, or gap field exists. Adherence is 0%. Phase 4 is therefore a behaviour change, not a refactor.**
- Every response respects the requested budget or returns a machine-readable omission/truncation record.
- Scope, authority, and contradiction warnings are never silently truncated.
- Confirmed facts, candidates, contradictions, gaps, and recommendations are separate fields; recommendations never invoke actions.
- `sinceRevision` is monotonic per workspace and committed transactionally with the change it describes.
- Exact relational retrieval precedes semantic retrieval.

## Alternatives considered

### Keep the fixed context view and advisory `maxTokens`

- Benefits: Preserves current response shape and implementation simplicity.
- Costs: Callers cannot rely on budgets or detect overruns, and deterministic
  deltas remain unavailable.
- Reason rejected/deferred: It fails the directive KPI and treats an echoed
  value as an unenforced hint.

### Truncate the serialized JSON string at the requested size

- Benefits: Simple hard size bound.
- Costs: Can produce invalid or semantically incomplete structures and silently
  remove safety-critical warnings.
- Reason rejected/deferred: Budgeting must operate on typed sections with
  explicit omissions.

### Perform semantic retrieval before exact state retrieval

- Benefits: Potentially compact, relevance-ranked context.
- Costs: Can miss exact scope, authority, contradiction, task, or evidence
  state and makes results harder to reproduce.
- Reason rejected/deferred: Exact operational truth must precede derived
  semantic retrieval.

### Require clients to trim the response

- Benefits: No server-side compiler changes.
- Costs: Every client implements different omission behavior and the server
  cannot state what was excluded.
- Reason rejected/deferred: Budget adherence is an application contract.

## Consequences

- Positive: Callers receive bounded typed context, explicit omissions, and
  deterministic revision deltas.
- Negative: Phase 4 intentionally changes behavior and requires prioritization
  rules for sections and warnings.
- Operational: Clients can request deltas and follow evidence references instead
  of receiving unbounded artifacts.
- Security: Scope, authority, and contradiction warnings receive protected
  budget treatment and cannot disappear silently.
- Compatibility: The legacy fixed view remains available through the legacy
  profile while the modern service establishes its contract.

## Migration and rollback

Introduce `context.query` beside the legacy view. Define typed sections,
priority rules, token accounting, omission records, and transactional workspace
revisions before switching modern clients. Re-run the populated P0-3 benchmark
at every stage. Rollback returns modern callers to the legacy fixed view while
preserving revision data already committed; it must not claim budget compliance
for legacy responses.

## Verification

- Keep the P0-3 populated context benchmark as the before measurement.
- Add tests at the minimum, boundary, and oversized budgets that validate either
  adherence or explicit machine-readable omissions.
- Verify protected warnings survive constrained budgets.
- Test monotonic `sinceRevision`, transactional updates, repeatable deltas, and
  exact-before-semantic retrieval.
- Measure the Phase 4 exit criterion as 100% budget adherence with omissions
  reported.
