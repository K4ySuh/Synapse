# ADR-0006: Context revisions and budget behaviour

- Status: Accepted
- Date: 2026-08-24
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

Add a transport-independent, revision-aware, budgeted `context.query`
application service with closed input and output models. Modern compact and
direct surfaces use the new service. Frozen legacy
`workspace.prepare_target_context` retains its existing schema and advisory
behavior.

The modern input is `workspaceId`, `intent`, `targets[]`, optional
`entityTypes[]`, optional `sinceRevision`, `maxTokens`, and
`includeEvidenceSummaries`. During transition, compact `target` and `purpose`
are deprecated aliases normalized before the service boundary.

The provider-neutral default counter is `utf8_bytes_v1`: one measured unit per
byte of the final canonical UTF-8 serialized facade envelope. This intentionally
conservative upper bound is deterministic and does not claim parity with a
provider tokenizer. Results report requested and used units, counter identity,
and status. A future injected precise counter may replace only accounting, not
retrieval or packing semantics.

Packing order is fixed: protected scope/authority/contradiction/revision
warnings, confirmed facts, coverage gaps, active tasks and recent actions,
candidates, non-mandatory recommendations, then optional evidence summaries.
Stable identities, priority scores, and lexical tie-breakers make the same
query at the same revision byte-repeatable. Every excluded section or item has
a typed omission reason, count, and safe continuation or resource link.

## Invariants

- **Baseline (measured at `fc15cff`): `maxTokens` is accepted, schema-validated at a minimum of 100, echoed back, and not enforced — response size is invariant across a 200× budget range and no truncation, omission, or gap field exists. Adherence is 0%. Phase 4 is therefore a behaviour change, not a refactor.**
- Every response respects the requested budget or returns a machine-readable omission/truncation record.
- Scope, authority, and contradiction warnings are never silently truncated.
- Confirmed facts, candidates, contradictions, gaps, and recommendations are separate fields; recommendations never invoke actions.
- `sinceRevision` is monotonic per workspace and committed transactionally with the change it describes.
- Exact relational retrieval precedes semantic retrieval.
- One consistent repository snapshot supplies the current revision and every
  returned section. The budget applies to the final canonical facade payload,
  including its fixed-point budget metadata and omission records.
- If the protected envelope cannot fit, return a closed `budget_too_small`
  result with the measured required minimum; never drop a warning, truncate a
  JSON string, or substitute a generic omission.
- `sinceRevision=N` returns changes in `(N, currentRevision]`. A future cursor
  is invalid. A cursor older than retained change-log coverage sets
  `fullRefreshRequired=true` rather than fabricating a partial delta.
- Context-visible domain state, relations, its monotonic revision, change-log
  rows, and audit event commit in one transaction. A rollback exposes none of
  them.
- Large evidence is represented by workspace-bound opaque resource links, not
  embedded artifact bodies.
- Phase 4 adds neither embeddings nor semantic/vector storage.

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
  action contract while the modern service enforces the new contract. Protocol
  selection does not change repository revisions or store authority.

## Migration and rollback

Introduce `context.query` beside the legacy view after State Store v2 is
authoritative under concurrency and crash tests. Define closed sections,
priority rules, counter accounting, omission records, protected-envelope
behavior, and transactional workspace revisions before switching modern
clients. Re-run the populated P0-3 benchmark at every stage. A modern facade
rollback may temporarily map callers to the legacy fixed view while preserving
committed revisions, but that view must never claim budget or delta compliance.

## Verification

- Keep the P0-3 populated context benchmark as the before measurement.
- Add tests at the minimum, boundary, and oversized budgets that validate either
  adherence or explicit machine-readable omissions.
- Verify protected warnings survive constrained budgets.
- Test monotonic `sinceRevision`, transactional updates, repeatable deltas, and
  exact-before-semantic retrieval.
- Measure the Phase 4 exit criterion as 100% budget adherence with omissions
  reported.
- Exercise exact-fit, one-unit-under, empty/huge workspaces, Unicode, large
  evidence, many contradictions, future cursors, pruned cursors, process
  restart, and rolled-back writes.
- Validate every modern result against its published closed schema and keep the
  compact official-SDK wire payload below 24,834 bytes.
