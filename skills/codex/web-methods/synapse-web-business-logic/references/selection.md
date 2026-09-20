# Business logic procedure

## Select this method

Select `synapse-web-business-logic` when the current question concerns a
workflow precondition, state transition, step ordering, replay/idempotency,
quantity or rate invariant, cross-channel assumption, concurrency window, or
another application-specific rule. Use access-control when the decisive issue
is actor permission and an input family when parser interpretation is central.

Apply the common contract at
`synapse://guidance/skills/synapse-web-pentesting/references/method-contract.md`.
For native skills installed beside the default profile, open
`synapse-web-pentesting/references/method-contract.md` under the same skill root.

## Required context

Recover the actor and tenant, stable workflow subject, current and expected
state, allowed transitions, preconditions, ordering and timing assumptions,
quantity/rate/value rules, canonical request/response and state evidence IDs,
baseline, and observable business effect. Identify authoritative state,
idempotency or replay keys, asynchronous workers, external dependencies,
transaction boundaries, cleanup or reversibility, and the policy source or
operator assumption behind the invariant.

A surprising response, duplicate message, changed timing, parameter name, or
single out-of-order request does not establish a violated invariant. Missing
state visibility, policy basis, stable baseline, or safe observable effect is a
coverage gap.

## Analyze the family question

Model the smallest relevant state machine: actor, object, starting state,
permitted transition, invariant, side effect, and terminal state. Ask whether a
step can be skipped, reordered, repeated, split across channels, resumed with
stale state, or completed after its precondition changes. Compare trusted
server state with client-supplied price, quantity, role, ownership, status,
limit, or workflow markers and determine which value controls the final effect.

For concurrency, distinguish an ordinary replay from overlapping operations.
Identify the read/check/write or reserve/commit boundary, synchronization and
idempotency behavior, and one harmless effect that shows whether the invariant
held. Bound parallelism and repetitions to the minimum needed; avoid inventory,
financial, messaging, entitlement, or irreversible state impact. Deterministic
state diffing or replay helpers may clarify a saved sequence without proving a
race or business impact.

## Test alternative explanations

Account for documented retries, at-least-once delivery, duplicate notifications
with one committed effect, eventual consistency, asynchronous completion,
stale reads, cache behavior, compensating transactions, reservation expiry,
feature flags, per-tenant policy, deliberately repeatable operations, and a UI
sequence that is advisory while the server enforces the invariant elsewhere.
Different responses may reflect validation, authorization, or rate limiting
rather than business-state acceptance.

## Weigh evidence and unknowns

Supporting evidence ties the controlled sequence or overlap to an authoritative
state transition or protected business effect that violates the stated
invariant, with a normal baseline and canonical pre/post evidence. Contrary
evidence includes server-side precondition enforcement, atomic commit,
idempotent replay, one final effect despite duplicate delivery, rollback or
compensation, expected policy that permits the transition, or eventual state
that resolves consistently.

State unknown authoritative stores, worker and transaction boundaries,
idempotency scope, clock and expiry behavior, alternate channels, compensation,
tenant rules, downstream effects, observation lag, cleanup, and whether the
operator's expected invariant is correct. Negative evidence covers only the
tested state, actor, sequence, timing window, and effect.

## Stop or hand back

Follow the common contribution and stop contract using method ID
`synapse-web-business-logic` and the current catalog digest. Stop when the exact
invariant is supported, refuted, inconclusive, or blocked by a named gap, and
stop before unsafe or irreversible state. Hand back to
`$synapse-web-pentesting`, or select access-control, authentication/session,
server-input, configuration, or another family when that boundary becomes
decisive.
