# Phase 2 Stage B Authority Integration Handoff

Status: integrated; ready for review
Date: 2026-08-09
Baseline: `873b56baa18e4a6c85f11a9fedfea217ab93700b` on `Beta`

## Outcome

Phase 2 now enforces server-held Authority Grants through the sole supported
`ActionRegistry.execute()` seam for the six migrated actions. The `legacy`
profile remains the frozen 174-tool compatibility surface. Authority-aware
`observe`, `supervised`, and `full_delegated` contexts are server owned; no
action input can select a grant, step-up, request state, dispatch, continuation,
or profile.

Covered full-delegated work executes without caller `confirm=true` and without
a per-call pause. Uncovered work returns typed `ApprovalRequired` with legacy
`-32001`, an exact requirement, and an opaque expiring request state; scope
denial remains `-32002`. Supervised sensitive work resumes only after an exact
step-up bound to grant revision, plan fingerprint, idempotency key, operator,
and expiry.

## Durable boundary

`synapse_mcp.policy.repository.WorkspaceAuthorityRepository` is the file-backed
implementation of a storage-neutral repository interface. It stores schema
version 1 at:

```text
DATA/workspaces/<workspace-id>/authority/state.json
```

The existing workspace lock covers each complete reload/evaluate/reserve/write
transaction. Writes are crash-atomic and `0600`. Optimistic revision checks
protect grant updates; a single transaction records the decision, reserves
total/rate-window/active dispatch budget, and creates the authorized dispatch.
The store retains grant revisions, exact step-ups, bounded opaque request
states, budget windows, decision audit, dispatch state, continuation bindings,
and unknown reconciliation. Corrupt or unsupported files are preserved and
fail closed with a recoverable reason.

Dispatch truth follows:

```text
authorized -> dispatched -> succeeded | failed | unknown
authorized -> cancelled
```

The Registry commits `dispatched` before the executor boundary. Exceptions
become conservative `unknown`. State-changing `dispatched` or `unknown` work is
never replayed. Explicit retry requires a plan classified as idempotent, an
idempotency key, and a durable `priorDispatchId` link.

## Continuations and jobs

Public input and trusted runtime fingerprints are separate. Caller-reserved
underscore fields are rejected, while worker flags and the internal authority
receipt are sealed by the trusted runtime fingerprint. A crawler worker checks
its receipt against durable dispatch truth before active execution.

`jobs.status` receives zero-budget continuation authority only when the
authority ledger and durable job record agree on workspace, origin action,
grant id/revision, dispatch, original and parent plan fingerprints, job,
handler, binding fingerprint, exact finalizer effects/outputs, job revision,
and lifecycle. Grant expiry or revocation stops new work but does not erase the
already-crossed dispatch boundary. Legacy jobs have no implicit authority; the
trusted operator must explicitly adopt one with a covering grant.

Job records also now use private atomic writes, monotonic revision/CAS checks,
legal transitions, durable control reservations, and an `applying`
finalization reservation. Competing status/list/watchdog/cancel callers produce
one terminal transition, one finalizer, one application audit, and one cleanup.
No process wait occurs while a workspace lock is held. Interrupted or failed
finalization is not retried automatically and exposes reconciliation state.
After an MCP restart, cancellation and timeout handling never signals a
persisted PID without a matching live process handle or applies continuation
effects across that uncertainty; it records operator reconciliation instead.

## Credential boundary

Target credentials may declare exact target origins independently of provider
origins. CORS and crawler requests resolve the credential again immediately
before every destination. Same-origin redirects retain covered authentication;
cross-origin redirects, links, and forms either obtain their own explicitly
covered headers or continue anonymously with a secret-free coverage reason.
Proxy credentials are resolved only against exact provider scope and are never
target headers. Secrets do not enter plans, authority state, results,
workspaces, evidence, or audit records.

## Budget decision

Phase 2 counters are dispatch budgets. One unit means one canonical action
dispatch, not an HTTP request. Total, per-window, and active units are named
separately; every `None`/JSON `null` is explicitly unbounded. Crawler
`maxPages`, redirect hops, forms, delays, concurrency, and similar network
volume remain action-specific inputs sealed by the plan fingerprint. A future
network-request budget requires shared HTTP/provider instrumentation.

## Operator workflow and rollback

`AuthorityOperatorService` requires a trusted local `OperatorPrincipal` and is
not in the Action Registry. The installed `synapse-authority` command creates,
lists, inspects, revises, and revokes grants; issues step-ups; inspects/resumes
opaque request states; adopts legacy jobs; reconciles/cancels dispatches; and
shows budget/dispatch usage.

Rollback disables the opt-in modern server or selects the stable legacy MCP.
Do not delete the authority file during rollback: unresolved and historical
dispatch truth remains necessary for safe recovery.

## Verification evidence

- Credential confinement: loopback same-origin, cross-origin anonymous,
  explicit multi-origin, CORS redirect, and forwarding-proxy tests.
- Replay/effects: exhaustive 25-pair equality across descriptor, plan, and
  Authority layers plus malformed-envelope rejection.
- Jobs: deterministic status/status, cancel/status, cancel/watchdog,
  list/status, stale writer, finalizer failure/interruption, legacy adoption,
  cleanup, and lock-free wait tests.
- Repository: concurrent one-winner reservation, all crash boundaries,
  revocation race, request-state expiry, unknown no-replay, idempotent retry
  link, restart, compaction, private mode, and corruption preservation.
- Registry walkthrough: all six migrated actions, observe reads/covered writes,
  full-delegated CORS and background crawler without caller approval, exact and
  whole-scope coverage, credentials, every denial dimension, supervised resume,
  revocation, continuation, evaluator failure, audit/evidence links, and legacy
  compatibility.

Fresh-environment validation passes 557 core tests, 2 template tests, 56
contract-filtered tests, 86 focused Stage B tests, and 5 modern SDK tests twice.
The modern loopback test also passes with deliberately invalid ambient proxy
variables. All seven workflow call counts remain unchanged; exact timings,
legacy surface measurements, and the frozen fixture digest are recorded in the
Stage B running status.

## Residual risk and Phase 3 boundary

Only six actions have canonical Registry contracts; the remaining legacy tools
still use per-call confirmation. The modern SDK server remains an opt-in
three-action profile and its trusted bindings are local process configuration,
not a finalized remote identity/session protocol. Phase 3 owns ADR-0004's full
modern compatibility surface, protocol-native outcome/error projection,
authenticated client/operator session integration, and migration of additional
actions. It must reuse the repository and Registry receipt boundary rather than
creating a second authority path. Phase 4 may replace the file repository with
SQLite behind the existing interface and may add true shared network-request
budgets; neither change is required for Phase 2 correctness.
