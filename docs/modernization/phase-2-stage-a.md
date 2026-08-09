# Phase 2 Stage A — Authority Engine design checkpoint

Corrected draft for operator/architectural-lead ratification. ADR-0009
supersedes this document's original input-type routing and singular
`SideEffectClass` assumptions. Phase 2 starts only from Registry v2: explicit
action IDs, validated canonical outputs, request-effective multidimensional
effects, availability-before-policy, and Action Registry as operational truth.
The Phase 1.1 truth gate additionally lands the descriptor-owned intent,
target/output/provider envelopes, and continuation lineage assumed below.

This document opens Phase 2
(Authority Grants, ADR-0003) by turning the proposed decision and the directive's
Section C into a design checkpoint that can be locked for a later Stage B. It
makes the architectural calls; the section "Decisions owed" lists the points
needing an explicit sign-off before Stage B specs are written.

- Author: architectural lead (Javier Roldán Ortiz)
- Governing ADR: ADR-0003 (Proposed) — Durable Authority Grants
- Supporting: ADR-0002 (Accepted, the registry seam), ADR-0004 (Proposed, profiles),
  ADR-0007 (outcome model), ADR-0008 (action identity)
- Directive source: Section C ("Introduce durable Authority Grants") and
  "Phase 2 — Authority Engine"
- Status: **corrected draft, awaiting checkpoint approval and an independent design review**
- Publication note: tracking this draft preserves the current development state;
  it does not ratify the decisions in Section 9 or authorize Stage B implementation

## 0. Preconditions and base dependency

The historical implementation prerequisites landed at `219d4a1`; Registry v2
and the official-SDK correction gate are integrated through `b1c29dc`. Phase
1.1 builds on that verified baseline:

1. **F-1 atomic-store prerequisite** — `2790b8d`, landed first. Scope,
   credentials, and private JSON writes use the shared `core/atomic_io.py`
   primitive.
2. **Phase 1 Action Registry slice** — `d590dc0`, merged without rewriting its
   reviewed history. Six actions across five packs route through
   `ActionRegistry.execute()` and its policy seam.

The Phase 1.1 handoff records the current exact test counts and commit range.
The legacy surface remains 174 tools / 99,337 compact bytes. Stage B is no
longer blocked on an intent or execution-truth prerequisite, but durable grant
state, decisions, budgets, and the dispatch ledger remain unimplemented.

## 1. Objective

Replace caller-asserted `confirm=true` — which the server today accepts,
validates, echoes, and does not enforce — with **durable, server-evaluated
Authority Grants**: the operator authorizes a bounded envelope once, and the model
works freely inside it while every dispatch is re-checked against the current
grant, scope state, budgets, and dispatch ledger. Authority becomes bounded,
expiring, revocable, and auditable, and model-supplied input can request but never
widen it.

The engine is delivered as an application service wired into the existing
`ActionRegistry.execute()` seam. It is exercised end-to-end over the six migrated
actions; it does **not** require Phase 3's modern protocol surface to be proven.

## 2. The load-bearing decision: profile-gated enforcement

The program's central invariant is that the legacy 174-tool surface stays
byte-identical and every frozen fixture stays green. Authority enforcement is a
behaviour change. These are reconciled by **gating enforcement on an execution
profile**, not by changing the legacy path:

- **`legacy` profile (default).** The evaluator is a pass-through, exactly as
  Phase 1. `confirm=true` and the executor's existing gates remain authoritative.
  Every Tier-1/Tier-2 fixture runs on this profile and is untouched. The frozen
  `confirm_omission.json` (`-32001`) contract is unchanged.
- **modern authority profiles (opt-in).** `observe`, `supervised`, and
  `full_delegated` evaluators consult the workspace's active
  grant and returns allow / approval-required / scope-denied. `confirm=true` is
  **not** accepted as proof of approval here (directive rule 2).

The profile is carried on `ExecutionContext` (a new field, defaulting to
`legacy`). The legacy transport projection always sets `legacy`; Phase 2 tests and
any future authority-aware entry set `authority`. Because the registry **always**
calls the evaluator first (ADR-0002 no-bypass invariant, already enforced), the
same code path serves both profiles — under `legacy` the decision is always
*allow*, so the observable surface cannot move. New authority behaviour is
**additive**, proven by new tests over the migrated actions.

The profile and all authority context are trusted entry-point state, never action
input. Supplying extra input fields named `profile`, `grantId`, `requestState`, or
similar cannot select a profile or grant. This matters because frozen legacy
input contracts deliberately accept unknown public fields. Phase 2 adds defaulted
`ExecutionContext` fields for profile, bound grant, idempotency key, and resumable
request-state reference; adapters set them from server-held session/operator
state, not from `ActionInput`.

This is the mechanism that lets Phase 2 introduce real authority without spending
the compatibility budget the whole program is built to protect. Phase 3's modern
surface later selects the `authority` profile by default.

## 3. The Authority Grant model

A typed, frozen model (proposed home `synapse_mcp/policy/authority.py`) mapping the
directive's minimum grant fields onto the Phase 1 policy vocabulary already carried
by every descriptor, so the evaluator compares like with like.

| Grant field | Type / source | Purpose |
| --- | --- | --- |
| `grantId`, `workspaceId` | ids | Identity; a grant authorizes work in one workspace |
| `revision` | positive integer | Optimistic lifecycle version; increments on every grant mutation |
| `mode` | `observe` / `supervised` / `full_delegated` | Operator-facing authority posture (§4) |
| `scopeDigest` | hash of the effective workspace authorization set | Binds the grant to normalized hosts/patterns/CIDRs; timestamps, notes, and ordering do not change it |
| `targetEnvelope` | exact scheme/host/port/path selectors and/or explicit `entireWorkspaceScope` | Delegates a subset or the whole frozen scope; digest alone never selects targets |
| `redirectPolicy` | allowed dynamic selectors and hop ceiling | Covers each normalized hop before connection, including explicitly authorized cross-host redirects |
| `providerRoutes` | direct/disabled or exact proxy/provider endpoints plus credential refs | Covers contacted infrastructure separately from assessment targets |
| `localOutputEnvelope` | exact normalized paths plus create/overwrite/prune permission | Covers local destinations separately from remote targets |
| `allowedActionPatterns` | globs over `ActionId` (e.g. `cors.*`, `workspace.summary`) | Which actions the grant covers |
| `allowedMethods` | HTTP methods | Ceiling for probe/method-bearing actions |
| `allowedEffects` | traffic destinations, local write domains, local/remote change, credential/secret use, replay rules | Compare request-effective effects; uncertainty uses the descriptor maximum |
| `riskCeiling` | `RiskClass` | Max `risk_class` the grant permits |
| `credentialRefs` | credential ids | Which credentials may be used (by reference; never secrets) |
| `thirdPartyProviders` | provider ids | Which third-party providers are permitted |
| `requestBudget`, `rateBudget`, `parallelismBudget` | operator-configured counters | Total / per-window / concurrent bounds; conservative defaults are not undocumented ceilings |
| `stateChangePolicy` | enum | How non-idempotent / state-changing actions are treated (e.g. always step-up) |
| `expiresAt`, `createdAt`, `approvedBy`, `revokedAt` | timestamps / operator principal | Lifecycle and audit |

The Registry v2 descriptor fields (`effects`, `effect_resolver`, `risk_class`,
`scope_policy`, `credential_policy`, and replay safety) provide policy bounds.
Phase 1.1 adds the fifteenth descriptor-owned contract: a pure
`intent_resolver` producing a frozen `AuthorizationIntent`, sealed with effects
and input fingerprint into `ExecutionPlan`. This is the recorded ADR-0002
amendment, not an inference from arbitrary input field names.

### 3.1 Trusted authorization intent

`AuthorizationIntent` now contains the canonical action ID, workspace/scope
digest and frozen selection, exact/whole-scope targets, seeds, redirect policy,
methods, credential references, provider/proxy route, exact local outputs, and
continuation lineage. The execution plan carries the validated input
fingerprints and effective effects. The resolver:

- performs validation and local normalization only — no traffic, credential
  resolution, write, or provider call;
- handles action-specific shapes such as CORS `candidate.url` versus `url`;
- includes unknown public extras in fingerprint material while preserving
  omission semantics of the validated legacy input;
- never includes raw credential values; the authority profile accepts credential
  references only;
- runs in `ActionRegistry.execute()` before policy evaluation, and the executor
  receives the identical plan object that policy reviewed;
- supplies a fingerprinted serialization to crawler workers/finalizers, which
  reject target, provider, output, input, workspace, or effect widening.

The descriptor now has fifteen fields. ADR-0002 and the contract ledger record
the amendment. Durable grants remain absent: caller fields request an envelope
but cannot grant it.

## 4. Grant modes

Per the directive, three operator-facing modes, evaluated server-side:

- **`observe`** — actions whose effective effects have no traffic, credential
  use, state change, or local writes beyond explicitly allowed observation
  evidence; uncovered effects return approval-required.
- **`full_delegated`** — the model may execute any action **covered by the grant**
  without per-call pauses. Covered = pattern, every effective-effect dimension,
  risk, method, credential, provider, and configured budget all satisfied.
  Uncovered work returns approval-required without dispatching.
- **`supervised`** — covered low-risk work proceeds; selected classes (e.g.
  non-idempotent replay, remote/local state changes, `high` risk, destructive
  local effects, or credential/secret use) require **exact step-up approval**
  bound to the action fingerprint and idempotency key.

Expert/raw actions are grantable only when an explicit action capability exists
and repository policy permits it. Methods, rates, budgets, and parallelism are
operator-controlled grant dimensions. Current adapter limitations are tracked
in `capability-gap-inventory.md`; they are not silently converted into permanent
Authority Engine prohibitions.

## 5. The evaluator: replacing the pass-through

Phase 1 landed the seam: `ActionRegistry.__init__(self, policy_evaluator=None)`
defaults to `PassThroughPolicyEvaluator`, whose
`evaluate(descriptor, request, effects) -> bool` returns `True`. Phase 2:

1. **Evolves the decision type** from `bool` to a `PolicyDecision` union: `Allow`,
   `ApprovalRequired(reason, request_state)`, `ScopeDenied(reason)`. `execute()`
   maps a non-`Allow` decision to the corresponding **existing** Phase 1 outcome
   rather than proceeding to the executor:
   - `ApprovalRequired` → the `ApprovalRequired` outcome (`legacy_code = -32001`),
     carrying a resumable request state.
   - `ScopeDenied` → the scope-denied outcome (`legacy_code = -32002`).
   - `Allow` → the executor runs, unchanged.
   This **preserves the observable `-32001`/`-32002` taxonomy** (ADR-0003
   invariant) — approval-required and scope-denied stay distinct decisions, and
   approval-required is a normal resumable outcome, not a protocol error.
   A target outside the current effective workspace scope maps to `ScopeDenied`
   (`-32002`). A changed scope digest invalidates the old grant but does not claim
   the target itself is out of scope; it maps to `ApprovalRequired` with
   `scope_changed` (`-32001`).
2. **Ships a `GrantPolicyEvaluator`** injected in place of the pass-through. Under
   the `legacy` profile it returns `Allow` unconditionally (byte-identical
   behaviour). Under the `authority` profile it evaluates, in order: workspace
   and current target scope → bound grant existence/lifecycle → scope digest →
   action, side-effect, risk, method, credential, and provider coverage → mode
   (§4) → prior dispatch state → atomic budget reservation. The first failure
   produces the corresponding decision.
3. **Keeps the no-bypass invariant.** The registry already calls the evaluator
   before every executor; that structural guarantee is unchanged, so an executor
   still cannot run without a decision.

Phase 2 uses a high-entropy opaque request-state id that resolves to server-held,
expiring state bound to workspace, grant, fingerprint, and idempotency key.
Possession of the id does not approve anything. This avoids inventing a sealed
self-contained token before the Phase 3 protocol/identity decision. Capable
clients later receive `resultType: input_required`; older modern clients receive
a structured `approval_required` result. Protocol projection remains Phase 3.

## 6. Durable authority repository and dispatch-state ledger

Phase 2 uses one versioned, workspace-local authority state file, proposed at
`DATA/workspaces/<workspace>/authority/state.json`, created at `0600`. It contains
grants, step-up approvals, request states, budget reservations, authority-decision
records, and dispatch records. Repository code holds one `file_lock` across the
entire read/evaluate/mutate/`atomic_write_text` transaction. Separate grant and
ledger files are rejected for Phase 2 because they cannot atomically reserve a
budget and record the authorization that consumed it without a database.

Every evaluation reloads current state, so expiry and revocation take effect
before the next dispatch. Every decision, including denial, receives an audit
record. An allowed execution creates a dispatch record with these transitions:

```text
authorized -> dispatched -> succeeded
                         -> failed
                         -> unknown
authorized -> cancelled        # execution boundary was provably not crossed
```

The `authorized` record and budget reservation are committed atomically. The
`dispatched` transition is committed immediately before calling the executor. A
crash leaving `authorized` can be cancelled and released safely; a crash leaving
`dispatched` becomes `unknown` and is not automatically replayed when the action
is state-changing/non-idempotent. Unknown reservations require expiry or operator
reconciliation rather than optimistic reuse.

The fingerprint is SHA-256 over versioned canonical JSON containing the action
id, workspace id, current scope digest, normalized `AuthorizationIntent`, full
validated input with defaults/extras, and idempotency key. Only the legacy
caller-asserted fields `confirm`, `approvalId`, `approvalReason`, and `riskTier`
are excluded. Correlation ids and deadlines are execution metadata, not approval
material. Credential ids are included; raw credential values are forbidden in
the authority-profile intent and never persisted.

## 7. Grant lifecycle and the operator plane

Grant issuance, step-up approval, reconciliation, and revocation are **operator**
operations — never model actions, and `confirm=true` is not a substitute. Phase 2
implements an application-level `AuthorityManagementService` reached only by a
trusted local/operator adapter and accepting an `OperatorPrincipal` from that
adapter, not from `ActionInput`. It does not register `authority.grant` or similar
in the model-executable Action Registry. Phase 3 may project this service through
an authenticated operator surface after its identity/protocol decision.

This keeps management outside the frozen 174 tools and avoids the circular design
where an untrusted model calls an action that grants itself authority. The first
principal contract is deliberately small (`principalId`, source, authentication
method) and auditable; a stronger signer identity model remains a separately
recorded evolution.

## 8. Compatibility, migration, and invariants

**Migration.** The six already-migrated actions become grant-evaluable first
(their descriptors already declare the needed policies). All other legacy actions
keep `confirm=true` under the `legacy` profile until they are both registry-
migrated (Phase 1 pattern) and grant-evaluated. No legacy-removal date is set.

**Invariants Stage B must hold (ADR-0003 + directive exit criteria):**

1. The legacy profile is byte-identical: all Tier-1/Tier-2 fixtures and
   `confirm_omission.json` stay green and unedited; `tools_list` stays 174 /
   99,337 compact bytes.
2. Model-supplied input can never widen scope, authority, risk ceiling, credential
   access, provider access, or budget.
3. The policy evaluator authorizes the same normalized intent the executor uses;
   no field-name heuristic or transport-only extraction is permitted.
4. The `-32001` (approval) / `-32002` (scope) taxonomy is preserved.
5. `full_delegated` authorized work does not pause; uncovered work does not
   dispatch.
6. A state-changing retry cannot duplicate an uncertain (`dispatched`/`unknown`)
   dispatch.
7. Credentials remain references resolved only at dispatch; secret values never
   enter grants, descriptors, audit summaries, or agent-facing results.
8. Authority decisions are linked to evidence and action records.

## 9. Decisions owed (checkpoint sign-off)

1. **Integration order — resolved.** F-1 landed before Phase 1; integrated
   `Beta` is `219d4a1` and the combined verification gate is PASS.
2. **Enforcement is profile-gated and additive** (§2) — ratify the recommendation
   that Phase 2 introduces no enforcement on the legacy profile, so the frozen
   surface is untouched and authority is proven only by new tests.
3. **Grant-management surface** (§7) — ratify the recommendation for an
   operator-only application service, not model-executable registry actions.
4. **`ExecutionContext` gains a `profile` field** (and later a resume/`requestState`
   carrier) — ratify defaulted trusted fields for profile, bound grant,
   idempotency key, and request-state id. Action input cannot set them.
5. **Whether a new `PolicyDecision` type supersedes the `evaluate -> bool` seam** —
   ratify the recommended return-type change, recorded as an ADR-0002 amendment
   in the ledger (same bar as a fixture change), since ADR-0002 is Accepted.
6. **Trusted intent resolution — resolved by Phase 1.1.** The descriptor-owned
   resolver and fifteen-field pin are recorded in ADR-0002 and the ledger;
   policy/executor/worker/finalizer share one sealed plan.
7. **One workspace-local transactional authority file** (§6) — ratify this over
   separate grant/ledger JSON files so budget reservation and authorization are
   one locked atomic mutation.
8. **Reason taxonomy** — ratify `target_out_of_scope` as `ScopeDenied/-32002` and
   grant/lifecycle/coverage/budget/step-up/`scope_changed` reasons as
   `ApprovalRequired/-32001`.
9. **Phase 2 request state and operator identity** — ratify server-held opaque
   request state plus the minimal trusted `OperatorPrincipal`; defer
   self-contained token sealing and stronger signer identity until an explicit
   protocol/operator-plane decision.

## 10. Stage B task outline (written in full once this checkpoint is ratified)

Strict dependency order, one commit per task, `bin/test` green after each, no
frozen fixture edited:

1. **Grant + pure decision model** — `policy/authority.py`: consume the existing
   `AuthorizationIntent`/`ExecutionPlan` and implement typed grant coverage plus
   `PolicyDecision` for the three modes. Compare exact versus whole-scope target
   selection, scope digest, redirects, providers, local outputs, methods,
   credential refs, effects, risk, and configurable budgets. Pure model + unit
   tests; no persistence or dispatch.
2. **Durable authority repository** — one workspace-local transactional state
   file on `core/atomic_io.py`; crash/lock/revision/budget/expiry/revocation and
   recovery tests.
3. **`GrantPolicyEvaluator`** — profile-aware evaluation → `PolicyDecision`;
   exhaustive coverage/mode/budget/ledger unit tests; legacy profile proven a
   pass-through.
4. **Wire decisions into the registry** — intent/plan wiring already exists;
   evolve `evaluate` to `PolicyDecision`, map decisions to outcomes, inject the
   evaluator, and extend trusted `ExecutionContext`. Legacy-profile equivalence
   is the gate.
5. **Operator management service** — issue/inspect/step-up/reconcile/revoke through
   the trusted non-registry service; evidence linkage.
6. **Authority walk-through** — new tests driving the six actions under the
   modern authority profiles: full-delegated no-pause, uncovered no-dispatch, step-up,
   revocation-before-next-dispatch, retry non-duplication; the P0-3 workflow-06
   benchmark stays green.
7. **Migration doc + ADR promotions** — record the pattern; move ADR-0003 to
   Accepted-applied; ledger the ADR-0002 seam amendment; Phase 2 handoff.

## Appendix A — why the descriptor evolved in Phase 1.1

Phase 1 descriptors express policy ceilings but not how to derive the exact
execution intent from action-specific input. For example, CORS accepts either
`candidate.url` or `url`, while the crawler normalizes `target`; future actions
have still more shapes. Authorizing by guessed field names would let policy and
the executor disagree about the target.

The descriptor therefore gained one pure intent resolver in Phase 1.1. This
changed an application contract and its test, but did not change legacy tool
names, input schemas, result fixtures, or wire bytes. ADR-0002's single-source
and no-bypass rules are now stronger: the same descriptor owns both policy
metadata and the resolver for the intent evaluated before its executor is
invoked.
