# Phase 1.1 Execution-Truth Gate Handoff

## Verdict and identity

`READY_FOR_PHASE_2`

- Branch: `Beta`
- Verified baseline and rollback point:
  `b1c29dc534f1f8f11e02cec3b217d32dff5d74ef`
- Implementation commit: `e20a780` (`fix(core): seal phase 1.1 execution truth`)
- Final HEAD: the documentation commit containing this handoff; the operator
  response records its full hash.
- Upstream at preflight: `origin/Beta` at the same baseline, zero commits
  ahead/behind.
- Reviewed range: `b1c29dc..HEAD`, plus the full execution paths named below.

No push, merge, release, tag, history rewrite, Authority Grant persistence,
budget engine, step-up/resume protocol, SQLite work, or bulk action migration
occurred. The operator-provided Phase 1.1 task brief remains an untracked input
and is not part of either implementation commit.

## Baseline

Preflight found a clean tracked worktree at `b1c29dc`; the only untracked file
was `docs/CODEX-TASK-SYNAPSE-PHASE-1.1-TRUTH-GATE.md`. The supported CI install
was reproduced in an isolated Python 3.13 environment before editing.

| Baseline command | Result |
| --- | --- |
| `bin/test` | PASS: 475 core in 15.747 s, 2 template tests, 7 deterministic workflows |
| `bin/test --core -k contracts` | PASS: 53 in 1.858 s |
| `bin/test-modern` with `.[modern-spike]` | PASS: 5 in 1.563 s |

The baseline legacy surface was 174 tools and 99,337 compact schema bytes. The
Phase 1.1 work did not change the frozen public tool schemas or result fixtures.

## Root causes and closed gates

### Gate 1 — jobs and continuations

`jobs.status` was declared `PURE_READ`, while its supported path called refresh,
persisted state transitions, detected process completion, ran adapter
finalizers, ingested workspace/evidence, logged completion evidence, and removed
sidecars. Finalizer name/data and local paths were mutable record fields outside
the original effect declaration.

The action now declares the maximum continuation effects and resolves to an
effect-free read only when the job is already finalized and has no remaining
sidecars. `background_jobs.snapshot()`/`snapshot_record()` provide the explicit
observational read. Every new job stores a creation-time execution plan. Its
continuation binding covers the action/correlation, workspace, target, job ID,
finalizer identity/data/effects, output/result/cleanup destinations, command
metadata, and original stdout/stderr/return-code paths. Status, list refresh,
watchdog completion, cancel, and finalization validate it before PID use,
return-code writes, finalizer calls, or cleanup. Workspace locking plus the
persisted `finalized` marker preserves once-only application under concurrent or
repeated polling.

Phase 2 must check expiry/revocation before a new active dispatch or explicit
resume. Normal polling/finalization of work already dispatched remains a
continuation of its sealed creation-time authority and does not ask the operator
to approve the same action again.

### Gate 2 — crawler background truth

The background crawler declared jobs/evidence/artifacts but omitted workspace
ingestion. Its worker reconstructed behavior from mutable args, and output and
worker sidecar paths were chosen after the Registry policy seam.

The maximum/effective effects now cover workspace, evidence, jobs, report
artifacts, conditional traffic/credential/provider use, external output,
overwrite/pruning, and background cleanup. The descriptor resolves before
policy:

- the seed origin or explicit potential whole-workspace-scope expansion;
- frozen scope snapshot and digest;
- methods and direct/proxy/disabled provider route;
- credential references;
- exact JSON, Mermaid, SVG, worker args, worker result, worker state, and worker
  plan destinations, including create/overwrite/prune semantics.

The worker receives a fingerprinted continuation derived from the exact parent
plan and rejects changed runtime args, targets, provider, or outputs. Planned
writes use resolved physical paths, atomic replacement, create-versus-overwrite
checks, and symlink revalidation. The finalizer can prune only destinations
marked for cleanup in that plan.

### Gate 3 — redirects and proxies

The shared `httpx` path previously delegated redirect following to the library,
so policy could see only the initial URL. Environment proxy behavior was not
fixed explicitly, and the effective proxy/credential route was not a separate
authorization dimension.

The shared backend now disables automatic redirects and `trust_env`, advances
each relative or absolute `Location` manually, and validates the normalized next
hop against the same `ExecutionPlan` before connecting. It enforces the plan and
runtime hop ceilings, detects loops, rejects malformed/userinfo destinations,
distinguishes scheme/host/port/path, records a query-redacted chain, and strips
Authorization, Cookie, and Proxy-Authorization from cross-origin target
requests. Cross-host redirects remain possible when the frozen envelope covers
the destination.

Direct, proxy, and disabled routes are fixed in `ProviderRoute` and checked at
runtime. The client ignores `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` without
fallback. Explicit proxies are origin-only and may not contain userinfo, path,
query, or fragment data. Proxy authentication is resolved by
`proxyCredentialId`; only the reference enters the plan, while the secret header
is supplied directly to the proxy transport and never serialized in plan JSON.

### Gate 4 — target envelope

Effects and a scope digest alone could not distinguish delegation of one target
from potential access to the whole workspace scope.

`core/execution.py` now supplies immutable, protocol-independent,
JSON-serializable types for canonical targets, frozen scope snapshots/digests,
exact target selectors, explicit `entireWorkspaceScope`, seeds, expansion
provenance, redirect policy, provider routes, local outputs, effect envelopes,
continuation lineage, authorization intent, and execution plans. Exact selectors
use non-regex `exact`, path-boundary `prefix`, or same-origin `any` matching.
Whole-scope selection uses the frozen existing host/pattern/CIDR matcher. A
digest detects scope changes but never selects or expands targets.

Caller/model fields describe a request only. No grant, approver identity,
budget, durable authority state, or grant evaluator was added.

## Main implementation surface

- `synapse_mcp/core/execution.py` — canonical intent/envelope/plan contracts,
  fingerprints, continuation binding, and planned local writes.
- `synapse_mcp/app/actions/{descriptor,registry}.py` — fifteenth descriptor
  field (`intent_resolver`) and one plan object shared by policy and executor.
- `synapse_mcp/app/actions/packs/{jobs,crawler,cors}.py` — truthful effective
  effects and action-specific intent resolution.
- `synapse_mcp/core/background_jobs.py`, `core/job_worker.py`, and
  `adapters/command_utils.py` — observational snapshots, sealed continuations,
  worker lineage, once-only finalization, and bounded callback effects.
- `synapse_mcp/adapters/web/{crawler_adapter,cors}.py` — runtime consumption of
  the plan, frozen scope, exact outputs, proxy references, and worker handoff.
- `synapse_mcp/core/http/{models,backends}.py` and `core/credentials.py` — manual
  pre-hop validation, explicit provider behavior, and proxy-only auth headers.
- `tests/test_phase11_execution_truth.py` plus Registry/contract updates — 16
  new adversarial integration tests linking metadata to runtime effects.

The application core imports no MCP SDK type. Adapter Registry remains a
discovery aggregator; Action Registry remains the operational effects/intent
source for the migrated slice.

## Acceptance evidence

| Criterion | Evidence |
| --- | --- |
| Deferred operations are not mislabeled pure reads | `jobs.status` maximum/effective effect tests; only clean finalized state narrows to `PURE_READ`; snapshots preserve record bytes |
| Polling neither repeats approval nor widens authority | status has no approval gate; origin lineage is retained; record/target/finalizer/effect/path mutation fails before finalizer; repeated and concurrent polling applies once |
| Worker/finalizer inherit correlated immutable plans | persisted plan contains origin correlation, parent fingerprint, actual job ID, handler, binding; worker input and finalizer-effect mutation tests fail closed |
| Background crawler declares all real domains | intent/effect test proves workspace, evidence, jobs, artifacts, cleanup/destruction and conditional operational dimensions |
| External output is exact and authorizable | normalized destinations distinguish create/overwrite; changed input, direct symlink substitution, and unplanned path writes fail before output |
| Multi-host expansion is truthful | `includeInScopeHosts=false` remains seed-origin only; `true` explicitly sets whole frozen workspace scope with provenance |
| Redirects use the policy-reviewed envelope | local relative, absolute cross-port, second-unplanned-hop, loop/limit, and userinfo tests; destination hit counters prove rejection before connection |
| Provider route is explicit | local proxy is present in intent and actually receives the request; runtime mutation fails; all three environment proxy variables are ignored |
| Secrets do not cross target/provider boundaries | cross-origin auth/cookie stripping test; proxy credential header reaches proxy but secret is absent from plan JSON; embedded/query proxy secrets are rejected |
| Partial and broad target delegation are representable | exact-one-of-two, explicit whole-scope, canonical equivalence, scope-digest change, and scheme/host/port distinction tests |
| Policy and runtime share one truth | a policy mutates validated target/output after evaluation; the executor sees the identical plan object and rejects before either path is written |
| Legacy and modern profiles remain compatible | all unchanged legacy fixtures/contracts pass; separate official-SDK spike remains 5/5 green |

## Final verification

Fresh CI-equivalent Python 3.13 environments were created separately for the
stable and modern profiles.

| Command | Result |
| --- | --- |
| `pip install -e .` | PASS in isolated `<TEMP>/synapse-phase11-final-stable/venv` |
| `SYNAPSE_PYTHON=... bin/test` | PASS: 491 core in 20.947 s; 2 templates in 0.000 s |
| `SYNAPSE_PYTHON=... bin/test --core -k contracts` | PASS: 53 in 2.288 s |
| `python -m compileall -q ...` | PASS |
| `pip install -e '.[modern-spike]'` | PASS in separate isolated `<TEMP>/synapse-phase11-final-modern/venv` |
| `SYNAPSE_PYTHON=... bin/test-modern` | PASS: 5 in 1.748 s using `mcp==2.0.0` |
| `git diff --check` | PASS |

Final clean-environment workflow wall times in milliseconds were `0.572`,
`3.969`, `3.112`, `2.483`, `60.174`, `65.543`, and `6.362`; call counts remain
`1`, `5`, `1`, `2`, `3`, `6`, and `1`. No public target was contacted. Remote CI
was not run for these local commits because no push was authorized.

The legacy profile remains 174 tools / 99,337 compact schema bytes, protocol
`2025-03-26`, with unchanged published schemas and result fixtures. The modern
spike remains exactly three actions on the isolated official SDK profile.

## Residual risks and Phase 2 boundary

- Durable grants, grant coverage decisions, budgets, approver identity,
  expiry/revocation state, step-up/resume, and a dispatch ledger remain Phase 2
  work by design.
- Only the Phase 1 migrated vertical has action-specific intent resolvers.
  Unmigrated actions retain the compatibility path; the shared HTTP helper is
  plan-enforcing when a migrated caller supplies a plan. Future migration must
  follow `action-migration-pattern.md` rather than infer targets from field
  names.
- An unfinished job persisted by an older binary without an execution plan now
  fails closed on refresh/finalization and requires operator review; new jobs
  always carry the plan.
- Plan fingerprints are local integrity/lineage checks, not a cryptographic
  defense against the local data owner. Synapse's existing local filesystem
  ownership remains the trust boundary; Phase 2 authority persistence must use
  the existing locked atomic-store prerequisite.

Phase 2 may begin with the pure grant-coverage and `PolicyDecision` model in
Stage A/B, consuming the existing `AuthorizationIntent`/`ExecutionPlan`. It
should compare explicit exact-versus-whole-scope selection, scope digest,
redirect policy, provider routes, local outputs, methods, credential references,
effective effects, risk, and budgets before adding persistence or dispatch
state.
