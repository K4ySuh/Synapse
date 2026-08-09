# Phase 2 Stage B Running Status

Updated: 2026-08-09
Current gate: complete
Verdict: `PHASE_2_READY_FOR_REVIEW`

## Gate 0 evidence

- Branch/HEAD/upstream: `Beta` at
  `873b56baa18e4a6c85f11a9fedfea217ab93700b`; `origin/Beta` is identical;
  ahead/behind is `0/0`.
- Starting worktree: no tracked changes; only the operator-provided Phase 1.1
  and Phase 2 Stage B task briefs are untracked. Neither will be edited or
  committed.
- Relevant starting range: `79f13bb..873b56b`; immediate implementation
  baseline is the parent of the eventual Stage B range, `873b56b`.
- Remote evidence checked read-only: CI run `31332087985` succeeded for this
  exact push commit across Python 3.10–3.13 and the MCP 2026-07-28 spike.
- Fresh stable install: 509 core tests, 2 custom adapter template tests, 54
  contract-filter tests, and 7 workflow benchmarks pass.
- Fresh modern-extra install: 5 modern tests pass twice; common HTTP/SOCKS
  proxy variables were all unset, so no ambient proxy exception was needed.
- `compileall` and `git diff --check` pass.
- Legacy compatibility: 174 tools and 99,337 compact schema bytes. Six frozen
  fixture files are unchanged; their sorted SHA-256 manifest hashes to
  `f456b6319e1377ef64c84f376ed6d404590a4f65f33f16cd7737c1ab568234b9`.
- Baseline workflow wall times in milliseconds: `0.428`, `3.046`, `1.621`,
  `2.130`, `56.836`, `60.880`, `4.599`; call counts remain `1,5,1,2,3,6,1`.

## Runtime map and reproduced defects

- The only supported migrated executor entry is `ActionRegistry.execute`;
  legacy projection and the isolated modern spike both call the global
  Registry. Workers call the crawler adapter with a sealed plan.
- CORS resolves a target credential once for its requested URL; the shared HTTP
  redirect path strips only standard auth headers on origin change and cannot
  re-resolve a credential for a covered destination.
- The crawler resolves one target credential against its seed and reuses the
  resulting headers for every redirect, discovered in-scope host, and POST form.
  Custom credential headers therefore cross origins. This confirms Gate 1.
- CORS/crawler proxy credentials are currently validated with target scopes,
  even though the proxy is provider infrastructure. Proxy auth is passed to
  the HTTP proxy object rather than target headers, but its scope model is wrong.
- Replay coverage differs among descriptor effects, execution-plan effects,
  and pure Authority evaluation. This confirms Gate 2.
- Job status/finalization lock their main mutation, but watchdog and cancel
  perform stale read/modify/write sequences around process termination. This
  confirms Gate 3.
- Public request fingerprints exclude every underscore-prefixed field; trusted
  worker flags can evade runtime binding. Pure authority also treats populated
  `job_status` lineage as proof without durable dispatch state. This confirms
  Gate 4.
- Stage A's ambiguous request/rate labels have been replaced by explicit
  dispatch-total, dispatch-rate-window, and active-dispatch units. Network
  volume remains action-specific sealed input, not an implied request counter.

## Current invariant

Documentation and the final gate must describe only behavior proven through
the real Registry, repository, executor, worker, and operator-service seams.
Fresh supported environments and frozen-contract measurements are the final
review boundary.

## Gate 1 evidence

- Added exact optional target-origin scopes while preserving legacy hostname
  scopes; target credential headers are recomputed from the opaque reference
  immediately before each outgoing request.
- Same-origin redirects retain covered authentication. Cross-origin redirects,
  discovered links, and POST destinations either re-resolve an explicitly
  covered credential or proceed anonymously with
  `credential_target_not_covered`; they never inherit target secret headers.
- Proxy credentials require a separate exact `providerScopes` origin and are
  supplied only to the proxy transport.
- Four local-loopback adversarial tests cover seed/same-origin, discovered
  cross-origin anonymous fallback, explicit two-origin coverage, CORS redirect
  confinement, proxy forwarding, and secret absence from plans, returned
  payloads, workspaces, and evidence.
- Broader result after the correction: 513 core tests, 2 templates, and all 7
  workflows pass; frozen legacy fixtures remain unedited.

## Gate 2 evidence

- Added one protocol-independent replay relation and canonical traffic/local
  write vocabularies under `core/effects.py`.
- Descriptor `ActionEffects`, sealed `EffectEnvelope`, Authority Grant
  coverage, and finalizer validation all call the same relation. The private
  Authority replay table was removed.
- The exhaustive 25-pair matrix passes identically at descriptor, plan, and
  Authority layers. In particular, `conditional` covers only `pure_read` and
  `conditional`; `non_idempotent` remains the widest explicit permission.
- Unknown serialized traffic, write-domain, and replay values fail closed with
  `invalid_effect_envelope` before plan verification or dispatch.
- A real background job with a conditional plan and non-idempotent finalizer
  fails before the finalizer runs. Focused results: 20 Authority tests and 17
  execution-truth tests pass.

## Gate 3 evidence

- Job records now use private crash-atomic writes, monotonic revisions, legal
  transition checks, and CAS rejection of stale snapshots. Existing records
  without revision fields are upgraded in memory on their next transaction.
- Status, list refresh, watchdog timeout, and cancel share durable control
  reservations. Only the reservation winner can commit the terminal state;
  process termination and every `wait()` occur outside the workspace lock.
- Finalization persists an `applying` reservation before invoking a finalizer,
  writing evidence, or deleting sidecars. Repeated/concurrent callers apply
  one finalizer, one completion audit, and one cleanup. Interrupted or raised
  finalization is never auto-replayed and returns explicit reconciliation.
- A legacy record without a sealed continuation plan fails with
  `legacy_job_adoption_required` rather than replaying.
- Nine deterministic event/barrier tests cover status/status,
  cancel/watchdog, cancel/status, list/status, stale terminal overwrite,
  finalizer failure, interrupted application, legacy adoption, cleanup, and
  lock-free process waits. The broader suite passes 525 core tests, 2
  templates, and all 7 workflows.

## Gates 4–5 evidence

- Public and trusted runtime fingerprints are separate. Migrated public calls
  reject underscore-reserved fields; trusted worker flags and the internal
  worker receipt are covered by the runtime fingerprint. Mutation of
  `_deferWorkflowRefreshToFinalizer` is detected.
- A populated job lineage is never sufficient. Continuations require durable
  agreement among authority dispatch truth and the sealed job record across
  workspace, origin action, grant revision, dispatch, parent plan, job,
  handler/binding, effects, outputs, revision, and lifecycle.
- Phase 2 counters are now unambiguously total, per-window, and active dispatch
  budgets. A one-page and 200-page crawler each consume one dispatch while
  producing distinct plan fingerprints; no counter claims to measure their
  outbound requests.

## Gate 6 evidence

- Added schema-versioned private authority state under each workspace using
  one workspace lock and crash-atomic `0600` replacement. Grant history,
  revocation, step-ups, expiring opaque request states, budget windows,
  decisions, dispatches, continuation bindings, and reconciliation are behind
  a storage-neutral interface.
- Authorization, budget reservation, decision audit, and `authorized` dispatch
  creation commit together. Dispatch transitions are legal and monotonic;
  revision checks reject stale grant updates.
- Repository tests cover one-winner concurrent reservation, pre-dispatch and
  dispatch-boundary crashes, post-result restart, revocation races, expiry,
  unknown no-replay, explicit idempotent retry links, compaction, private
  mode, corruption/unsupported preservation, and process restart.

## Gates 7–8 evidence

- The Registry accepts a typed policy result, installs the trusted receipt into
  execution context, records `dispatched` before the executor boundary, and
  commits success/failure/unknown afterward. Evaluator exceptions fail closed
  before execution.
- `legacy` remains pass-through with existing adapter confirmation. Modern
  CORS and crawler consume a grant receipt; caller `confirm=false` is not an
  authority signal. Worker receipt fields are sealed and checked against the
  durable dispatch before active worker execution.
- `AuthorityOperatorService` requires a local/test trusted
  `OperatorPrincipal`; `synapse-authority` manages grant lifecycle, step-up,
  opaque resume, legacy-job adoption, reconciliation/cancellation, and usage.
  No `authority.*` Registry actions exist.

## Gate 9 evidence

- The local-loopback Registry walkthrough covers all six migrated actions:
  both workspace reads, covered evidence-only analysis, full-delegated CORS,
  bounded background crawler, and continuation polling/finalization.
- Exact-target grants cannot reach another path; an explicit whole-scope grant
  can. Credential IDs are covered while secret values stay absent from the
  authority file and operational artifacts.
- Action, method, effect, risk, credential, provider, output, target, scope,
  expiry/revocation, and budget gaps do not dispatch. Supervised exact step-up
  resumes the identical opaque request. Revoked grants block new work but not
  verified collection, and collection consumes zero additional dispatch units.
- Decisions, dispatch transitions, and results share grant/dispatch/plan audit
  identity in both the authority store and evidence log. Legacy jobs require
  explicit operator adoption; legacy per-call confirmation remains intact.

## Gate 10 final validation

- Fresh stable editable install: 557 core tests, 2 custom adapter template
  tests, and 56 contract-filtered tests pass. `compileall`, the installed
  `synapse-authority --help` entry point, and `git diff --check` pass.
- Fresh modern-extra editable install: all 5 official-SDK tests pass twice.
  The loopback test removes common upper/lowercase HTTP, HTTPS, ALL/SOCKS, and
  no-proxy variables internally; a separate run with deliberately invalid
  ambient proxy endpoints also passes all 5 tests.
- The focused Stage B authority, repository, Registry, credential,
  continuation, lifecycle, execution-truth, and projection corpus passes 86
  tests.
- Final workflow call counts remain `1,5,1,2,3,6,1`. Wall times in milliseconds
  are `0.496`, `3.013`, `1.682`, `2.100`, `58.052`, `61.189`, and `4.614`;
  the two job workflows remain in baseline-scale variance with no duplicate
  dispatch.
- The legacy surface remains 174 unique tools and 99,337 compact schema bytes.
  The sorted six-fixture SHA-256 manifest remains
  `f456b6319e1377ef64c84f376ed6d404590a4f65f33f16cd7737c1ab568234b9`;
  no frozen fixture changed.
- All active tests used in-process loopback servers or disabled/fake executors.
  No public assessment target was contacted, and the final secret-pattern scan
  found no live credential material in the changed files.
