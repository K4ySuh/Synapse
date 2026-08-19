# Phase 2 Stage B Running Status

Updated: 2026-08-19
Current gate: complete
Verdict: `PHASE_2_PASS`

Audited implementation base:
`937c7707a1f96bbf2f8b70b620fd5b6700020ced` on `Beta`.
Final closure implementation:
`0b17118693038436a85e388f8a99bd749e370832`. This running-status update is
the documentation commit immediately following that implementation commit.

## Historical Gate 0 evidence (2026-08-09)

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

## Historical Gate 10 validation (2026-08-09)

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

## Final adversarial closure gate (2026-08-19)

### Corrected defects

- **Official-SDK supervised resume.** The modern adapter now consumes the
  SDK-unsealed `ctx.request_state` value. The raw repository ID remains
  server-held; the client sees only the SDK-sealed token. Before replanning,
  the adapter restores the original correlation, idempotency key, profile,
  grant, and revision. `SYNAPSE_MODERN_REQUEST_STATE_ID` was removed as a
  per-request channel. A black-box SDK test proves initial step-up, trusted
  `approve-request`, standard resume, one HTTP request/dispatch/budget, wrong
  workspace/action/argument/session rejection, step-up expiry, grant revision,
  grant revocation, and replay rejection.
- **Authorization identity and retry safety.** `authorizationFingerprint`
  covers approval material while excluding correlation/deadline execution
  metadata. The existing complete `planFingerprint` still seals correlation
  and continuation metadata for audit integrity. An idempotency key is bound to
  one authorization fingerprint; changed payload/action/scope conflicts,
  pending state must be resumed, and a correlation change cannot bypass an
  `authorized`, `dispatched`, or `unknown` ledger entry. Request state binds
  workspace, session, action, profile, grant/revision, both fingerprints,
  original correlation/key, expiry, and exact step-up state, and is consumed
  atomically with one dispatch.
- **Background lifecycle cleanup.** Process observation no longer writes
  `returncode.txt`. A deterministic barrier pauses a polling observer after it
  sees completion, lets the enabled watchdog finalize and delete sidecars, and
  then resumes the observer; no sidecar or stale path reappears. A preserved
  whole-suite failure also exposed status stealing a live watchdog's timeout.
  Status now defers only when the watchdog and matching live process handle are
  both present, preserving restart recovery and deterministic watchdog audit
  ownership.

### Final validation evidence

- Focused Phase 2 command (`test_phase2_authority_model`, repository,
  integration, credential confinement, job lifecycle, execution truth, and
  slice projection): **94 tests passed**.
- `bin/test --core -k contracts`: **56 tests passed**; all frozen fixtures are
  unchanged.
- Fresh Python 3.13 virtual environment with `pip install -e
  '.[modern-spike]'`, then `bin/test-modern`: **6 tests passed in 2.806 s**
  against official `mcp==2.0.0`.
- Two consecutive final `bin/test` runs: **565 core + 2 template tests passed**
  in **40.223 s** and **39.129 s**. Workflow call counts remained
  `1,5,1,2,3,6,1`; the second-run wall times in milliseconds were `0.455`,
  `3.023`, `1.669`, `2.186`, `57.267`, `61.190`, and `3.991`.
- Job stress: the complete lifecycle corpus passed 10 consecutive runs (110
  tests), the watchdog timeout passed 20 consecutive runs, and watchdog plus
  restart-timeout paths passed 10 consecutive paired runs. The deterministic
  sidecar and timeout-owner regressions also pass together.
- `compileall` used an external `PYTHONPYCACHEPREFIX`; `git diff --check`, the
  modernization documentation suite, `bin/check-setup`, installed
  `synapse-authority --help`, `approve-request --help`, and an isolated
  `list-requests` smoke all pass. The repository defines no additional
  formatting, lint, or type-check command.
- Legacy contract tests pass. The surface remains **174 tools / 99,337 compact
  bytes**. The sorted top-level six-fixture SHA-256 manifest remains
  `f456b6319e1377ef64c84f376ed6d404590a4f65f33f16cd7737c1ab568234b9`, and
  the correction diff names no frozen fixture.
- The changed-file secret scan found no private keys, cloud keys, or assigned
  password/token/API-key material. The correction diff introduces and tracks no
  `DATA`, report, credential, session, job-sidecar, or bytecode artifacts. This
  developer clone still has pre-existing ignored local `DATA/` and bytecode
  caches; they remain outside the reviewed diff and were not treated as shared
  repository content.

### Protocol durability and Phase 3 boundary

The SDK's client-visible token and Synapse's raw durable request ID are
different layers. The opt-in server currently uses the SDK's default ephemeral
request-state key; therefore a client `v1` token is bound to the current server
process and is **not** restart durable. The raw pending record survives and is
available to the trusted operator through `list-requests`/`inspect-request`.
After restart, the operator reviews that record, lets it expire, and initiates
and approves a new protocol request. Persistent SDK key management,
authenticated remote client/operator sessions, the full modern protocol
surface, and migration of the remaining 168 legacy actions remain Phase 3.

GitHub Actions run #10 for audited base `937c770` failed in the Python 3.13
job and predates the closure correction. The implementation correction is
committed as `0b17118693038436a85e388f8a99bd749e370832`; the final branch-head
CI result is verified externally after publication rather than asserted inside
the commit that triggers it. Published tasks 2–7 previously landed together in
`937c770` despite the original one-commit-per-task request; history was not
rewritten to conceal the deviation.
