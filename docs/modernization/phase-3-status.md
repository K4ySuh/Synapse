# Phase 3 running status

Updated: 2026-08-20
Current session: Phase 3C — production modern MCP adapter
Baseline: `6f46dae128520e06056dce50632e750023aedc80` on `Beta`
State: Sessions 3A, 3B, and 3C complete; Session 3D not started

## Preflight

- Worktree began clean; local and remote `Beta` matched the reviewed baseline.
- `git merge-base --is-ancestor 6f46dae HEAD` returned success.
- The root `AGENTS.md`, Phase 3 execution pack, Phase 3A brief, then-current
  Phase 2 closure evidence, modernization index, ADR-0004, migration pattern,
  registry/policy/projection implementations, and relevant tests were read.
- The requested `action-migration-guide.md` did not exist at entry. Phase 3A
  added it and marked the older `action-migration-pattern.md` as historical,
  replacing the one-action-per-commit rule with bounded pack batches.

## Baseline stability evidence

- `bin/test`: 565 core tests passed in 40.827 seconds; 2 template tests passed.
  Workflow calls remained `1,5,1,2,3,6,1`.
- Fresh retained Python 3.13 modern environment with official `mcp==2.0.0`,
  `SYNAPSE_PYTHON=<MODERN_ENV>/bin/python bin/test-modern`:
  6 tests passed in 2.819 seconds.
- CVE provider pause regression: 25/25 isolated process runs passed.
- No-network workflow benchmark regression: 25/25 isolated process runs
  passed.

The reviewed CVE failure was a genuine test-harness timing race: a real
wall-clock assertion observed only the *remaining* persisted provider pause
after response handling, so scheduler/IO time could reduce a nominal 30 ms
pause below the asserted 20 ms. Phase 3A now uses an injected deterministic
provider clock and asserts the exact coordinated sleep.

The reviewed workflow failure occurred at the background-job boundary while
the benchmark changed process-global state paths. The harness now waits for
watchdog/process-handle cleanup and for the intentionally timed-out tool thread
before releasing the isolated root. No retry or relaxed assertion was added.

## Migration ledger

| Reviewed use case | Actions | State |
|---|---:|---|
| control_plane | 5 | complete |
| reporting | 20 | complete |
| engagement_state | 24 | complete |
| credentials_auth | 10 | complete |
| local_artifacts | 5 | complete |
| web_assessment | 62 | complete |
| app_discovery | 10 | complete |
| scanner_execution | 9 | complete |
| infrastructure_osint | 18 | complete |
| cve_intelligence | 11 | complete |

All 174 actions now enter `ActionRegistry.execute()` first. Six native pack
executors remain in place; 168 descriptors use the protocol-free retained-
implementation bridge, with the old dispatch body independently callable as a
per-action rollback adapter. The generated manifest fixes canonical IDs,
legacy aliases, models, classifications, availability, implementation targets,
serializer ownership, migration state, and parity-test location.

The 40 pack counts are: access_control 6, adapters 2, cache 4,
command_injection 4, cors 4, crawler 2, credentials 10, csrf 3, cve 11,
documentation 17, dumps 1, evidence 4, ffuf 3, fingerprint 4, graphql 4,
headers_cookies 2, insecure_deser 2, jobs 3, js 7, jwt 2, lfi 4, nmap 3,
nuclei 3, open_redirect 3, perimeter 3, project 1, purple_team 1, scope 2,
shodan 14, sitemap 1, social 1, spec_import 2, sqli 3, ssi 5, ssrf 3, ssti 5,
tls_posture 2, workspace 15, xss 4, and xxe 4.

## Frozen equivalence

- Live legacy discovery deep-equals the approved fixture: 174 names in the
  exact order with exact descriptions and JSON Schemas.
- The compact tools array remains exactly 99,337 UTF-8 bytes.
- All 174 aliases dispatch through the Registry by default. Removing one ID
  from `LEGACY_DISPATCH_ACTIONS` preserves descriptor-owned discovery and
  validation while falling back to the retained implementation branch.
- Six field-specific native output models remain; each of the other 168 actions
  has a distinct typed JSON-object result model with the common
  status/background/job/result/error core and JSON-checked additional fields.
- Missing ffuf, Nuclei, or nmap executables and missing Shodan provider
  configuration are asserted as typed unavailability.

## Final verification

- Baseline regressions after the deterministic fixes: CVE provider pause 25/25
  isolated runs; no-network workflow corpus 25/25 isolated runs.
- Inventory/descriptor gate: 7 tests passed; registry negative gate: 21 tests
  passed; action contract gate: 15 tests passed.
- Legacy projection/result/contract gates: 3 projection, 6 slice, 21 result,
  and 13 byte-contract tests passed.
- Authority/exactly-once/ledger/continuation gates: 15 integration, 18
  repository, 17 execution-truth, 12 job-lifecycle, and 5 credential-
  confinement tests passed.
- `bin/test`: 576 core tests passed in 43.065 seconds; 2 template tests passed.
  Workflow calls remained `1,5,1,2,3,6,1`.
- `SYNAPSE_PYTHON=<MODERN_ENV>/bin/python bin/test-modern`: 6 official-SDK
  tests passed in 3.342 seconds.
- `python -m compileall -q MCPS/Synapse-MCP/synapse_mcp
  MCPS/Synapse-MCP/tests`, `bin/generate-action-inventory --check`, and
  `git diff --check` passed.

## Deferred by the Session 3A boundary

- The retained implementation adapter remains the explicit rollback target;
  physical branch retirement requires a separate decision.
- The official-SDK spike remains exactly three actions. Compact/direct facade,
  modern transport expansion, and interoperability/default decisions belong to
  Sessions 3B–3D.
- ADR-0004 remains Proposed until those later sessions implement and verify the
  complete compatibility decision.

PHASE_3A_PASS

## Session 3B preflight

- The new session began from the complete but uncommitted 3A worktree at the
  reviewed `6f46dae` baseline. Session 3A was independently rechecked, passed
  576 core tests, 2 template tests, 6 official-SDK tests, compile, generated-
  inventory, and diff gates, then was committed as `a5d66fe` before 3B edits.
- `PHASE_3A_PASS`, the 174-action inventory, exact legacy parity, and the
  retained rollback mapping were present and consistent.
- The Phase 3 execution pack, dedicated 3B brief, main plan, ADR-0004,
  Registry/policy/authority/ledger code, modern spike, workspace/jobs/report
  APIs, architecture tests, and relevant authority tests were read before
  implementation.

## Compact and direct application surfaces

The application-only compact surface is fixed at exactly eleven operations, in
this order:

1. `engagement.open`
2. `engagement.inspect`
3. `context.query`
4. `capabilities.search`
5. `actions.describe`
6. `actions.run_passive`
7. `actions.run_active`
8. `reviews.apply`
9. `artifacts.inspect`
10. `reports.render`
11. `tasks.control`

Its deterministic transport-neutral metadata is 21,648 compact UTF-8 bytes,
below the Phase 3 ceiling of 24,834 bytes. The direct surface contains 174
operations in canonical Registry order. Every direct input schema and action
output schema equals `REGISTRY.contract_schema(action_id)`, and annotations are
derived from the same descriptor effects as catalog search and description.

`capabilities.search` provides bounded, query-bound cursor pagination and
filters by text, pack, reviewed intent/use case, effect, risk, availability,
credential need/access, and scope. It never hides high-risk capabilities.
`actions.describe` returns canonical input/output schemas, maximum effects,
risk, scope, credential policy, availability, approval rules, safe examples,
and stable identity for all 174 actions.

## Execution, authority, and outcomes

- Compact and direct execution revalidate nested arguments with the selected
  canonical input model, invoke only `ActionRegistry.execute()`, and preserve
  Registry output-model validation and typed outcomes.
- Model-facing input cannot submit a grant, principal, authority profile,
  authority session, or request state. `confirm=true` is rejected instead of
  becoming modern authority. Trusted bindings exist only in
  `FacadeCallContext`, supplied by a future adapter.
- `actions.run_passive` rejects before dispatch when canonical maximum effects
  include traffic, credential or secret use, remote mutation, or local
  destruction. Truthful workspace/evidence writes are allowed.
- Active execution preserves scope, credential, grant, approval, idempotency,
  exactly-once dispatch, continuation, and ledger behavior. Approval-required
  results expose only a random operation handle and safe requested input.
- Supervised resume restores the durable request binding and original action,
  arguments, correlation, and idempotency key. Cross-principal, cross-session,
  cross-workspace, changed, and replayed handles fail before dispatch.

## Resources and task control

Local path fields are removed from model-facing results. Existing allowed-root
files become random resource references whose server-held records bind
principal, authority session, workspace, artifact type, media type, size, and
content hash. Every read rechecks the binding, allowed root, file identity, and
version; traversal, tampering, stale content, and cross-binding reads fail
closed. The application reference table is process-local in 3B.

`tasks.control` remains an application facade over canonical `jobs.list`,
`jobs.status`, and `jobs.cancel`, plus the existing durable approval resume
path. It does not implement or imitate the standard MCP Tasks extension.

## Documentation cleanup

The original local modernization plan is retained. Eight auxiliary Phase 2 and
truth/correction-gate design, inventory, execution, status, and handoff files
were removed after closure. Durable authority and Registry decisions remain in
ADR-0003 and ADR-0009, with shipped history in `CHANGELOG.md`; all surviving
tracked links were reconciled.

## Session 3B final verification

- Focused Phase 3B gate: 20 tests passed, including compact/direct accounting,
  all-174 schema equivalence, catalog filters/pagination, nested validation,
  every passive denial dimension, authority/scope/credential preservation,
  exactly-once resume, and resource confinement.
- Architecture boundary: 2 tests passed; Registry gate: 21 tests passed.
- `bin/test`: 596 core tests passed in 48.786 seconds; 2 template tests passed.
  Workflow calls remained `1,5,1,2,3,6,1`.
- `SYNAPSE_PYTHON=<MODERN_ENV>/bin/python bin/test-modern`: 6 official-SDK
  tests passed in 3.757 seconds.
- `python -m compileall -q MCPS/Synapse-MCP/synapse_mcp
  MCPS/Synapse-MCP/tests`, `bin/generate-action-inventory --check`, and
  `git diff --check` passed.
- Frozen legacy discovery remains 174 tools and 99,337 compact bytes. The
  official-SDK spike remains exactly three actions and no Phase 3C transport
  implementation was added.

## Deferred by the Session 3B boundary

- Bind compact/direct services to official-SDK stdio and Streamable HTTP in
  Phase 3C, with authenticated principal resolution and persistent rotating
  request-state/resource protection for multi-worker use.
- Keep the standard MCP Tasks extension deferred until supported by the pinned
  official SDK and interoperability evidence exists.
- Benchmark legacy, compact, and direct projections on the fixed corpus and
  decide the default only in Phase 3D.
- Keep the retained implementation adapter as the explicit rollback target;
  physical branch retirement remains a separate reviewed decision.

PHASE_3B_PASS

## Session 3C preflight

- Began on `Beta` at `aa2dc5708f14ae69d4aeff1f2dc180298b892ff1`;
  `6f46dae128520e06056dce50632e750023aedc80` remained an ancestor and the
  latest commit was the complete Phase 3B gate. Both predecessor tokens were
  present. Unrelated operator changes already present in `bin/check-setup` and
  `docs/Operations.md` were preserved.
- Read the repository policy, Phase 3 execution pack and 3C brief, Phase 3
  plan/status, ADR-0004, spike and packaging/entry points, compact/direct
  services, authority integration/repository, resource resolver, SDK request-
  state implementation, official SDK documentation, and relevant tests before
  editing.
- Rechecked primary sources on 2026-08-20. Official Python SDK
  [`v2.0.0`](https://github.com/modelcontextprotocol/python-sdk/releases/tag/v2.0.0)
  remained the latest stable release and the normative specification remained
  [`2026-07-28`](https://modelcontextprotocol.io/specification/2026-07-28).
  The exact `mcp==2.0.0` pin was retained; no unreviewed upgrade was proposed.
- Pre-edit gates passed: 26 facade/Registry/architecture tests and 6 isolated
  official-SDK spike tests.

## Production adapter and entry points

- Added `synapse_mcp.transport.modern` and the `synapse-mcp-modern` entry point.
  Startup must explicitly select `modern-compact` or `modern-direct`, and
  `stdio` or `streamable-http`. The `modern` extra isolates `mcp==2.0.0` from
  the stable installation. `modern-spike` and `synapse-mcp-modern-spike` remain
  deprecated compatibility aliases that forward to the production runtime.
- The SDK boundary is confined to `transport/modern/`. It projects exactly the
  Phase 3B application contracts: 11 compact tools or 174 canonical direct
  tools, deterministic order, complete input/output schemas, structured common
  outcomes, concise descriptions/instructions, truthful annotations, and
  opaque `synapse://artifact/{reference}` links. `confirm` is omitted.
- Success returns schema-valid structured content; unavailable/policy/runtime
  failures return the same schema with `isError`; validation uses the SDK
  protocol error path. On `2026-07-28`, approval returns official
  `InputRequiredResult` containing only an opaque operation handle, bounded
  requested input, dispatch state, reason, and trace. Earlier negotiated eras
  receive a schema-conformant error outcome rather than an invented extension.
- `tasks.control` continues to use the existing application service. No
  standard Tasks extension or other optional extension is enabled because SDK
  2.0.0 does not supply the required standard Tasks implementation.

## Identity, state, and HTTP threat model

- Stdio requires an operator-configured local principal. HTTP requires one
  high-entropy bearer token mapped by constant-time SHA-256 digest lookup to a
  stable principal. A private, reloadable server-held binding then maps exact
  principal/workspace context to `observe`, `supervised`, or `full_delegated`
  authority session and optional selected grant. `clientInfo`, display names,
  tool input, and unverified forwarded headers never authenticate or authorize.
- Private, locked, crash-atomic `operations.json` and `resources.json` records
  retain exact arguments and artifact paths only server-side. They bind opaque
  handles to principal, workspace, authority session, correlation,
  idempotency, allowed roots, and content version across restart/workers.
- Operator keyrings use schema version 1 and ordered `hex:`/`base64:` keys of
  at least 32 decoded bytes. The first key seals and all keys unseal. SDK state
  is bound to stable audience and authenticated principal. Expiry, tamper,
  wrong audience/principal, retired key, cross-binding resource access, and
  replay fail before dispatch/read. Explicit ephemeral state is limited to
  local single-process development and logs a restart warning.
- Loopback is the HTTP default. Non-loopback startup requires explicit remote
  enablement, digest-backed authentication, allowed hosts and origins,
  persistent keyring, and either direct TLS files or explicit trusted-proxy
  CIDRs. Ambiguous/untrusted forwarded headers, missing/duplicate bearer auth,
  Host/Origin attacks, and MCP method/version body-header mismatches fail
  closed. Authenticated responses are private/no-store; public cache hints are
  limited to caller-identical discovery/tool/resource-template metadata.
- `--observability otel` preserves an active OpenTelemetry trace ID and uses
  the deployment's standard provider/exporter; `disabled` removes the SDK
  tracing middleware while retaining a bounded local trace ID. Correlation is
  propagated through the facade/Registry/authority path but never changes
  authorization; bearer, credential, grant, raw path, and sealed-state contents
  are not logged.

## Transport and profile verification matrix

| Surface | Stdio | Loopback Streamable HTTP | Authority evidence |
|---|---|---|---|
| `modern-compact` (11) | real subprocess; all 5 SDK revisions | authenticated real subprocess; all 5 SDK revisions | observe discovery/error, supervised restart/step-up/exactly-once resume |
| `modern-direct` (174) | real subprocess plus all-revision in-process discovery | authenticated real subprocess plus all-revision in-process discovery | same Registry binding; Phase 3B full-delegated and denial suites remain green |

The five SDK-supported revisions exercised were modern `2026-07-28` and
handshake revisions `2024-11-05`, `2025-03-26`, `2025-06-18`, and
`2025-11-25`. Every revision published the same configured Synapse surface;
wire negotiation did not select a surface or authority profile.

## Session 3C final verification

- Production modern adapter: 12 tests passed in 9.454 seconds. Coverage
  includes both surfaces/transports, all five supported revisions, discovery
  TTL/cache scope, deterministic schemas/annotations, structured outcomes,
  resource links, client/argument spoofing denial, remote startup matrix,
  HTTP authentication/Host/Origin/forwarded/method/version checks, persistent
  resources, key rotation/restart/expiry/tamper/audience/principal/retirement,
  supervised trace-continuous resume, and exact one-request dispatch.
- Existing focused facade/architecture/Registry/authority/job/credential gate:
  76 tests passed before the final suite. This retains cancellation, job race,
  dispatch ledger, continuation, credential confinement, and full-delegated
  application behavior.
- `bin/test`: 596 core tests passed in 45.697 seconds; 2 template tests passed.
  Workflow calls remained `1,5,1,2,3,6,1`.
- `pip install -e '.[modern]'` and `synapse-mcp-modern --help` passed. Final
  `bin/test-modern`, `compileall` over core/core-tests/modern-tests,
  `bin/generate-action-inventory --check` (174 actions), and
  `git diff --check` passed.
- Official MCP Inspector 2.3.0: PASS. Its CLI connected through
  `config/modern-inspector.json` and returned all 11 compact tools with complete
  schemas and annotations.
- Official MCP conformance 0.1.16: **NOT_RUN**. Exact blocker: its `server`
  command accepts only `--url` and exposes no request-header/token option, so it
  cannot reach Synapse's mandatory authenticated HTTP endpoint; its listed
  server scenarios also stop at specification `2025-11-25` and do not cover
  `2026-07-28`. Phase 3D owns the final cross-client/conformance gate.

## Deferred by the Session 3C boundary

- The frozen `synapse-mcp` legacy server remains independently invocable and
  default. Phase 3C makes no adoption/removal decision and adds no silent wire-
  revision fallback.
- Phase 3D must run the fixed client/workflow corpus, resolve the conformance
  authentication/revision gap, decide the default, and close or revise
  ADR-0004. No Phase 3D implementation was started here.
- Public remote deployment remains non-default. The adapter supplies a narrow
  digest-backed principal resolver and explicit TLS/proxy boundary, not OAuth
  or a public deployment opinion.

PHASE_3C_PASS
