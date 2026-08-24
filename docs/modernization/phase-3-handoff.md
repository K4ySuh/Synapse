# Phase 3 interoperability handoff

Date: 2026-08-24
Baseline: `c356b95412528e3a84c208b759225dd338d7bfd4`
Decision: complete; `modern-compact` stdio is the Codex default

Phase 3A through 3D are complete. A superseded client-comparison attempt is
retained only in the historical evidence section below. The active closure
contract uses stable Codex, without experimental feature flags. Protocol-native
`input_required` remains supported when negotiated, but it is no longer the
only valid supervised-resume carrier. Older negotiated revisions use the
typed `approval_required` result, its opaque `operationHandle`, and
`tasks.control(operation=resume)` after trusted operator step-up.

## Adopted surfaces

| Surface | Tools | Exact payload bytes | Disposition |
| --- | ---: | ---: | --- |
| `modern-compact` | 11 | 22,863 | default Codex stdio surface |
| `legacy` | 174 | 99,337 | frozen rollback and bootstrap compatibility |
| `modern-direct` | 174 | 1,513,976 | explicit diagnostic/compatibility surface |

All three projections enter the same Registry/application path. Surface
selection does not change scope, identity, or execution authority. The legacy
launcher and contract fixtures remain intact; adoption does not imply a legacy
removal date.

## Codex closure gate

`bin/run-phase3d-codex` is the reproducible live gate. It uses a fictional
`benchmark` workspace and `app.acme-demo.test`, disables external target
traffic, creates private temporary identity/key files, and starts a new modern
MCP process for resume. It explicitly disables Codex's under-development
`mcp_2026_07_28` feature.

The accepted batch used Codex CLI `0.149.0`, `gpt-5.6-sol`, stable negotiated
behavior, `modern-compact`, and stdio. Three independent repetitions each
passed:

1. `engagement.inspect` exactly once under an observe grant;
2. `actions.run_active` exactly once, returning `approval_required`, an opaque
   handle, and `dispatch=not_started`;
3. one exact step-up through the trusted local operator service;
4. restart into a fresh MCP process;
5. `tasks.control(operation=resume)` exactly once;
6. trace continuity and exactly one successful Registry dispatch.

Across nine stages there were nine expected MCP tool calls, zero duplicates,
zero schema retries, three approval interruptions, three successful resumes,
and three successful dispatches. Response status remained null because the
CORS fixture used `httpBackend=disabled` and `disableTraffic=true`.

Reproduce it with:

```bash
bin/run-phase3d-codex --preflight
bin/run-phase3d-codex --run --repetitions 3
```

Raw JSONL and opaque handles remain under `DATA/phase3d-codex/`. Sanitized
machine evidence is committed as
[`codex-closure-results.json`](evidence/phase-3/codex-closure-results.json).

## Supporting gates and accepted residuals

- Transport-independent projection fixtures remain deterministic: legacy
  99,337 bytes, compact 22,863 bytes, and direct 1,513,976 bytes. The separate
  official-SDK wire fixtures measure compact at 23,567 bytes for revision
  `2026-07-28` and 24,205 bytes for revisions `2024-11-05`, `2025-03-26`,
  `2025-06-18`, and `2025-11-25`; all remain below the 24,834-byte ceiling.
- Inspector `2.3.0` already discovered complete compact/direct schemas over
  stdio and loopback Streamable HTTP.
- The modern adapter suites cover both transports, every supported negotiated
  revision, restart, request-state rotation/tamper/expiry, cross-binding
  attacks, Host/Origin checks, and remote-startup fail-closed behavior.
- The alpha conformance subscription failures are accepted as non-blocking for
  this release because Synapse does not advertise subscription capabilities;
  runner-fixture tools and proxy-mediated header cases are not production
  Synapse contracts. HTTP remains supported but is not the selected local
  Codex default.
- Protocol-native `input_required` is additive. When stable Codex negotiates
  it, the server can use it; the application handle path remains necessary for
  compatible older revisions and for explicit task control.

## Operator configuration and rollback

`bin/print-mcp-config` now prints the modern compact Codex profile by default
and has no alternate-agent output mode. Use `--legacy` for the frozen rollback
profile. Independent agent clients are outside the project acceptance contract
unless the operator explicitly reintroduces them.

Before using the modern profile, create the private `0600` identity binding and
request-state keyring described in `docs/Operations.md`, then create/select
the required Authority Grant with the trusted `synapse-authority` service.
Codex host approval permits an MCP invocation to reach Synapse; it does not
create scope or server-held execution authority.

Rollback requires only selecting:

```bash
bin/print-mcp-config --legacy
```

This is a modern-adapter rollback with frozen wire compatibility. The legacy
server still uses the canonical Registry and its existing scope/authority
policy; it is not a retained-dispatch or authority bypass. The rollback
launcher is tested without the modern SDK, identity binding, or request-state
keyring. No workspace, evidence, scope, grant, or frozen legacy contract
migration is required.

PHASE_3_PASS

## Phase 3R corrective handoff

Decision: complete under the operator-amended Codex-only acceptance contract.
Independent agent clients are not a current project requirement and must not be
introduced without a new operator instruction. The earlier blocked cross-client
attempt remains historical evidence only; no universal cross-agent result is
claimed.

The corrective implementation is cumulative:

- Phase 3R-1 commit `1844261` makes all 174 effect/authority declarations
  executable truth and fixes the model/control-plane boundary.
- Phase 3R-2 commit `b4e0e9b` publishes action-specific standard output
  contracts, exact official-SDK wire evidence, consistent runtime resolution,
  and explicit legacy/modern readiness.
- Phase 3R-3 adds bound opaque dump-directory/source pass-back, complete
  protocol/surface result metadata, standalone retained-action binding,
  concurrent exactly-once resume tests, a Codex-only exact transport/safety
  runner, and a Codex-only objective-driven benchmark. The implementation and
  evidence are committed as `6b3b764`.

The final exact smoke used Codex CLI `0.149.0`, `gpt-5.6-sol`, MCP
`2025-06-18`, `modern-compact`, and stdio. Three independent repetitions all
passed malformed/unavailable/denial, cross-binding, approval, restart/resume,
and replay acceptance. Each produced one successful post-step-up dispatch,
zero duplicate or unauthorized dispatches, zero schema retries, and zero
external target traffic. See
[`transport-smoke-results.json`](evidence/phase-3/transport-smoke-results.json).

The objective prompt supplied no tool names, canonical action IDs, exact
argument objects, or call counts. Workspace summary, bounded context, passive
headers/cookies, offline dump/sitemap/fingerprint, disabled-traffic CORS,
background submit/cancel/inspect/finalization, and evidence/report/resource
integrity each passed 3/3. There were zero schema retries, zero duplicate side
effects, and zero external traffic. Two repeated passive task-state reads are
retained as non-blocking client telemetry. See
[`agent-benchmark-results.json`](evidence/phase-3/agent-benchmark-results.json).

Final repository verification passed 619 core tests, 2 adapter-template tests,
15 official-SDK modern tests, 174-action/output generation checks, frozen
legacy 174 tools / 99,337 bytes, compact application projection 22,863 bytes,
compilation/syntax, JSON/TOML, secret/opaque/path, and diff gates.

Accepted residuals:

- Generic MCP conformance remains `partial_fail`; current stable and alpha
  runners cannot inject the required bearer header, and every historical
  non-pass remains explicitly classified.
- The production Codex client still negotiates `2025-06-18`; the stable typed
  application handle is the accepted approval carrier. No experimental client
  feature is enabled.
- The Codex account reached its usage ceiling during a redundant post-cleanup
  objective rerun. The committed objective evidence is the already successful
  same-prompt 3/3 batch, revalidated by the current Codex-only runner; no failed
  case is counted as a pass.

Rollback remains `bin/print-mcp-config --legacy`. No legacy contract, data,
scope, grant, or workspace migration is required.

PHASE_3R1_PASS

PHASE_3R2_PASS

PHASE_3_CODEX_PASS

PHASE_3R3_PASS

PHASE_3_PASS
