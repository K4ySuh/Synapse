# Phase 3 interoperability benchmark method

Status: corrective Codex method complete; historical methods retained below
Frozen: 2026-08-23
Baseline commit: `c356b95412528e3a84c208b759225dd338d7bfd4`

This document fixes the Phase 3D comparison method before client results are
used to decide the default. The original method and its blocked result remain
below for auditability.

## 2026-08-24 adversarial corrective Codex method

The operator-approved corrective gate tests stable Codex through its normal
client flow. Independent agent clients are outside the current Phase 3 scope
and must not be added to project acceptance unless the operator explicitly
reintroduces them. Historical cross-client attempts remain below only as audit
facts. Client display metadata, negotiated revision, and model input never
select a Synapse surface or create authority.

The live evidence is split deliberately:

- `bin/run-phase3-transport-smoke` retains the earlier exact-tool choreography
  as an exact transport and safety smoke. It runs malformed input, unavailable
  capability, denied effect/scope/credential, cross-principal/session/
  workspace/resource binding, approval-without-dispatch, restart/resume, and
  replay cases three times with stable Codex.
- `bin/run-phase3-agent-benchmark` states assessment objectives and safety
  constraints without supplying MCP tool names, canonical action IDs, exact
  argument objects, or call counts. It runs the seven fixed workflows three
  times with stable Codex and accepts catalog-selected semantic equivalents
  only when their observable result and integrity checks match.

The seven objective workflows are workspace summary, bounded target context,
passive stored header/cookie analysis, offline dump/sitemap/fingerprint,
disabled-traffic CORS planning and validation, background submit/cancel/
inspect/finalization without resubmission, and evidence/report/opaque-resource
integrity. The exact smoke supplies the ten Phase 3D safety and authority cases;
exhaustive expiry, revocation, concurrent resume, job race, transport-header,
and supported-revision cross-products remain deterministic repository gates.

Each workflow/case records the negotiated revision and advertised
capabilities, trusted startup surface, transport, selection result, schema
retries, duplicate behavior, available latency/token telemetry, declared
effects, network-attempt count, result, trace presence, dispatch count, and
resource/evidence integrity. Raw client streams and opaque material remain in
ignored `DATA/`; committed evidence contains no raw handle, request state,
trace ID, credential, binding, or local path.

Carrier selection is capability-based. Clients negotiating the normative
request-state capability use protocol-native input-required; compatible older
clients use typed `approval_required` plus an opaque application handle after
trusted exact step-up. Deterministic tests exercise three repetitions of the
native disabled-traffic carrier and both carriers under sequential and
concurrent resume, requiring one successful dispatch and a typed replay denial.

Inspector discovery is a separate generic gate. Stable conformance `0.1.16`
and alpha `0.2.0-alpha.11` still expose no bearer/header injection option, so
the proxy run is not repeated as direct security evidence. The aggregate
remains `partial_fail`; every non-pass is classified as an applicable failure,
non-advertised capability, runner fixture mismatch, or transport limitation.
Repository security tests and named-agent adoption do not convert that generic
verdict into a pass.

The live commands are:

```bash
bin/run-phase3-transport-smoke --run --repetitions 3
bin/run-phase3-agent-benchmark --run --repetitions 3
```

Stable Codex CLI `0.149.0` with `gpt-5.6-sol` has passed both corrective live
gates 3/3 at negotiated revision `2025-06-18`, with no experimental feature.
No independent-agent result or universal cross-agent claim is part of this
closure.

## 2026-08-24 closure amendment

The operator removed Claude Code as a required client. Phase 3D closure now
uses stable production Codex as the sole live model client and accepts either
of Synapse's equivalent supervised carriers:

- MCP `input_required` plus protocol request state when the client negotiates
  `2026-07-28`; or
- a typed `approval_required` application result, opaque `operationHandle`,
  and `tasks.control(operation=resume)` after an exact trusted operator
  step-up on older negotiated revisions.

Experimental client protocol flags are forbidden in the gate. The application
fallback must restart the MCP server before resume, preserve trace/request
binding, expose no authority material, and result in exactly one dispatch.

The live acceptance corpus is three independent repetitions of passive
workspace inspection, supervised disabled-traffic action interruption, exact
operator step-up, restart, and resume. Every stage must select exactly one
expected MCP tool, with zero duplicates or schema retries. Existing automated
workflow, denial, cross-binding, resource, job, legacy-contract, and both-
transport suites remain mandatory supporting evidence. Inspector remains the
transport/discovery client. Streamable HTTP and `modern-direct` remain
supported compatibility profiles, but the adoption decision targets local
Codex over `modern-compact` stdio.

The amended method is executable with:

```bash
bin/run-phase3d-codex --preflight
bin/run-phase3d-codex --run --repetitions 3
```

The verdict and exact accepted batch are recorded in `phase-3-handoff.md` and
`evidence/phase-3/codex-closure-results.json`.

## Named implementations

- Synapse `0.6.0b0` at the baseline commit above.
- Python `3.14.6` and official Python MCP SDK `2.0.0`.
- Codex CLI `0.149.0`, with an explicit `gpt-5.6-sol` model selection.
- Claude Code `2.1.220`; the exact model must be captured from a successful
  first-party run rather than inferred from an alias.
- MCP Inspector `2.3.0`, stable MCP conformance `0.1.16`, and the
  `2026-07-28`-aware conformance alpha `0.2.0-alpha.11` where the stable runner
  cannot represent the normative revision.
- Normative MCP specification `2026-07-28`; the frozen legacy launcher
  advertises `2025-03-26`.

Client versions and authentication are checked immediately before the run. A
missing client, expired sign-in, unsupported transport, or skipped security
case is recorded as a blocker rather than imputed from another client.

## Fixture and repetitions

The existing fictional `benchmark` workspace and `app.acme-demo.test` target
remain the fixed no-network fixture. Real external traffic is disabled. Server
state, identity bindings, request-state keys, client configuration, prompts,
model selection, and environment are fixed for a comparison batch.

Run three independent repetitions per supported client and surface over stdio.
Run three modern-surface compatibility repetitions over loopback Streamable
HTTP when the client supports it. The original seven workflows may be grouped
into one client session per repetition, but every workflow must retain its own
result and call accounting. Supervised approval is a two-turn run whose server
is restarted between turns. Record raw per-run JSON before aggregation.

## Success and tolerance rules

- Task success and required evidence fields: 100% for every deterministic
  workflow. Modern may not lose a success that legacy achieves.
- Invalid tool selection, malformed-schema retry, policy/scope/credential
  violation, duplicate dispatch, and duplicate side effect: zero.
- Supervised cases: exactly one approval interruption, 100% successful resume,
  and exactly one dispatch after approval.
- Discovery/search/describe calls are overhead, not selection errors. Record
  them separately. Compact may add at most one search and one describe call per
  selected canonical action.
- Median end-to-end client latency may be no more than 1.5 times legacy plus 15
  seconds. The slowest repetition may be no more than 2 times legacy plus 30
  seconds. These bounds are evaluated within the same client and workflow.
- Payloads and schemas must be byte-deterministic across repeated generation.
  The frozen boundary is
  `json.dumps(value, separators=(",", ":")).encode("utf-8")` with default
  ASCII escaping. Legacy must remain 174 tools and 99,337 bytes;
  `modern-compact` must remain at most 24,834 bytes and strictly below one
  quarter of legacy.

Server payload size and client on-demand tool loading are separate metrics.
Claude tool-search calls and any Codex deferred-tool events are counted from
observed client logs; neither is inferred from the server payload alone.

## Required cases

The fixed corpus retains workspace summary, bounded target context, passive
headers/cookies analysis, disabled-traffic CORS planning/execution, background
submission/inspection, timeout recovery without duplicate work, and report
rendering/resource retrieval. The Phase 3D additions are catalog search and
describe, supervised approval/resume, task cancel/resume, unavailable optional
capability, malformed input, policy denial, cross-principal/workspace attacks,
restart resume, and direct-tool selection on a tool-search-capable host.

Automated repository suites remain the authority for exhaustive adversarial
cross-products. Live-client runs prove actual discovery, selection, result, and
resume behavior and do not replace those suites.

The 2026-08-23 run stopped before the original complete corpus because both
then-mandatory client gates failed. Its partial read slice must not be compared
as if it completed this original method; the exact results and missing fields
are preserved in `evidence/phase-3/benchmark-results.json`. The later closure
uses the explicit amendment above rather than retroactively changing those
historical results.
